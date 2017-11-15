#!/usr/bin/env python
#
# Simple Let's Encrypt client.
#
# Copyright (C) 2015  Jakub Warmuz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""Simple Let's Encrypt client."""
import abc
import argparse
import collections
import contextlib
import datetime
import doctest
import hashlib
import errno
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import unittest

import pkg_resources

import six
from six.moves import zip  # pylint: disable=redefined-builtin

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import mock
import OpenSSL
import pytz
import requests

from acme import client as acme_client
from acme import crypto_util
from acme import challenges
from acme import errors as acme_errors
from acme import jose
from acme import messages


# pylint: disable=too-many-lines


logger = logging.getLogger(__name__)  # pylint: disable=invalid-name

VERSION = pkg_resources.require('simp_le-client')[0].version
URL = 'https://github.com/zenhack/simp_le'

LE_PRODUCTION_URI = 'https://acme-v01.api.letsencrypt.org/directory'
# https://letsencrypt.org/2015/11/09/why-90-days.html
LE_CERT_VALIDITY = 90 * 24 * 60 * 60
DEFAULT_VALID_MIN = LE_CERT_VALIDITY / 3

EXIT_RENEWAL = EXIT_TESTS_OK = EXIT_REVOKE_OK = EXIT_HELP_VERSION_OK = 0
EXIT_NO_RENEWAL = 1
EXIT_ERROR = 2


class Error(Exception):
    """simp_le error."""


class UnitTestCase(unittest.TestCase):
    """simp_le unit test case."""

    class AssertRaisesContext(object):
        """Context for assert_raises."""
        # pylint: disable=too-few-public-methods

        def __init__(self):
            self.error = None

    @contextlib.contextmanager
    def assert_raises(self, exc):
        """Assert raises context manager."""
        context = self.AssertRaisesContext()
        try:
            yield context
        except exc as error:
            context.error = error
        else:
            self.fail('Expected exception (%s) not raised' % exc)

    def assert_raises_regexp(self, exc, regexp, func, *args, **kwargs):
        """Assert raises that tests exception message against regexp."""
        with self.assert_raises(exc) as context:
            func(*args, **kwargs)
        msg = str(context.error)
        self.assertTrue(re.match(regexp, msg) is not None,
                        "Exception message (%s) doesn't match "
                        "regexp (%s)" % (msg, regexp))

    def assert_raises_error(self, *args, **kwargs):
        """Assert raises simp_le error with given message."""
        self.assert_raises_regexp(Error, *args, **kwargs)

    @staticmethod
    def check_logs(level, pattern, func):
        """Check whether func logs a message matching pattern.

        ``pattern`` is a regular expression to match the logs against.
        ``func`` is the function to call.
        ``level`` is the logging level to set during the function call.

        Returns True if there is a match, False otherwise.
        """
        log_msgs = []

        class TestHandler(logging.Handler):
            """Log handler that saves logs in ``log_msgs``."""

            def emit(self, record):
                log_msgs.append(record.msg % record.args)

        handler = TestHandler(level=level)
        logger.addHandler(handler)

        try:
            func()
            for msg in log_msgs:
                if re.match(pattern, msg) is not None:
                    return True
            return False
        finally:
            logger.removeHandler(handler)


_PEM_RE_LABELCHAR = r'[\x21-\x2c\x2e-\x7e]'
_PEM_RE = re.compile(
    (r"""
^-----BEGIN\ ((?:%s(?:[- ]?%s)*)?)\s*-----$
.*?
^-----END\ \1-----\s*""" % (_PEM_RE_LABELCHAR, _PEM_RE_LABELCHAR)).encode(),
    re.DOTALL | re.MULTILINE | re.VERBOSE)
_PEMS_SEP = b'\n'


def split_pems(buf):
    r"""Split buffer comprised of PEM encoded (RFC 7468).

    >>> x = b'\n-----BEGIN FOO BAR-----\nfoo\nbar\n-----END FOO BAR-----'
    >>> len(list(split_pems(x * 3)))
    3
    >>> list(split_pems(b''))
    []
    """
    for match in _PEM_RE.finditer(buf):
        yield match.group(0)


def gen_pkey(bits):
    """Generate a private key.

    >>> gen_pkey(1024)
    <OpenSSL.crypto.PKey object at 0x...>

    Args:
      bits: Bit size of the key.

    Returns:
      Freshly generated private key.
    """
    assert bits >= 1024
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
    return pkey


def gen_csr(pkey, domains, sig_hash='sha256'):
    """Generate a CSR.

    >>> [str(domain) for domain in crypto_util._pyopenssl_cert_or_req_san(
    ...     gen_csr(gen_pkey(1024), [b'example.com', b'example.net']))]
    ['example.com', 'example.net']

    Args:
      pkey: Private key.
      domains: List of domains included in the cert.
      sig_hash: Hash used to sign the CSR.

    Returns:
      Generated CSR.
    """
    assert domains, 'Must provide one or more hostnames for the CSR.'
    req = OpenSSL.crypto.X509Req()
    req.add_extensions([
        OpenSSL.crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=b', '.join(b'DNS:' + d for d in domains)
        ),
    ])
    req.set_pubkey(pkey)

    # pre-1.0.2 version of OpenSSL the generated CSR will contain a
    # zero-length Version field which will cause some strict parsers
    # (e.g. the one in Golang, used by Boulder) to fail.
    req.set_version(2)

    req.sign(pkey, sig_hash)
    return req


def get_le_tos_hash(le_uri):
    """Returns up to date Let's Encrypt ToS hash"""
    try:
        le_directory = requests.get(le_uri).json()
    except requests.ConnectionError:
        raise Error("Connection to %s failed.", le_uri)
    except ValueError:
        raise Error("Failed to decode JSON from %s", le_uri)

    le_tos_uri = le_directory['meta']['terms-of-service']
    le_tos_hash = sha256_of_uri_contents(le_tos_uri)
    return le_tos_hash


class ComparablePKey(object):  # pylint: disable=too-few-public-methods
    """Comparable key.

    Suppose you have the following keys with the same material:

    >>> pem = OpenSSL.crypto.dump_privatekey(
    ...     OpenSSL.crypto.FILETYPE_PEM, gen_pkey(1024))
    >>> k1 = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem)
    >>> k2 = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem)

    Unfortunately, in pyOpenSSL, equality is not well defined:

    >>> k1 == k2
    False

    Using `ComparablePKey` you get the equality relation right:

    >>> ck1, ck2 = ComparablePKey(k1), ComparablePKey(k2)
    >>> other_ckey = ComparablePKey(gen_pkey(1024))
    >>> ck1 == ck2
    True
    >>> ck1 == k1
    False
    >>> k1 == ck1
    False
    >>> other_ckey == ck1
    False

    Non-equalty is also well defined:

    >>> ck1 != ck2
    False
    >>> ck1 != k1
    True
    >>> k1 != ck1
    True
    >>> k1 != other_ckey
    True
    >>> other_ckey != ck1
    True

    Wrapepd key is available as well:

    >>> ck1.wrapped is k1
    True

    Internal implementation is not optimized for performance!
    """
    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __ne__(self, other):
        return not self == other  # pylint: disable=unneeded-not

    def _dump(self):
        return OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_ASN1, self.wrapped)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        # pylint: disable=protected-access
        return self._dump() == other._dump()


class Vhost(collections.namedtuple('Vhost', 'name root')):
    """Vhost: domain name and public html root."""
    _SEP = ':'

    @classmethod
    def decode(cls, data):
        # pylint: disable=anomalous-unicode-escape-in-string
        """Decode vhost and perform basic sanitization on the domain name:
        - raise an error if domain is not ASCII (Internationalized Domain
        Names are supported by Let's Encrypt using punycode).
        - converts domain to lowercase.

        >>> Vhost.decode('example.com')
        Vhost(name='example.com', root=None)
        >>> Vhost.decode('EXAMPLE.COM')
        Vhost(name='example.com', root=None)

        utf-8 test with example.china:
        >>> Vhost.decode(u'\u4f8b\u5982.\u4e2d\u56fd')
        Traceback (most recent call last):
        ...
        Error: Non-ASCII domain names aren't supported. To issue
        for an Internationalized Domain Name, use Punycode.
        >>> Vhost.decode('example.com:/var/www/html')
        Vhost(name='example.com', root='/var/www/html')
        >>> Vhost.decode(Vhost(name='example.com', root=None))
        Vhost(name='example.com', root=None)
        """
        if isinstance(data, cls):
            return data
        parts = data.split(cls._SEP, 1)

        try:
            utf8test = parts[0]
            if isinstance(utf8test, six.binary_type):
                utf8test = utf8test.decode('utf-8')
            utf8test.encode('ascii')
        except UnicodeError:
            raise Error("Non-ASCII domain names aren't supported. "
                        "To issue for an Internationalized Domain Name, "
                        "use Punycode.")

        parts[0] = parts[0].lower()

        parts.append(None)
        return cls(name=parts[0], root=parts[1])


class IOPlugin(object):
    """Input/output plugin.

    In case of any problems, `persisted`, `load` and `save`
    methods should raise `Error`, for which message will be
    displayed directly to the user through STDERR (in `main`).

    """
    __metaclass__ = abc.ABCMeta

    Data = collections.namedtuple('IOPluginData', 'account_key key cert chain')
    """Plugin data.

    Unless otherwise stated, plugin data components are typically
    filled with the following data:

    - for `account_key`: private account key, an instance of `acme.jose.JWK`
    - for `key`: private key, an instance of `OpenSSL.crypto.PKey`
    - for `cert`: certificate, an instance of `OpenSSL.crypto.X509`
    - for `chain`: certificate chain, a list of `OpenSSL.crypto.X509` instances
    """

    EMPTY_DATA = Data(account_key=None, key=None, cert=None, chain=None)

    def __init__(self, path, **dummy_kwargs):
        self.path = path

    @abc.abstractmethod
    def persisted(self):
        """Which data is persisted by this plugin?

        This method must be overridden in subclasses and must return
        `IOPlugin.Data` with Boolean values indicating whether specific
        component is persisted by the plugin.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def load(self):
        """Load persisted data.

        This method must be overridden in subclasses and must return
        `IOPlugin.Data`. For all non-persisted data it must set the
        corresponding component to `None`. If the data was not persisted
        previously, it must return `EMPTY_DATA` (note that it does not
        make sense for the plugin to set subset of the persisted
        components to not-None: this would mean that data was persisted
        only partially - if possible plugin should detect such condition
        and throw an `Error`).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def save(self, data):
        """Save data to file system.

        This method must be overridden in subclasses and must accept
        `IOPlugin.Data`. It must store all persisted components and
        ignore all non-persisted components. It is guaranteed that all
        persisted components are not `None`.
        """
        raise NotImplementedError()

    # Plugin registration magic
    registered = {}

    @classmethod
    def register(cls, **kwargs):
        """Register IO plugin."""
        def init_and_reg(plugin_cls):
            """Initialize plugin class and register."""
            plugin = plugin_cls(**kwargs)
            assert (os.path.sep not in plugin.path and
                    plugin.path not in ('.', '..'))
            cls.registered[plugin.path] = plugin
            return plugin_cls
        return init_and_reg


class FileIOPlugin(IOPlugin):
    """Plugin that saves/reads files on disk."""

    READ_MODE = 'rb'
    WRITE_MODE = 'wb'

    def load(self):
        logger.debug('Loading %s', self.path)
        try:
            with open(self.path, self.READ_MODE) as persist_file:
                content = persist_file.read()
        except IOError as error:
            if error.errno == errno.ENOENT:
                # file does not exist, so it was not persisted
                # previously
                return self.EMPTY_DATA
            raise
        return self.load_from_content(content)

    @abc.abstractmethod
    def load_from_content(self, content):
        """Load from file contents.

        This method must be overridden in subclasses. It will be called
        with the contents of the file read from `path` and should return
        whatever `IOPlugin.load` is meant to return.
        """
        raise NotImplementedError()

    def save_to_file(self, data):
        """Save data to file."""
        logger.info('Saving %s', self.path)
        try:
            with open(self.path, self.WRITE_MODE) as persist_file:
                persist_file.write(data)
        except OSError as error:
            logging.exception(error)
            raise Error('Error when saving %s', self.path)


class JWKIOPlugin(IOPlugin):  # pylint: disable=abstract-method
    """IO Plugin that uses JWKs."""

    @classmethod
    def load_jwk(cls, data):
        """Load JWK."""
        return jose.JWKRSA.json_loads(data)

    @classmethod
    def dump_jwk(cls, jwk):
        """Dump JWK."""
        return jwk.json_dumps()


@IOPlugin.register(path='account_key.json')
class AccountKey(FileIOPlugin, JWKIOPlugin):
    """Account key IO Plugin using JWS."""

    # this is not a binary file
    READ_MODE = 'r'
    WRITE_MODE = 'w'

    def persisted(self):
        return self.Data(account_key=True, key=False, cert=False, chain=False)

    def load_from_content(self, content):
        return self.Data(account_key=self.load_jwk(content), key=None,
                         cert=None, chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_jwk(data.account_key))


class OpenSSLIOPlugin(IOPlugin):  # pylint: disable=abstract-method
    """IOPlugin that uses pyOpenSSL.

    Args:
      typ: One of `OpenSSL.crypto.FILETYPE_*`, used in loading/dumping.
    """

    def __init__(self, typ=OpenSSL.crypto.FILETYPE_PEM, **kwargs):
        self.typ = typ
        super(OpenSSLIOPlugin, self).__init__(**kwargs)

    def load_key(self, data):
        """Load private key."""
        return ComparablePKey(OpenSSL.crypto.load_privatekey(self.typ, data))

    def dump_key(self, data):
        """Dump private key."""
        return OpenSSL.crypto.dump_privatekey(self.typ, data.wrapped).strip()

    def load_cert(self, data):
        """Load certificate."""
        return jose.ComparableX509(OpenSSL.crypto.load_certificate(
            self.typ, data))

    def dump_cert(self, data):
        """Dump certificate."""
        return OpenSSL.crypto.dump_certificate(self.typ, data.wrapped).strip()


def load_pem_jwk(data):
    """Load JWK encoded as PEM."""
    return jose.JWKRSA(key=serialization.load_pem_private_key(
        data, password=None, backend=default_backend()))


def dump_pem_jwk(data):
    """Dump JWK as PEM."""
    return data.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).strip()


@IOPlugin.register(path='external.sh', typ=OpenSSL.crypto.FILETYPE_PEM)
class ExternalIOPlugin(OpenSSLIOPlugin):
    """External IO Plugin.

    This plugin executes script that complies with the
    "persisted|load|save protocol":

    - whenever the script is called with `persisted` as the first
      argument, it should send to STDOUT a single line consisting of a
      subset of four keywords: `account_key`, `key`, `cert`, `chain`
      (in any order, separated by whitespace);

    - whenever the script is called with `load` as the first argument it
      shall write to STDOUT all persisted data as PEM encoded strings in
      the following order: account_key, key, certificate, certificates
      in the chain (from leaf to root). If some data is not persisted,
      it must be skipped in the output;

    - whenever the script is called with `save` as the first argument,
      it should accept data from STDIN and persist it. Data is encoded
      and ordered in the same way as in the `load` case.
    """

    @property
    def script(self):
        """Path to the script."""
        return os.path.join('.', self.path)

    def get_output_or_fail(self, command):
        """Get output or throw an exception in case of errors."""
        try:
            proc = subprocess.Popen(
                [self.script, command], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as error:
            raise Error('Failed to execute external script: %s' % error)

        stdout, stderr = proc.communicate()
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: %d' %
                        proc.returncode)

        # Do NOT log `stdout` as it might contain secret material (in
        # case key is persisted)
        return stdout

    def persisted(self):
        """Call the external script and see which data is persisted."""
        output = self.get_output_or_fail('persisted').split()
        return self.Data(
            account_key=(b'account_key' in output),
            key=(b'key' in output),
            cert=(b'cert' in output),
            chain=(b'chain' in output),
        )

    def load(self):
        """Call the external script to retrieve persisted data."""
        pems = list(split_pems(self.get_output_or_fail('load')))
        if not pems:
            return self.EMPTY_DATA
        persisted = self.persisted()

        account_key = load_pem_jwk(
            pems.pop(0)) if persisted.account_key else None
        key = self.load_key(pems.pop(0)) if persisted.key else None
        cert = self.load_cert(pems.pop(0)) if persisted.cert else None
        chain = ([self.load_cert(cert_data) for cert_data in pems]
                 if persisted.chain else None)
        return self.Data(account_key=account_key, key=key,
                         cert=cert, chain=chain)

    def save(self, data):
        """Call the external script and send data to be persisted to STDIN."""
        persisted = self.persisted()
        output = []
        if persisted.account_key:
            output.append(dump_pem_jwk(data.account_key))
        if persisted.key:
            output.append(self.dump_key(data.key))
        if persisted.cert:
            output.append(self.dump_cert(data.cert))
        if persisted.chain:
            output.extend(self.dump_cert(cert) for cert in data.chain)

        logger.info('Calling `%s save` and piping data through', self.script)
        try:
            proc = subprocess.Popen(
                [self.script, 'save'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except OSError as error:
            logger.exception(error)
            raise Error(
                'There was a problem executing external IO plugin script')
        stdout, stderr = proc.communicate(_PEMS_SEP.join(output))
        if stdout is not None:
            logger.debug('STDOUT: %s', stdout)
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: %d' %
                        proc.returncode)


class PluginIOTestMixin(object):
    """Common plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    PLUGIN_CLS = NotImplemented

    def __init__(self, *args, **kwargs):
        super(PluginIOTestMixin, self).__init__(*args, **kwargs)

        raw_key = gen_pkey(1024)
        self.all_data = IOPlugin.Data(
            account_key=jose.JWKRSA(key=rsa.generate_private_key(
                public_exponent=65537, key_size=1024,
                backend=default_backend(),
            )),
            key=ComparablePKey(raw_key),
            cert=jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['a'])),
            chain=[
                jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['b'])),
                jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['c'])),
            ],
        )
        self.key_data = IOPlugin.EMPTY_DATA._replace(key=self.all_data.key)

    def setUp(self):  # pylint: disable=invalid-name
        self.root = tempfile.mkdtemp()
        self.path = os.path.join(self.root, 'plugin')
        # pylint: disable=not-callable
        self.plugin = self.PLUGIN_CLS(path=self.path)

    def tearDown(self):  # pylint: disable=invalid-name
        shutil.rmtree(self.root)


class FileIOPluginTestMixin(PluginIOTestMixin):
    """Common FileIO plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    def test_empty(self):
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_save_ignore_unpersisted(self):
        self.plugin.save(self.all_data)
        self.assertEqual(self.plugin.load(), IOPlugin.Data(
            *(data if persist else None for persist, data in
              zip(self.plugin.persisted(), self.all_data))))


class PortNumWarningTest(UnitTestCase):
    """Tests relating to the port number warning."""

    def _check_warn(self, should_log, path):
        """test whether the supplied path triggers the port number warning.

        ``should_log`` is a boolean indicating whether or not we expect the
        path to trigger a warning.
        ``path`` is the webroot path to check.

        If ``should_log`` is inconsistent with the behavior of
        ``compute_roots`` given ``path``, the test fails.
        """
        return self.assertEqual(
            self.check_logs(
                logging.WARN,
                '.*looks like it is a port number.*',
                lambda: compute_roots([
                    Vhost('example.com', path),
                ], 'webroot')
            ),
            should_log,
        )

    def test_warn_port(self):
        """A bare port number triggers the warning."""
        self._check_warn(True, '8000')

    def test_warn_port_path(self):
        """``port_no:path`` triggers the warning."""
        self._check_warn(True, '8000:/webroot')

    def test_no_warn_path(self):
        """A bare path doesn't trigger the warning."""
        self._check_warn(False, '/my-web-root')

    def test_no_warn_bigport(self):
        """A number too big to be a port doesn't trigger the warning."""
        self._check_warn(False, '66000')


class ExternalIOPluginTest(PluginIOTestMixin, UnitTestCase):
    """Tests for ExternalIOPlugin."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = ExternalIOPlugin

    def save_script(self, contents):
        with open(self.path, 'w') as external_plugin_file:
            external_plugin_file.write(contents)
        os.chmod(self.path, 0o700)

    def test_no_persisted_empty(self):
        self.save_script('#!/bin/sh')
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_missing_path_raises_error(self):
        self.assert_raises_error(
            'Failed to execute external script', self.plugin.load)

    def test_load_nonzero_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assert_raises_error(
            '.*exited with non-zero code: 1', self.plugin.load)

    def test_save_nonzero_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assert_raises_error(
            '.*exited with non-zero code: 1', self.plugin.save, self.key_data)

    def one_file_script(self, persisted):
        path = os.path.join(self.root, 'pem')
        self.save_script("""\
#!/bin/sh
case $1 in
  save) cat - > {path};;
  load) [ ! -f {path} ] ||  cat {path};;
  persisted) echo {persisted};;
esac
""".format(path=path, persisted=persisted))
        return path

    def test_it(self):
        path = self.one_file_script('cert chain key account_key')
        # not yet persisted
        self.assertEqual(IOPlugin.EMPTY_DATA, self.plugin.load())
        # save some data
        self.plugin.save(self.all_data)
        self.assertTrue(os.path.exists(path))
        # loading should return the persisted data back in
        self.assertEqual(self.all_data, self.plugin.load())


@IOPlugin.register(path='chain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class ChainFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate chain plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=False, chain=True)

    def load_from_content(self, content):
        chain = [self.load_cert(cert_data)
                 for cert_data in split_pems(content)]
        return self.Data(account_key=None, key=None, cert=None, chain=chain)

    def save(self, data):
        return self.save_to_file(_PEMS_SEP.join(
            self.dump_cert(chain_cert) for chain_cert in data.chain))


class ChainFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for ChainFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = ChainFile


@IOPlugin.register(path='fullchain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullChainFile(ChainFile):
    """Full chain file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=True, chain=True)

    def load(self):
        data = super(FullChainFile, self).load()
        if data.chain is None:
            cert, chain = None, None
        else:
            cert, chain = data.chain[0], data.chain[1:]
        return self.Data(account_key=data.account_key, key=data.key,
                         cert=cert, chain=chain)

    def save(self, data):
        return super(FullChainFile, self).save(self.Data(
            account_key=data.account_key, key=data.key,
            cert=None, chain=([data.cert] + data.chain)))


class FullChainFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for FullChainFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = FullChainFile


@IOPlugin.register(path='key.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='key.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class KeyFile(FileIOPlugin, OpenSSLIOPlugin):
    """Private key file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=True, cert=False, chain=False)

    def load_from_content(self, content):
        return self.Data(account_key=None, key=self.load_key(content),
                         cert=None, chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_key(data.key))


class KeyFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for KeyFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = KeyFile


@IOPlugin.register(path='cert.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='cert.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class CertFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=True, chain=False)

    def load_from_content(self, content):
        return self.Data(account_key=None, key=None,
                         cert=self.load_cert(content), chain=None)

    def save(self, data):
        return self.save_to_file(self.dump_cert(data.cert))


class CertFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for CertFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = CertFile


@IOPlugin.register(path='full.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullFile(FileIOPlugin, OpenSSLIOPlugin):
    """Private key, certificate and chain plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=True, cert=True, chain=True)

    def load_from_content(self, content):
        pems = split_pems(content)
        return self.Data(
            account_key=None,
            key=self.load_key(next(pems)),
            cert=self.load_cert(next(pems)),
            chain=[self.load_cert(cert) for cert in pems],
        )

    def save(self, data):
        pems = [self.dump_key(data.key), self.dump_cert(data.cert)]
        pems.extend(self.dump_cert(cert) for cert in data.chain)
        self.save_to_file(_PEMS_SEP.join(pems))


class FullFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for FullFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = FullFile


def create_parser():
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        usage=argparse.SUPPRESS, add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='See %s for more info.' % URL,
    )

    general = parser.add_argument_group()
    general.add_argument(
        '-v', '--verbose', action='store_true', default=False,
        help='Increase verbosity of the logging.',
    )

    modes = parser.add_argument_group()
    modes.add_argument(
        '-h', '--help', action='store_true',
        help='Show this help message and exit.',
    )
    modes.add_argument(
        '--version', action='store_true',
        help='Display version and exit.'
    )
    modes.add_argument(
        '--revoke', action='store_true', default=False,
        help='Revoke existing certificate')
    modes.add_argument(
        '--test', action='store_true', default=False,
        help='Run tests and exit.',
    )
    modes.add_argument(
        '--integration_test', action='store_true', default=False,
        help='Run integration tests and exit.',
    )

    manager = parser.add_argument_group(
        'Webroot manager', description='This client is just a '
        'sophisticated manager for $webroot/' +
        challenges.HTTP01.URI_ROOT_PATH + '. You can (optionally) '
        'specify `--default_root`, and override per-vhost with '
        '`-d example.com:/var/www/other_html` syntax.',
    )
    manager.add_argument(
        '-d', '--vhost', dest='vhosts', action='append',
        help='Domain name that will be included in the certificate. '
        'Must be specified at least once.', metavar='DOMAIN:PATH',
        type=Vhost.decode,
    )
    manager.add_argument(
        '--default_root', help='Default webroot path.', metavar='PATH',
    )

    io_group = parser.add_argument_group('Certificate data files')
    io_group.add_argument(
        '-f', dest='ioplugins', action='append', default=[],
        metavar='PLUGIN', choices=sorted(IOPlugin.registered),
        help='Input/output plugin of choice, can be specified multiple '
        'times and, in fact, it should be specified as many times as it '
        'is necessary to cover all components: key, certificate, chain. '
        'Allowed values: %s.' % ', '.join(sorted(IOPlugin.registered)),
    )
    io_group.add_argument(
        '--cert_key_size', type=int, default=4096, metavar='BITS',
        help='Certificate key size. Fresh key is created for each renewal.',
    )
    io_group.add_argument(
        '--valid_min', type=int, default=DEFAULT_VALID_MIN, metavar='SECONDS',
        help='Minimum validity of the resulting certificate.',
    )
    io_group.add_argument(
        '--reuse_key', action='store_true', default=False,
        help='Reuse private key if it was previously persisted.',
    )

    reg = parser.add_argument_group(
        'Registration', description='This client will automatically '
        'register an account with the ACME CA specified by `--server`.'
    )
    reg.add_argument(
        '--account_key_public_exponent', type=int, default=65537,
        metavar='BITS', help='Account key public exponent value.',
    )
    reg.add_argument(
        '--account_key_size', type=int, default=4096, metavar='BITS',
        help='Account key size in bits.',
    )
    reg.add_argument(
        '--tos_sha256', help='SHA-256 hash of the contents of Terms Of '
        'Service URI contents.', metavar='HASH',
    )
    reg.add_argument(
        '--email', help='Email address. CA is likely to use it to '
        'remind about expiring certificates, as well as for account '
        'recovery. Therefore, it\'s highly recommended to set this '
        'value.',
    )

    http = parser.add_argument_group(
        'HTTP', description='Configure properties of HTTP requests and '
        'responses.',
    )
    http.add_argument(
        '--user_agent', default=('simp_le/' + VERSION), metavar='NAME',
        help='User-Agent sent in all HTTP requests. Override with '
        '--user_agent "" if you want to protect your privacy.',
    )
    http.add_argument(
        '--server', metavar='URI', default=LE_PRODUCTION_URI,
        help='Directory URI for the CA ACME API endpoint.',
    )

    return parser


def supported_challb(authorization):
    """Find supported challenge body.

    This plugin supports only `http-01`, so CA must offer it as a
    single-element combo. If this is not the case this function returns
    `None`.

    Returns:
      `acme.messages.ChallengeBody` with `http-01` challenge or `None`.
    """
    for combo in authorization.body.combinations:
        first_challb = authorization.body.challenges[combo[0]]
        if len(combo) == 1 and isinstance(
                first_challb.chall, challenges.HTTP01):
            return first_challb
    return None


def compute_roots(vhosts, default_root):
    """Compute webroots.

    Args:
      vhosts: collection of `Vhost` objects.
      default_root: Default webroot path.

    Returns:
      Dictionary mapping vhost name to its webroot path. Vhosts without
      a root will be pre-populated with the `default_root`.
    """
    roots = {}
    for vhost in vhosts:
        if vhost.root is not None:
            root = vhost.root

            # We've had users mistakenly try to supplie a port number, like
            # example.com:8000 (see issue #51). Theoretically, this could be
            # a valid path, but it's *probably* a mistake; warn the user:
            match = re.match(r'^([0-9]{1,5})(:|$)', root)
            if match:
                portno, _ = match.groups()
                if 0 <= int(portno) < 2 ** 16:
                    logger.warning("Your webroot path (%s) looks like it is "
                                   "a port number or starts with one; this "
                                   "should be a directory name/path. "
                                   "Continuing anyway, but this may not be "
                                   "what you intended...", root)
        else:
            root = default_root
        roots[vhost.name] = root

    empty_roots = dict((name, root)
                       for name, root in six.iteritems(roots) if root is None)
    if empty_roots:
        raise Error('Root for the following host(s) were not specified: %s. '
                    'Try --default_root or use -d example.com:/var/www/html '
                    'syntax' % ', '.join(empty_roots))
    return roots


def save_validation(root, challb, validation):
    """Save validation to webroot.

    Args:
      root: Webroot path.
      challb: `acme.messages.ChallengeBody` with `http-01` challenge.
      validation: `http-01` validation
    """
    try:
        os.makedirs(os.path.join(root, challb.URI_ROOT_PATH))
    except OSError as error:
        if error.errno != errno.EEXIST:
            # directory doesn't already exist and we cannot create it
            raise
    path = os.path.join(root, challb.path[1:])
    with open(path, 'w') as validation_file:
        logger.debug('Saving validation (%r) at %s', validation, path)
        validation_file.write(validation)


def remove_validation(root, challb):
    """Remove validation from webroot.

    Args:
      root: Webroot path.
      challb: `acme.messages.ChallengeBody` with `http-01` challenge.
    """
    path = os.path.join(root, challb.path[1:])
    try:
        logger.debug('Removing validation file at %s', path)
        os.remove(path)
    except OSError as error:
        logger.error('Could not remove validation '
                     'file at %s : %s', path, error)


def sha256_of_uri_contents(uri, chunk_size=10):
    """Get SHA256 of URI contents.

    >>> with mock.patch('requests.get') as mock_get:
    ...     sha256_of_uri_contents('https://example.com')
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    h = hashlib.sha256()  # pylint: disable=invalid-name
    try:
        response = requests.get(uri, stream=True)
    except requests.ConnectionError:
        raise Error("Connection to %s failed.", uri)

    for chunk in response.iter_content(chunk_size):
        h.update(chunk)
    return h.hexdigest()


def componentwise_or(first, second):
    """Componentwise OR.

    >>> componentwise_or((False, False), (False, False))
    (False, False)
    >>> componentwise_or((True, False), (False, False))
    (True, False)
    >>> componentwise_or((True, False), (False, True))
    (True, True)
    """
    return tuple(x or y for x, y in zip(first, second))


def persist_data(args, existing_data, new_data):
    """Persist data on disk.

    Uses all selected plugins to save certificate data to disk.
    """
    for plugin_name in args.ioplugins:
        plugin = IOPlugin.registered[plugin_name]
        if any(persisted and existing != new
               for persisted, existing, new in
               zip(plugin.persisted(), existing_data, new_data)):
            plugin.save(new_data)


def asn1_generalizedtime_to_dt(timestamp):
    """Convert ASN.1 GENERALIZEDTIME to datetime.

    Useful for deserialization of `OpenSSL.crypto.X509.get_notAfter` and
    `OpenSSL.crypto.X509.get_notAfter` outputs.

    TODO: Implement remaining two formats: *+hhmm, *-hhmm.

    >>> asn1_generalizedtime_to_dt('201511150803Z')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=<UTC>)
    >>> asn1_generalizedtime_to_dt('201511150803+1512')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=pytz.FixedOffset(912))
    >>> asn1_generalizedtime_to_dt('201511150803-1512')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=pytz.FixedOffset(-912))
    """
    dt = datetime.datetime.strptime(  # pylint: disable=invalid-name
        timestamp[:12], '%Y%m%d%H%M%S')
    if timestamp.endswith('Z'):
        tzinfo = pytz.utc
    else:
        sign = -1 if timestamp[-5] == '-' else 1
        tzinfo = pytz.FixedOffset(
            sign * (int(timestamp[-4:-2]) * 60 + int(timestamp[-2:])))
    return tzinfo.localize(dt)


def renewal_necessary(cert, valid_min):
    """Is renewal necessary?

    >>> cert = crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60))
    >>> renewal_necessary(cert, 60 * 60 * 24)
    True
    >>> renewal_necessary(cert, 1)
    False
    """
    now = pytz.utc.localize(datetime.datetime.utcnow())
    expiry = asn1_generalizedtime_to_dt(cert.get_notAfter().decode())
    diff = expiry - now
    logger.debug('Certificate expires in %s on %s (relative to %s)',
                 diff, expiry, now)
    return diff < datetime.timedelta(seconds=valid_min)


class TestLoader(unittest.TestLoader):
    """simp_le test loader."""

    def load_tests_from_subclass(self, subcls):
        """Load tests which subclass from specific test case class."""
        module = __import__(__name__)
        return self.suiteClass([
            self.loadTestsFromTestCase(getattr(module, attr))
            for attr in dir(module)
            if isinstance(getattr(module, attr), type) and
            issubclass(getattr(module, attr), subcls)])


def test_suite(args, suite):
    """Run a specific test suite."""
    return EXIT_TESTS_OK if unittest.TextTestRunner(
        verbosity=(2 if args.verbose else 1)).run(
            suite).wasSuccessful() else EXIT_ERROR


def test(args):
    """Run tests (--test)."""
    return test_suite(args, unittest.TestSuite((
        TestLoader().load_tests_from_subclass(UnitTestCase),
        doctest.DocTestSuite(optionflags=(
            doctest.ELLIPSIS | doctest.IGNORE_EXCEPTION_DETAIL)),
    )))


def integration_test(args):
    """Run integration tests (--integration-test)."""
    return test_suite(
        args, unittest.defaultTestLoader.loadTestsFromTestCase(
            IntegrationTests))


def check_plugins_persist_all(ioplugins):
    """Do plugins cover all components (key/cert/chain)?"""
    persisted = IOPlugin.Data(
        account_key=False, key=False, cert=False, chain=False)
    for plugin_name in ioplugins:
        persisted = IOPlugin.Data(*componentwise_or(
            persisted, IOPlugin.registered[plugin_name].persisted()))

    not_persisted = set([
        component
        for component, persist in six.iteritems(persisted._asdict())
        if not persist])
    if not_persisted:
        raise Error('Selected IO plugins do not cover the following '
                    'components: %s.' % ', '.join(not_persisted))


def load_existing_data(ioplugins):
    """Load existing data from disk.

    Returns:
      `IOPlugin.Data` with all plugin data merged and sanity checked
      for coherence.
    """
    def merge(first, second, field):
        """Merge data from two plugins.

        >>> add(None, 1, 'foo')
        1
        >>> add(1, None, 'foo')
        1
        >>> add(None, None, 'foo')
        None
        >>> add(1, 2, 'foo')
        Error: Some plugins returned conflicting data for the "foo" component
        """
        if first is not None and second is not None and first != second:
            raise Error('Some plugins returned conflicting data for '
                        'the "%s" component' % field)
        return first or second

    all_existing = IOPlugin.EMPTY_DATA
    for plugin_name in ioplugins:
        all_persisted = IOPlugin.registered[plugin_name].persisted()
        all_data = IOPlugin.registered[plugin_name].load()

        # Check that plugins obey the interface: "`not persisted`
        # implies `data is None`" which is equivalent to `persisted or
        # data is None`
        assert all(persisted or data is None
                   for persisted, data in zip(all_persisted, all_data))

        all_existing = IOPlugin.Data(*(merge(*data) for data in zip(
            all_existing, all_data, all_data._fields)))
    return all_existing


def pyopenssl_cert_or_req_san(cert):
    """SANs from cert or csr."""
    # This function is not inlined mainly because pylint is bugged
    # when it comes to locally disabling protected access...
    # pylint: disable=protected-access
    return crypto_util._pyopenssl_cert_or_req_san(cert)


def valid_existing_cert(cert, vhosts, valid_min):
    """Is the existing cert data valid for enough time?

    If provided certificate is `None`, then always return True:

    >>> valid_existing_cert(cert=None, vhosts=[], valid_min=0)
    False

    >>> cert = jose.ComparableX509(crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60)))

    Return True iff `valid_min` is not bigger than certificate lifespan:

    >>> valid_existing_cert(cert, [Vhost.decode('example.com')], 0)
    True
    >>> valid_existing_cert(cert, [Vhost.decode('example.com')], 60 * 60 + 1)
    False

    If SANs mismatch return False no matter if expiring or not:

    >>> valid_existing_cert(cert, [Vhost.decode('example.net')], 0)
    False
    >>> valid_existing_cert(cert, [Vhost.decode('example.org')], 60 * 60 + 1)
    False
    """
    if cert is None:
        return False  # no existing certificate

    # renew existing?
    new_sans = [vhost.name for vhost in vhosts]
    existing_sans = pyopenssl_cert_or_req_san(cert.wrapped)
    logger.debug('Existing SANs: %r, new: %r', existing_sans, new_sans)
    return (set(existing_sans) == set(new_sans) and
            not renewal_necessary(cert, valid_min))


def check_or_generate_account_key(args, existing):
    """Check or generate account key."""
    if existing is None:
        logger.info('Generating new account key')
        return jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=args.account_key_public_exponent,
            key_size=args.account_key_size,
            backend=default_backend(),
        ))
    return existing


def registered_client(args, existing_account_key):
    """Create ACME client, register if necessary."""
    key = check_or_generate_account_key(args, existing_account_key)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    if args.email is None:
        logger.warning('--email was not provided; ACME CA will have no '
                       'way of contacting you.')
    new_reg = messages.NewRegistration.from_data(email=args.email)
    try:
        regr = client.register(new_reg)
    except acme_errors.ConflictError as error:
        logger.debug('Client already registered: %s', error.location)
    else:
        if regr.terms_of_service is not None:
            tos_hash = sha256_of_uri_contents(regr.terms_of_service)
            logger.debug('TOS hash: %s', tos_hash)
            if args.tos_sha256 != tos_hash:
                raise Error('TOS hash mismatch. Found: %s.' % tos_hash)
            client.agree_to_tos(regr)

    return client


def get_certr(client, csr, authorizations):
    """Get Certificate Resource for specified CSR and authorizations."""
    try:
        certr, _ = client.poll_and_request_issuance(
            jose.ComparableX509(csr), authorizations.values(),
            # https://github.com/letsencrypt/letsencrypt/issues/1719
            max_attempts=(10 * len(authorizations)))
    except acme_errors.PollError as error:
        if error.timeout:
            logger.error(
                'Timed out while waiting for CA to verify '
                'challenge(s) for the following authorizations: %s',
                ', '.join(authzr.uri for _, authzr in error.exhausted)
            )

        invalid = [authzr for authzr in six.itervalues(error.updated)
                   if authzr.body.status == messages.STATUS_INVALID]
        if invalid:
            logger.error("CA marked some of the authorizations as invalid, "
                         "which likely means it could not access "
                         "http://example.com/.well-known/acme-challenge/X. "
                         "Did you set correct path in -d example.com:path "
                         "or --default_root? Are all your domains accessible "
                         "from the internet? Please check your domains' DNS "
                         "entries, your host's network/firewall setup and "
                         "your webserver config. If a domain's DNS entry has "
                         "both A and AAAA fields set up, some CAs such as "
                         "Let's Encrypt will perform the challenge validation "
                         "over IPv6. If you haven't setup correct CAA fields "
                         "or if your DNS provider does not support CAA, "
                         "validation attempts after september 8, 2017 will "
                         "fail.  Failing authorizations: %s",
                         ', '.join(authzr.uri for authzr in invalid))

        raise Error('Challenge validation has failed, see error log.')
    return certr


def persist_new_data(args, existing_data):
    """Issue and persist new key/cert/chain."""
    roots = compute_roots(args.vhosts, args.default_root)
    logger.debug('Computed roots: %r', roots)

    client = registered_client(args, existing_data.account_key)

    authorizations = dict(
        (vhost.name, client.request_domain_challenges(
            vhost.name, new_authzr_uri=client.directory.new_authz))
        for vhost in args.vhosts
    )
    if any(supported_challb(auth) is None
           for auth in six.itervalues(authorizations)):
        raise Error('CA did not offer http-01-only challenge combo. '
                    'This client is unable to solve any other challenges.')

    for name, auth in six.iteritems(authorizations):
        challb = supported_challb(auth)
        response, validation = challb.response_and_validation(client.key)
        save_validation(roots[name], challb, validation)

        client.answer_challenge(challb, response)

    if args.reuse_key and existing_data.key is not None:
        logger.info('Reusing existing certificate private key')
        key = existing_data.key
    else:
        logger.info('Generating new certificate private key')
        key = ComparablePKey(gen_pkey(args.cert_key_size))
    csr = gen_csr(key.wrapped, [vhost.name.encode() for vhost in args.vhosts])
    try:
        certr = get_certr(client, csr, authorizations)
        persist_data(args, existing_data, new_data=IOPlugin.Data(
            account_key=client.key, key=key,
            cert=certr.body, chain=client.fetch_chain(certr)))
    except Error as error:
        persist_data(args, existing_data, new_data=IOPlugin.Data(
            account_key=client.key, key=None, cert=None, chain=None))
        raise error
    finally:
        for name, auth in six.iteritems(authorizations):
            challb = supported_challb(auth)
            remove_validation(roots[name], challb)


def revoke(args):
    """Revoke certificate."""
    existing_data = load_existing_data(args.ioplugins)
    if existing_data.cert is None:
        raise Error('No existing certificate')

    key = check_or_generate_account_key(args, existing_data.account_key)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    client.revoke(existing_data.cert, rsn=0)
    return EXIT_REVOKE_OK


def setup_logging(verbose):
    """Setup basic logging."""
    level = logging.DEBUG if verbose else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt='%(asctime)s:%(levelname)s:%(name)s:%(lineno)d: %(message)s',
    )
    formatter.converter = time.gmtime  # UTC instead of localtime
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)


def main_with_exceptions(cli_args):
    # pylint: disable=too-many-return-statements
    """Run the script, throw exceptions on error."""
    parser = create_parser()
    try:
        args = parser.parse_args(cli_args)
    except SystemExit:
        return EXIT_ERROR

    if args.test:  # --test
        return test(args)
    elif args.integration_test:  # --integration_test
        return integration_test(args)
    elif args.help:  # --help
        parser.print_help()
        return EXIT_HELP_VERSION_OK
    elif args.version:  # --version
        sys.stdout.write('%s %s\n' % (os.path.basename(sys.argv[0]), VERSION))
        return EXIT_HELP_VERSION_OK

    setup_logging(args.verbose)
    logger.debug('%r parsed as %r', cli_args, args)

    if args.revoke:  # --revoke
        return revoke(args)

    if args.vhosts is None:
        raise Error('You must set at least one -d/--vhost')
    check_plugins_persist_all(args.ioplugins)

    existing_data = load_existing_data(args.ioplugins)
    if valid_existing_cert(existing_data.cert, args.vhosts, args.valid_min):
        logger.info('Certificates already exist and renewal is not '
                    'necessary, exiting with status code %d.', EXIT_NO_RENEWAL)
        return EXIT_NO_RENEWAL

    if args.tos_sha256 is None:
        logger.info("Retrieving Let's Encrypt latest Terms of Service.")
        args.tos_sha256 = get_le_tos_hash(LE_PRODUCTION_URI)

    persist_new_data(args, existing_data)
    return EXIT_RENEWAL


def exit_with_error(message):
    """Print `message` and debugging tips to STDERR, exit with EXIT_ERROR."""
    sys.stderr.write('%s\n\nDebugging tips: -v improves output verbosity. '
                     'Help is available under --help.\n' % message)
    return EXIT_ERROR


def main(cli_args=tuple(sys.argv[1:])):     # tuple avoids a pylint warning
                                            # about (mutable) list as default
                                            # argument.
    """Run the script, with exceptions caught and printed to STDERR."""
    # logging (handler) is not set up yet, use STDERR only!
    try:
        return main_with_exceptions(cli_args)
    except Error as error:
        return exit_with_error(error)
    except messages.Error as error:
        return exit_with_error('ACME server returned an error: %s\n' % error)
    except BaseException as error:  # pylint: disable=broad-except
        # maintain manifest invariant: `exit 1` iff renewal not
        # necessary, `exit 2` iff error
        traceback.print_exc(file=sys.stderr)
        return exit_with_error(
            '\nUnhandled error has happened, traceback is above')


class MainTest(UnitTestCase):
    """Unit tests for main()."""

    # this is a test suite | pylint: disable=missing-docstring

    @classmethod
    def _run(cls, args):
        return main(shlex.split(args))

    @mock.patch('sys.stdout')
    def test_exit_code_help_version_ok(self, dummy_stdout):
        # pylint: disable=unused-argument
        self.assertEqual(EXIT_HELP_VERSION_OK, self._run('--help'))
        self.assertEqual(EXIT_HELP_VERSION_OK, self._run('--version'))

    @mock.patch('sys.stderr')
    def test_error_exit_codes(self, dummy_stderr):
        # pylint: disable=unused-argument
        test_args = [
            '',  # no args - no good
            '--bar',  # unrecognized
            '-f account_key.json -f key.pem -f fullchain.pem',  # no vhosts
            # no root
            '-f account_key.json -f key.pem -f fullchain.pem -d example.com',
            # no root with multiple domains
            '-f account_key.json -f key.pem -f fullchain.pem '
            '-d example.com:public_html  -d www.example.com',
        ]
        # missing plugin coverage
        test_args.extend(['-d example.com:public_html %s' % rest for rest in [
            '-f account_key.json',
            '-f key.pem',
            '-f account_key.json -f key.pem',
            '-f key.pem -f cert.pem',
            '-f key.pem -f chain.pem',
            '-f fullchain.pem',
            '-f cert.pem -f fullchain.pem',
        ]])

        for args in test_args:
            self.assertEqual(
                EXIT_ERROR, self._run(args), 'Wrong exit code for %s' % args)


@contextlib.contextmanager
def chdir(path):
    """Context manager that adjusts CWD."""
    old_path = os.getcwd()
    os.chdir(path)
    try:
        yield old_path
    finally:
        os.chdir(old_path)


class IntegrationTests(unittest.TestCase):
    """Integrations tests with Boulder.

    Prerequisites:
    - /etc/hosts:127.0.0.1 le.wtf
    - Boulder running on localhost:4000
    - Boulder verifying http-01 on port 5002
    """
    # this is a test suite | pylint: disable=missing-docstring

    SERVER = 'http://localhost:4000/directory'
    TOS_SHA256 = ('b16e15764b8bc06c5c3f9f19bc8b99fa'
                  '48e7894aa5a6ccdad65da49bbf564793')
    PORT = 5002

    @classmethod
    def _run(cls, cmd):
        args = ' '.join(cmd[1:])
        logger.debug('Running simp_le with the following args: %s', args)
        return subprocess.call(cmd)

    @classmethod
    @contextlib.contextmanager
    def _new_swd(cls):
        path = tempfile.mkdtemp()
        try:
            with chdir(path) as old_path:
                yield old_path, path
        finally:
            shutil.rmtree(path)

    @classmethod
    def get_stats(cls, *paths):
        def _single_path_stats(path):
            all_stats = os.stat(path)
            stats = dict(
                (name[3:], getattr(all_stats, name)) for name in dir(all_stats)
                # skip access (read) time, includes _ns.
                if name.startswith('st_') and not name.startswith('st_atime'))
            # st_*time has a second-granularity so it can't be
            # reliably used to prove that contents have changed or not
            with open(path, 'rb') as f:  # pylint: disable=invalid-name
                stats.update(checksum=hashlib.sha256(f.read()).hexdigest())
            return stats
        return dict((path, _single_path_stats(path)) for path in paths)

    def test_it(self):
        webroot = os.path.join(os.getcwd(), 'public_html')
        cmd = ["simp_le", "-v", "--server", (self.SERVER), "--tos_sha256",
               (self.TOS_SHA256), "-f", "account_key.json", "-f", "key.pem",
               "-f", "full.pem"]
        files = ('account_key.json', 'key.pem', 'full.pem')
        with self._new_swd():
            webroot_fail_arg = ["-d", "le.wtf:%s" % os.getcwd()]
            self.assertEqual(EXIT_ERROR, self._run(cmd + webroot_fail_arg))
            # Failed authorization should generate the account key anyway
            unchangeable_stats = self.get_stats(files[0])

            webroot_1_arg = ["-d", "le.wtf:%s" % webroot]
            self.assertEqual(EXIT_RENEWAL, self._run(cmd + webroot_1_arg))
            # Account key should be kept from previous failed attempt
            self.assertEqual(unchangeable_stats, self.get_stats(files[0]))
            initial_stats = self.get_stats(*files)

            self.assertEqual(EXIT_NO_RENEWAL, self._run(cmd + webroot_1_arg))
            # No renewal => no files should be touched
            # NB get_stats() would fail if file didn't exist
            self.assertEqual(initial_stats, self.get_stats(*files))

            self.assertEqual(EXIT_REVOKE_OK, self._run([
                "simp_le", "-v", "--server", (self.SERVER), "--revoke",
                "-f", "account_key.json", "-f", "full.pem"]))
            # Revocation shouldn't touch any files
            self.assertEqual(initial_stats, self.get_stats(*files))

            webroot_2_arg = ["-d", "le2.wtf:%s" % webroot]
            # Changing SANs should trigger "renewal"
            self.assertEqual(EXIT_RENEWAL,
                             self._run(cmd + webroot_1_arg + webroot_2_arg))
            # but it shouldn't unnecessarily overwrite the account key (#67)
            self.assertEqual(unchangeable_stats, self.get_stats(files[0]))


if __name__ == '__main__':
    raise SystemExit(main())
