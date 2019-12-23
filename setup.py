import codecs
import os
import setuptools


here = os.path.abspath(os.path.dirname(__file__))
readme = codecs.open(os.path.join(here, 'README.rst'), encoding='utf-8').read()

install_requires = [
    # We don't use idna directly, but problems with PyPI's solver
    # have resulted in broken installations twice now, (when idna 2.6
    # was released, and again with 2.7) so as a workaround, we provide
    # an explicit upper bound here, before any of the other constraints
    # are read.
    #
    # See:
    #
    # * https://github.com/zenhack/simp_le/issues/62
    # * https://github.com/pypa/pip/issues/988
    'idna<2.8',

    'acme>=1.0.0',
    'cryptography',
    # formerly known as acme.jose:
    'josepy',
    'mock',
    'pyOpenSSL',
    'pytz',
]

tests_require = [
    'pycodestyle',
    'pylint',
]

setuptools.setup(
    name='simp_le-client',
    author='Ian Denhardt',
    author_email='ian@zenhack.net',
    description="Simple Let's Encrypt Client",
    long_description=readme,
    license='GPLv3',
    url='https://github.com/zenhack/simp_le',
    py_modules=['simp_le'],
    setup_requires=['setuptools_scm'],
    use_scm_version=True,
    install_requires=install_requires,
    extras_require={
        'tests': tests_require,
    },
    entry_points={
        'console_scripts': [
            'simp_le = simp_le:main',
        ],
    },
    classifiers=[
        'Development Status :: 6 - Mature',
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
)
