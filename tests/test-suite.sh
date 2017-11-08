#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

case $1 in
  lint_suite)
    pycodestyle simp_le.py
    pylint --disable=locally-disabled,fixme simp_le
    ;;
  simp_le_suite)
    simp_le -v --test
    simp_le -v --integration_test
    ;;
  docker_suite)
    official-images/test/run.sh zenhack/simp_le
    docker run --rm zenhack/simp_le -v --test
    docker run --rm --net="host" -v "${TRAVIS_BUILD_DIR}/public_html:/simp_le/certs/public_html" zenhack/simp_le -v --integration_test
    ;;
esac

# vim: set ts=2 sw=2 et :
