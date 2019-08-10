#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

run_host_integration_test(){
  case $ACME_CA in
    boulder)
      simp_le -v --integration_test \
        --server http://10.77.77.1:4001/directory
      ;;
    pebble)
      simp_le -v --integration_test \
        --ca_bundle "${TRAVIS_BUILD_DIR}/pebble.minica.pem" \
        --server https://pebble:14000/dir
      ;;
  esac
}

run_docker_integration_test(){
  case $ACME_CA in
    boulder)
      docker run --rm \
        --network host \
        --volume "${TRAVIS_BUILD_DIR}/public_html:/simp_le/certs/public_html" \
        "$IMAGE" -v --integration_test \
        --server http://10.77.77.1:4001/directory
      ;;
    pebble)
      docker run --rm \
        --network acmenet \
        --volume "${TRAVIS_BUILD_DIR}/public_html:/simp_le/certs/public_html" \
        --volume "${TRAVIS_BUILD_DIR}/pebble.minica.pem:/pebble.minica.pem" \
        "$IMAGE" -v --integration_test \
        --server https://pebble:14000/dir \
        --ca_bundle /pebble.minica.pem
      ;;
  esac
}

case $1 in
  lint_suite)
    pycodestyle simp_le.py
    pylint --disable=locally-disabled,fixme simp_le
    ;;
  simp_le_suite)
    simp_le -v --test
    run_host_integration_test
    ;;
  docker_suite)
    official-images/test/run.sh "$IMAGE"
    docker run --rm "$IMAGE" -v --test
    run_docker_integration_test
    ;;
esac

# vim: set ts=2 sw=2 et :
