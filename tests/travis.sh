#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

SERVER=http://localhost:4000/directory
PORT=5002

setup_boulder() {
  # Per the boulder README:
  docker_ip=$(ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}')

  export GOPATH=${HOME?}/go
  git clone --depth=1 https://github.com/letsencrypt/boulder \
    $GOPATH/src/github.com/letsencrypt/boulder
  cd $GOPATH/src/github.com/letsencrypt/boulder
  docker-compose pull
  docker pull letsencrypt/boulder-tools
  docker-compose build
  docker-compose run \
    -e FAKE_DNS=$docker_ip \
    --service-ports \
    boulder &
  cd -
}

setup_webroot() {
  mkdir public_html
  cd public_html
  if python -V 2>&1 | grep -q "Python 3."; then
    python -m http.server ${PORT?} &
  else
    python -m SimpleHTTPServer ${PORT?} &
  fi
  cd -
}

wait_for_boulder() {
  i=0
  while ! curl ${SERVER?} >/dev/null 2>&1; do
    if [ $(($i * 5)) -gt $((5 * 60)) ]; then
      printf 'Boulder has not started for 5 minutes, timing out.\n'
      exit 1
    fi
    i=$((i + 1))
    sleep 5
  done
}

if [ "py${TOXENV#py}" = "${TOXENV}" ]; then
  BOULDER_INTEGRATION=yes
fi

case $1 in
  install)
    pip install tox
    if [ "x$BOULDER_INTEGRATION" != "x" ]; then
      setup_boulder
      setup_webroot
      wait_for_boulder
    fi
    ;;
  script)
    export TOXENV
    tox
    if [ "x$BOULDER_INTEGRATION" != "x" ]; then
      . .tox/$TOXENV/bin/activate
      pip -V
      simp_le -v --test
      simp_le -v --integration_test
    fi
    ;;
esac

# vim: set ts=2 sw=2 et :
