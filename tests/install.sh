#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

PORT=5002

setup_docker_compose () {
  curl -L https://github.com/docker/compose/releases/download/1.21.1/docker-compose-"$(uname -s)"-"$(uname -m)" > docker-compose.temp
  chmod +x docker-compose.temp
  sudo mv docker-compose.temp /usr/local/bin/docker-compose
}

setup_boulder() {
  # Per the boulder README:
  docker_ip=$(ifconfig docker0 | grep "inet addr:" | cut -d: -f2 | awk '{ print $1}')

  export GOPATH=${HOME?}/go
  git clone https://github.com/letsencrypt/boulder \
    $GOPATH/src/github.com/letsencrypt/boulder
  cd $GOPATH/src/github.com/letsencrypt/boulder
  git checkout release-2019-10-13
  docker-compose pull
  docker-compose build
  docker-compose run \
    --use-aliases \
    -e FAKE_DNS=$docker_ip \
    --service-ports \
    boulder &
  cd -
}

setup_pebble() {
  docker network create --driver=bridge --subnet=10.30.50.0/24 acmenet
  curl https://raw.githubusercontent.com/letsencrypt/pebble/master/test/certs/pebble.minica.pem > ${TRAVIS_BUILD_DIR}/pebble.minica.pem
  cat ${TRAVIS_BUILD_DIR}/pebble.minica.pem

  docker run \
    --name pebble \
    --network acmenet \
    --ip="10.30.50.2" \
    --publish 14000:14000 \
    letsencrypt/pebble:v2.1.0 \
    pebble -config /test/config/pebble-config.json -dnsserver 10.30.50.3:8053 &

  docker run \
    --name challtestserv \
    --network acmenet \
    --ip="10.30.50.3" \
    --publish 8055:8055 \
    letsencrypt/pebble-challtestsrv:v2.1.0 \
    pebble-challtestsrv -defaultIPv6 "" -defaultIPv4 10.30.50.1 &
}

setup_acme_server() {
  case $ACME_CA in
    boulder)
      setup_boulder
      ;;
    pebble)
      setup_pebble
      ;;
  esac
}

wait_for_acme_server() {
  i=0
  case $ACME_CA in
    boulder)
      url='http://10.77.77.1:4001/directory'
      ;;
    pebble)
      url='https://pebble:14000/dir'
      ;;
  esac
  while ! curl -k $url >/dev/null 2>&1; do
    if [ $(($i * 5)) -gt $((5 * 60)) ]; then
      printf "$ACME_CA has not started for 5 minutes, timing out.\n"
      exit 1
    fi
    i=$((i + 1))
    sleep 5
  done
}

setup_webroot() {
  mkdir public_html
  cd public_html
  python -m http.server ${PORT?} &
  cd -
}

case $1 in
  lint_suite)
    pip install -e .[tests]
    ;;
  simp_le_suite)
    pip install -e .
    setup_docker_compose
    setup_acme_server
    setup_webroot
    wait_for_acme_server
    ;;
  docker_suite)
    [ $ARCH != "amd64" ] && docker run --rm --privileged multiarch/qemu-user-static:register --reset
    docker build --build-arg BUILD_FROM="${FROM}" --tag "$IMAGE" --file docker/Dockerfile .
    git clone https://github.com/docker-library/official-images.git official-images
    setup_docker_compose
    setup_acme_server
    setup_webroot
    wait_for_acme_server
    ;;
esac

# vim: set ts=2 sw=2 et :
