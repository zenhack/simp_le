#!/bin/sh

# This script is sourced in .travis.yml, and `source` doesn't take
# into evaluate the shebang line, so it needs to be set explicitly
# here. Otherwise tests will happily pass despite non-zero exit codes
# from some of the commands in this file (#39).
set -xe

SERVER='http://10.77.77.1:4000/directory'
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
  git clone --depth=1 https://github.com/letsencrypt/boulder \
    $GOPATH/src/github.com/letsencrypt/boulder
  cd $GOPATH/src/github.com/letsencrypt/boulder
  docker-compose pull
  docker-compose build
  docker-compose run \
    --use-aliases \
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

case $1 in
  lint_suite)
    pip install -e .[tests]
    ;;
  simp_le_suite)
    pip install -e .
    setup_docker_compose
    setup_boulder
    setup_webroot
    wait_for_boulder
    ;;
  docker_suite)
    [ $ARCH != "amd64" ] && docker run --rm --privileged multiarch/qemu-user-static:register --reset
    docker build --build-arg BUILD_FROM="${FROM}" --tag "$IMAGE" --file docker/Dockerfile .
    git clone https://github.com/docker-library/official-images.git official-images
    setup_docker_compose
    setup_boulder
    setup_webroot
    wait_for_boulder
    ;;
esac

# vim: set ts=2 sw=2 et :
