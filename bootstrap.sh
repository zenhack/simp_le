#!/bin/sh -xe

# keep in sync with .travis.yml
bootstrap_deb () {
  apt-get update

  apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    libssl-dev \
    libffi-dev \
    python3 \
    python3-dev \
    python3-virtualenv
}

bootstrap_rpm () {
  installer=$(command -v dnf || command -v yum)
  "${installer?}" install -y \
    ca-certificates \
    gcc \
    libffi-devel \
    openssl-devel \
    python \
    python-devel \
    python-virtualenv
}

if [ -f /etc/debian_version ]
then
  bootstrap_deb
elif [ -f /etc/redhat-release ]
then
  bootstrap_rpm
fi
