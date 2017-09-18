FROM alpine:3.6

MAINTAINER Ian Denhardt (@zenhack)

ARG SIMP_LE_VERSION=master

ENV PATH=/usr/local/bin:$PATH \
    SIMP_LE_VERSION=${SIMP_LE_VERSION}

RUN apk --no-cache add \
        bash \
        openssl \
        python3 \
    && apk --no-cache --virtual .build-deps add \
        gcc \
        git \
        libffi-dev \
        musl-dev \
        openssl-dev \
        py-pip \
        python3-dev \
    && pip3 install --no-cache-dir git+https://github.com/zenhack/simp_le.git@${SIMP_LE_VERSION} \
    && apk --update --purge del .build-deps \
    && rm /var/cache/apk/*

COPY /entrypoint.sh /simp_le/entrypoint.sh

WORKDIR /simp_le/certs

ENTRYPOINT [ "/bin/bash", "/simp_le/entrypoint.sh" ]
CMD [ "--help" ]
