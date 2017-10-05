FROM alpine:3.6

LABEL maintainer="Ian Denhardt (@zenhack)"

ARG SIMP_LE_VERSION=master

ENV PATH=/usr/local/bin:$PATH \
    SIMP_LE_VERSION=${SIMP_LE_VERSION}

RUN apk update \
    && apk add \
        openssl \
        python3 \
    && apk add --virtual .build-deps \
        gcc \
        git \
        libffi-dev \
        musl-dev \
        openssl-dev \
        py-pip \
        python3-dev \
    && pip3 install --no-cache-dir git+https://github.com/zenhack/simp_le.git@${SIMP_LE_VERSION} \
    && apk del --purge .build-deps \
    && rm -fv /var/cache/apk/*

COPY /entrypoint.sh /simp_le/entrypoint.sh

WORKDIR /simp_le/certs

ENTRYPOINT [ "/simp_le/entrypoint.sh" ]
CMD [ "--help" ]
