ARG BUILD_FROM=alpine:3.7

FROM $BUILD_FROM

LABEL maintainer="Ian Denhardt (@zenhack)"

ENV PATH=/usr/local/bin:$PATH

COPY . /simp_le/src

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
        tzdata \
    && cp /usr/share/zoneinfo/UTC /etc/localtime \
    && echo "UTC" > /etc/timezone \
    && pip3 install --no-cache-dir /simp_le/src \
    && rm -rf /simp_le/src \
    && apk del --purge .build-deps \
    && rm -fv /var/cache/apk/*

WORKDIR /simp_le/certs

COPY /docker/entrypoint.sh /simp_le/entrypoint.sh

ENTRYPOINT [ "/simp_le/entrypoint.sh" ]
CMD [ "--help" ]
