simp_le for Docker
========

[![Build Status](https://travis-ci.org/zenhack/simp_le.svg)](https://travis-ci.org/zenhack/simp_le)

Simple [Let’s Encrypt](https://letsencrypt.org/) client in a Docker container.

This image is running on Alpine Linux and is around 80MB in size.

N.B. this was originally a fork of https://github.com/kuba/simp_le, which is unmaintained and has some breakage due to bitrot. Thanks to @kuba for the original implementation.


Manifesto
---------

For more info on simp_le aims, please read [its manifesto](https://github.com/zenhack/simp_le/blob/master/README.rst#manifesto).

How to use this image
--------

The generated files are saved inside the container to `/simp_le/certs`, mount a volume there to get them.

To obtain a certificate and private key for both `example.com` and `www.example.com` (assuming both domains are resolving to the host IP and a webserver is already running on the host, serving files from `/path/to/webroot`):

```
$ docker run --rm \
    -v /path/to/webroot:/simp_le/www \
    -v $PWD:/simp_le/certs \
    zenhack/simp_le \
    --email you@example.com \
    -f account_key.json \
    -f fullchain.pem \
    -f key.pem \
    -d example.com \
    -d www.example.com \
    --default_root /simp_le/www
```

- `-v /path/to/webroot:/simp_le/www` bind mount the local path `/path/to/webroot` to `/simp_le/www` inside the container, which is in turn used as simp_le default webroot with `--default_root`
- `-v $PWD:/simp_le/certs` bind mount your local working directory to `/simp_le/certs` inside the container, where the requested files will be created.

For more info run `$ docker run --rm zenhack/simp_le --help`.

Example use with nginx container
--------

You can combine this container with [nginx](https://hub.docker.com/_/nginx/) to quickly obtain certificates for your domains:

```
$ docker run -d \
    --name nginx \
    -p "80:80" \
    -v webroot:/usr/share/nginx/html \
    nginx:alpine
```
```
$ docker run --rm \
    --volumes-from nginx \
    -v $PWD:/simp_le/certs zenhack/simp_le \
    --email you@example.com \
    -f account_key.json \
    -f fullchain.pem \
    -f key.pem \
    -d example.com \
    -d www.example.com \
    --default_root /usr/share/nginx/html
```

Building the image from source
--------

For testing and development purpose, you can build this image from the cloned GitHub repository:

```
$ git clone https://github.com/zenhack/simp_le.git
$ cd simp_le
$ docker build -t zenhack/simp_le -f docker/Dockerfile.localbuild .
```

You can also build the image with a specific release of simp_le:

```
$ docker build --build-arg SIMP_LE_VERSION=0.5.0 -t zenhack/simp_le:0.5.0 docker/
```

Help
--------

Have a look at https://github.com/zenhack/simp_le/wiki/Examples
