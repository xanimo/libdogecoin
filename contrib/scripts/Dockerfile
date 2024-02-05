# syntax=docker/dockerfile:1
ARG FLAVOR
FROM --platform=$BUILDPLATFORM ubuntu:$FLAVOR AS build
ARG TARGET_HOST=${TARGET_HOST:-"x86_64-pc-linux-gnu"}
ARG TARGET_ARCH=${TARGET_ARCH:-"amd64"}

# configure the shell before the first RUN
SHELL ["/bin/bash", "-ex", "-o", "pipefail", "-c"]

RUN sed -i "s/deb http:\/\/archive.ubuntu.com\/ubuntu focal-backports main restricted universe multiverse/deb [arch=${TARGET_ARCH}] http:\/\/archive.ubuntu.com\/ubuntu focal-backports main restricted universe multiverse/g" /etc/apt/sources.list
RUN mkdir -p build
COPY ../. /libdogecoin
WORKDIR /libdogecoin
RUN ./contrib/scripts/setup.sh --host ${TARGET_HOST} --depends --docker
RUN ./contrib/scripts/build.sh --host ${TARGET_HOST} --depends
RUN ./contrib/scripts/pack.sh --host=${TARGET_HOST} --prefix=build
RUN cp -r ./output/* ../build

FROM scratch as artifact
COPY --from=build ./build ./output
