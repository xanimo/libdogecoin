# syntax=docker/dockerfile:1
ARG FLAVOR
FROM --platform=$BUILDPLATFORM ubuntu:$FLAVOR AS build
ARG TARGET_HOST=${TARGET_HOST:-"x86_64-pc-linux-gnu"}

# configure the shell before the first RUN
SHELL ["/bin/bash", "-ex", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install --no-install-recommends -y \
    git \
    ca-certificates
RUN mkdir -p build
RUN git clone https://github.com/xanimo/libdogecoin
RUN cd libdogecoin && git checkout 0.1-dev-docker && ./contrib/scripts/setup.sh --host ${TARGET_HOST} --depends --docker
RUN cd libdogecoin && ./contrib/scripts/build.sh --host ${TARGET_HOST} --depends
RUN cd libdogecoin && ./contrib/scripts/pack.sh --host=${TARGET_HOST} --prefix=build --docker
RUN cp -r libdogecoin/output/* /build \
    && rm -rf libdogecoin

FROM scratch as artifact
COPY --from=build /build /build

FROM release
