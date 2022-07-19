# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM ubuntu:jammy AS build
ARG TARGET_HOST=${TARGET_HOST:-"x86_64-pc-linux-gnu"}

RUN apt-get update && apt-get install -y git
RUN mkdir -p build
RUN git clone https://github.com/xanimo/libdogecoin
RUN cd libdogecoin && git checkout 0.1-dev-docker && ./contrib/scripts/setup.sh --host ${TARGET_HOST} --depends --docker
RUN cd libdogecoin && ./contrib/scripts/build.sh --host ${TARGET_HOST} --depends
COPY pack.sh libdogecoin/contrib/scripts/pack.sh
RUN cd libdogecoin && ./contrib/scripts/pack.sh --host=${TARGET_HOST} --prefix=build --docker
RUN cp -r libdogecoin/output/* /build \
    && rm -rf libdogecoin

FROM scratch as artifact
COPY --from=build /build /build

FROM release
