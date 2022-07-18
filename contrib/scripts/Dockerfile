# syntax=docker/dockerfile:1
ARG IMG_ARCH
ARG TARGET_HOST

FROM --platform=$BUILDPLATFORM ${IMG_ARCH}/ubuntu:jammy AS build
ARG COMMIT=${COMMIT:-0.1-dev-docker}
ARG TARGET_HOST
ARG TARGETPLATFORM
ARG TAG=${TAG:-v0.1}
RUN apt-get update
RUN apt-get install -y \
git \
wget
RUN git clone https://github.com/xanimo/libdogecoin
WORKDIR /libdogecoin
RUN git checkout $COMMIT && rm -rf ./contrib/scripts/*
COPY . ./contrib/scripts/
RUN ./contrib/scripts/run.sh --host ${TARGET_HOST} --docker --setup --depends
RUN ./contrib/scripts/run.sh --host ${TARGET_HOST} --docker --build --depends
RUN TAG=${TAG} ./contrib/scripts/run.sh --host ${TARGET_HOST} --docker --package
RUN cp ./build ./root/build

FROM scratch as artifact
ARG TARGET_HOST
ARG TAG=${TAG:-v0.1}
COPY --from=build /root/build/libdogecoin-${TARGET_HOST}-${TAG} /build/libdogecoin-${TARGET_HOST}-${TAG}

FROM release
