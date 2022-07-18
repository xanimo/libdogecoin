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

FROM build as builder
RUN git checkout $COMMIT && rm -rf ./contrib/scripts/*
COPY . ./contrib/scripts/
RUN ./contrib/scripts/run.sh --host ${TARGET_HOST} --docker --setup --depends
RUN ./contrib/scripts/run.sh --host ${TARGET_HOST} --docker --build --depends
RUN ./contrib/scripts/pack.sh --host=${TARGET_HOST} --prefix=build --docker 

FROM builder as artifact
ARG TARGET_HOST
ARG TAG=${TAG:-v0.1}
COPY --from=builder /output /build

FROM release
