# syntax=docker/dockerfile:1
ARG IMG_ARCH
FROM --platform=$BUILDPLATFORM ${IMG_ARCH}/ubuntu:jammy AS build
ARG COMMIT=${COMMIT:-0.1-dev-docker}
ARG TARGET_HOST
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN apt-get update
RUN apt-get install -y \
git \
wget
RUN git clone https://github.com/xanimo/libdogecoin
WORKDIR /libdogecoin
RUN git checkout $COMMIT
RUN ./contrib/scripts/run.sh --host ${TARGET_HOST} --docker --setup --build --depends --test
ENTRYPOINT [ "./contrib/scripts/run.sh" ]
