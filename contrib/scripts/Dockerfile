# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM ubuntu:jammy AS build
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/xanimo/libdogecoin \
    && cd /libdogecoin \
    && git checkout 0.1-dev-transaction
WORKDIR /libdogecoin
RUN ./contrib/scripts/run.sh --docker --host --all --setup
ENTRYPOINT [ "./contrib/scripts/run.sh" ]
