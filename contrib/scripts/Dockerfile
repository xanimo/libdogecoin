# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM ubuntu:jammy AS build
ARG TARGET_HOST_TRIPET
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN apt-get update && apt-get install -y git wget
RUN git clone https://github.com/xanimo/libdogecoin \
    && cd /libdogecoin \
    && git checkout 0.1-dev-koinu-refactor
WORKDIR /libdogecoin
RUN ./contrib/scripts/run.sh --docker --host $TARGET_HOST_TRIPET --setup --depends --clean
RUN ./contrib/scripts/run.sh --docker --host $TARGET_HOST_TRIPET --build --depends --clean
RUN ./contrib/scripts/run.sh --docker --host $TARGET_HOST_TRIPET --depends --clean --test
ENTRYPOINT [ "./contrib/scripts/run.sh" ]
