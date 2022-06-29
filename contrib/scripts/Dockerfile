# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM ubuntu:jammy AS build
ARG TARGET_HOST_TRIPET
ARG TARGETPLATFORM
ARG BUILDPLATFORM
RUN apt-get update
RUN apt-get install -y --no-install-recommends \
git \
wget \
apt-transport-https \
ca-certificates \
curl \
gnupg-agent \
software-properties-common
RUN git clone https://github.com/xanimo/libdogecoin
WORKDIR /libdogecoin
RUN git checkout 0.1-dev-buildx
RUN ./contrib/scripts/run.sh --docker --host $TARGET_HOST_TRIPET --setup --depends --clean
RUN ./contrib/scripts/run.sh --docker --host $TARGET_HOST_TRIPET --build --depends --clean
RUN ./contrib/scripts/run.sh --docker --host $TARGET_HOST_TRIPET --depends --clean --test
ENTRYPOINT [ "./contrib/scripts/run.sh" ]
