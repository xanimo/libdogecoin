sudo apt-get update
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y \
autoconf \
automake \
libtool-bin \
libevent-dev \
build-essential \
curl \
python3 \
valgrind \
g++-arm-linux-gnueabihf \
qemu-user-static \
qemu-user
make -C depends \
HOST=arm-linux-gnueabihf \
CROSS_COMPILE='yes' \
SPEED=slow V=1
./autogen.sh
./configure \
--prefix=`pwd`/depends/arm-linux-gnueabihf \
LIBTOOL_APP_LDFLAGS='-all-static' \
LIBS='-levent -levent_core -lm' \
LDFLAGS=-static-libstdc++ \
--enable-glibc-back-compat \
--enable-static \
--disable-shared
make && qemu-arm -E LD_LIBRARY_PATH=/usr/arm-linux-gnueabihf/lib/ /usr/arm-linux-gnueabihf/lib/ld-linux-armhf.so.3 ./tests