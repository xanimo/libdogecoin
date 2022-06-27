#!/bin/bash

set -e

pushd `pwd`/wrappers/golang/libdogecoin

if ! command -v go &> /dev/null
then
    wget https://go.dev/dl/go1.18.2.linux-amd64.tar.gz
    echo "e54bec97a1a5d230fc2f9ad0880fcbabb5888f30ed9666eca4a91c5a32e86cbc go1.18.2.linux-amd64.tar.gz" | sha256sum -c
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.18.2.linux-amd64.tar.gz
    sudo mv /usr/local/go/bin/go /usr/local/bin/go
    echo "export PATH=$PATH:/usr/local/bin/go" >> ~/.bashrc
    source ~/.bashrc
    sudo rm go1.18.2.linux-amd64.tar.gz
    if ! command -v go &> /dev/null
    then
        echo "go could not be found"
        exit
    fi
fi

go build -x -work -ldflags '-linkmode external -extldflags "-static"' .

go test -v

go clean -x -i -testcache

popd