#!/bin/bash

#install dependencies
sudo apt-get update
apt-get install -y libelf-dev lsb-release wget \
    software-properties-common procps \
    build-essential make gnupg libbpf-dev \
    bpfcc-tools docker.io clang bpftrace llvm libelf-dev

mkdir bpf-tooling
cd bpf-tooling
git clone https://github.com/libbpf/libbpf.git
cd libbpf/src
make install

cd ..
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make install

cd ../..