# This Dockerfile generates a build environment for generating ELFs
# of testdata programs. Run `make build` in this directory to build it.
FROM debian:bookworm

RUN apt-get update \
	&& apt-get install -y libelf-dev lsb-release wget \
    software-properties-common procps build-essential make gnupg libbpf-dev bpfcc-tools docker.io clang bpftrace llvm 


# Let's install libbpf.
WORKDIR /build
RUN git clone https://github.com/libbpf/libbpf.git
WORKDIR /build/libbpf/src
RUN make install

# Let's install bpftool
WORKDIR /build
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git
WORKDIR /build/bpftool/src
RUN make install



WORKDIR /build/sysstream

COPY . .

RUN touch *.c && make
RUN cp ./sysstream /usr/bin/sysstream
WORKDIR /
RUN rm -rf /build

WORKDIR /sysstream
