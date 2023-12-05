FROM ubuntu:latest

RUN apt-get update && \
    apt-get install -y build-essential git cmake \
                       zlib1g-dev libevent-dev \
                       libelf-dev llvm \
                       clang libc6-dev-i386 \
                       vim wget \ 
                        nodejs npm \
                        && wget -O /tmp/go.tar.gz https://go.dev/dl/go1.21.4.linux-amd64.tar.gz \ 
                        && tar zxvf /tmp/go.tar.gz -C /opt \ 
                        && rm /tmp/*.tar.gz

RUN rm -rf /var/cache/apt/archives/ && mkdir /src && \
    git init
WORKDIR /src

# Link asm/byteorder.h into eBPF
RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

# Build libbpf as a static lib
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git && \
    cd libbpf-bootstrap && \
    git submodule update --init --recursive

RUN cd libbpf-bootstrap/libbpf/src && \
    make BUILD_STATIC_ONLY=y && \
    make install BUILD_STATIC_ONLY=y LIBDIR=/usr/lib/x86_64-linux-gnu/

# Clones the linux kernel repo and use the latest linux kernel source BPF headers and checkout target linux version
RUN git clone -b v5.10 --depth 1 git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git && \
    cp linux/include/uapi/linux/bpf* /usr/include/linux/

ENV PATH  /opt/go/bin:$PATH