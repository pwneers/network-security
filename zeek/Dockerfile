# Zeek + C++ toolchain for the net-security exercises.
# Based on the official Zeek image (Debian, multi-arch: amd64 + arm64).
FROM zeek/zeek:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        gdb \
        tcpdump \
        tshark \
        less \
        vim-tiny \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/zeek/bin:${PATH}"

WORKDIR /work
CMD ["bash"]
