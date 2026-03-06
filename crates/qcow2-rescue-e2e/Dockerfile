FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-utils \
    e2fsprogs \
    btrfs-progs \
    ntfs-3g \
    dosfstools \
    gdisk \
    fdisk \
    util-linux \
    mount \
    kmod \
    xfsprogs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

COPY bin/qcow2-rescue-e2e /usr/local/bin/qcow2-rescue-e2e
RUN chmod +x /usr/local/bin/qcow2-rescue-e2e

ENTRYPOINT ["qcow2-rescue-e2e", "generate", "/work/output"]
