#!/usr/bin/bash

set -ex

cd $(dirname $0)
LINUX_SOURCE_DIR=`realpath ../`
ROOTFS_DIR=`realpath ./rootfs`
if [ ! -e "$ROOTFS_DIR/bin" ]; then
    if [ -e "$ROOTFS_DIR" ]; then
        sudo rm -rf "$ROOTFS_DIR"
    fi
    DOCKER_IMAGE_NAME=rootfsimg
    echo Building rootfs
    docker build --network=host . -t $DOCKER_IMAGE_NAME -f rootfs.Dockerfile

    mkdir -p "$ROOTFS_DIR"
    # isolate this filesystem from our host root, in case "security_model=passthrough" has fs-related exploits.
    sudo mount -t tmpfs tmpfs -o nodev "$ROOTFS_DIR"

    # docker run --rm -v "$ROOTFS_DIR":/rootfs $DOCKER_IMAGE_NAME cp -ax / /rootfs
    # sudo rmdir "$ROOTFS_DIR"/rootfs
    #
    # the above no longer works in latest debian:stable for some reason

    docker run --rm -v "$ROOTFS_DIR":/rootfs $DOCKER_IMAGE_NAME bash -c 'cp -ax $(ls -A / | grep -vE "rootfs|dev|proc|sys|tmp|mnt") /rootfs'
    sudo rm "$ROOTFS_DIR"/.dockerenv
    sudo bash -c "cat /etc/resolv.conf > '$ROOTFS_DIR/etc/resolv.conf'"
fi
DISK=vda.vhd
if [ ! -e "$DISK" ]; then
    touch "$DISK"
    truncate -s 10G "$DISK"
    # on some distributions, this is in /usr/sbin even though it technically doesn't require root
    export PATH=$PATH:/usr/sbin
    if ! mkfs.ext4 -F "$DISK"; then
        echo "Failed to mkfs.ext4 $DISK"
        rm "$DISK"
        exit 1
    fi
fi

termsize=(`stty size`)
termheight=${termsize[0]}
termwidth=${termsize[1]}
sudo sh -c "echo 'stty rows $termheight cols $termwidth' > '$ROOTFS_DIR/_termsize.sh'"
exec_args="${@:1}"

memory=2G
cpus=2

qemuFlags=(
    -machine q35,accel=kvm
    -enable-kvm
    -cpu host
    -m $memory
    -smp $cpus

    -kernel ../vmlinux
    -append "\
        root=root rw rootfstype=9p rootflags=trans=virtio \
        console=ttyS0,115200 kgdboc=ttyS1,115200 \
        nokaslr no_hash_pointers loglevel=7 \
        init=/init.sh - \
        $exec_args
    "

    -virtfs "local,path=$ROOTFS_DIR,mount_tag=root,security_model=passthrough,readonly=off"
)

network=1
if [[ $network == 1 ]]; then
    qemuFlags+=(
        -netdev "user,id=net0,ipv4=on,net=10.0.0.0/24,host=10.0.0.1,dhcpstart=10.0.0.2,ipv6=off,hostfwd=tcp::2222-:22"
        -device "virtio-net,netdev=net0"
    )
fi

qemuFlags+=(
    -chardev "stdio,id=stdio,signal=off"
    -device "pci-serial,chardev=stdio"

    -chardev "socket,path=$PWD/kgdb.sock,server=on,wait=off,id=kgdb"
    -device "pci-serial,chardev=kgdb"

    -drive "file=$DISK,format=raw,if=virtio"

    -nographic
    -nodefaults
    -pidfile .qemu.pid
)

{
    sleep 1;
    sudo chown $(id -u):$(id -g) $PWD/kgdb.sock
    sudo chown $(id -u):$(id -g) $PWD/.qemu.pid
} &

sudo qemu-system-x86_64 "${qemuFlags[@]}"
