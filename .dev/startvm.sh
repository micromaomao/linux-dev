#!/usr/bin/bash

cd $(dirname $0)

memory=4G
cpus=$(nproc)
network=1
fs_type=9pfs
no_user_aslr=0
no_virtio_serial=0

exec_args=""

set -e

function show_help () {
    echo "Usage: startvm.sh [OPTIONS] [--] [exec program]"
    echo "Options:"
    echo "  -m, --memory SIZE    Set the amount of memory for the VM (default: 2G)"
    echo "  -c, --cpus COUNT     Set the number of CPUs for the VM (default: 2)"
    echo "  -n, --no-network     Disable the network interface (default: no)"
    echo "  -f, --fs TYPE        Which type of root filesystem to use. Available options:"
    echo "                         9pfs (default)"
    echo "                         virtiofs (Requires virtiofsd)"
    echo "                         vhd (Uses .dev/vda.vhd)"
    echo "                           (rm .dev/vda.vhd to repopulate the disk image)"
    echo "      --no-user-aslr   Disable user-space ASLR (default: no)"
    echo "      --no-virtio-serial"
    echo "                       Disable virtio-serial and use PCI serial instead (default: no)"
    echo ""
    exit 1
}

while [ "${1:-}" != '' ]; do
    case $1 in
        -m | --memory ) shift
            memory=$1
            ;;
        -c | --cpus ) shift
            cpus=$1
            ;;
        -n | --no-network )
            network=0
            ;;
        -f | --fs ) shift
            case $1 in
                9pfs )
                    fs_type=9pfs
                    ;;
                virtiofs )
                    fs_type=virtiofs
                    ;;
                vhd )
                    fs_type=vhd
                    ;;
                * )
                    echo "Unknown filesystem type $1"
                    show_help
                    ;;
            esac
            ;;
        --no-user-aslr )
            no_user_aslr=1
            ;;
        --no-virtio-serial )
            no_virtio_serial=1
            ;;
        -h | --help )
            show_help
            ;;
        -- )
            shift
            exec_args="$@"
            break
            ;;
        -* | --* )
            echo "Unknown option $1"
            show_help
            ;;
        *)
            for restarg in "$@"; do
                if [[ $restarg == -* ]]; then
                    echo "Options must come before any positional arguments"
                    show_help
                fi
            done
            exec_args="$@"
            break
            ;;
    esac
    shift
done

set -ex

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

termsize=(`stty size`)
termheight=${termsize[0]}
termwidth=${termsize[1]}
sudo touch "$ROOTFS_DIR/_runtime_init.sh"
sudo chown $(id -u):$(id -g) "$ROOTFS_DIR/_runtime_init.sh"
echo "stty rows $termheight cols $termwidth" > "$ROOTFS_DIR/_runtime_init.sh"

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
    sudo mkdir -p tmp_mnt
    sudo mount -o loop "$DISK" tmp_mnt
    sudo cp -ax "$ROOTFS_DIR/." tmp_mnt
    sudo umount tmp_mnt
    sudo rmdir tmp_mnt
    sudo chown $(id -u):$(id -g) "$DISK"
fi

if [[ $no_user_aslr == 1 ]]; then
    echo 'echo 0 > /proc/sys/kernel/randomize_va_space' >> "$ROOTFS_DIR/_runtime_init.sh"
fi

if [[ $fs_type == "9pfs" ]]; then
    root_cmd="root=root rw rootfstype=9p rootflags=trans=virtio"
elif [[ $fs_type == "virtiofs" ]]; then
    root_cmd="root=rootfs rw rootfstype=virtiofs"
elif [[ $fs_type == "vhd" ]]; then
    root_cmd="root=/dev/vda rw"
fi

if [[ $no_virtio_serial == 0 ]]; then
    console_cmd="console=hvc0 kgdboc=hvc1"
else
    console_cmd="console=ttyS0,115200 kgdboc=ttyS1,115200"
fi

qemuFlags=(
    -machine q35,accel=kvm
    -enable-kvm
    -cpu host
    -m $memory
    -smp $cpus

    -kernel ../vmlinux
    -append "\
        $root_cmd \
        earlycon $console_cmd \
        nokaslr no_hash_pointers loglevel=8 \
        trace_clock=local \
        init=/init.sh - \
        $exec_args
    "
)

if [[ $fs_type == "9pfs" ]]; then
    qemuFlags+=(
        -virtfs "local,path=$ROOTFS_DIR,mount_tag=root,security_model=passthrough,readonly=off"
    )
elif [[ $fs_type == "virtiofs" ]]; then
    virtiofs_socket_path=$(mktemp -u /tmp/virtiosock-XXXXXXXXXXX)
    sudo virtiofsd --socket-path="$virtiofs_socket_path" --shared-dir="$ROOTFS_DIR" --inode-file-handles=prefer &
    virtiofsd_pid=$!
    qemuFlags+=(
        -chardev "socket,id=virtiofs,path=$virtiofs_socket_path"
        -device "vhost-user-fs-pci,queue-size=1024,chardev=virtiofs,tag=rootfs"
        -object "memory-backend-file,id=mem,size=$memory,mem-path=/dev/shm,share=on"
        -numa "node,memdev=mem"
    )
fi

if [[ $network == 1 ]]; then
    qemuFlags+=(
        -netdev "user,id=net0,ipv4=on,net=10.0.0.0/24,host=10.0.0.1,dhcpstart=10.0.0.2,ipv6=off,hostfwd=tcp::2222-:22"
        -device "virtio-net,netdev=net0"
    )
fi

if [[ $no_virtio_serial == 0 ]]; then
    qemuFlags+=(
        -device "virtio-serial-pci,id=virtio-serial0"
        -device "virtconsole,chardev=stdio"
        -device "virtconsole,chardev=kgdb"
    )
else
    qemuFlags+=(
        -device "pci-serial,chardev=stdio"
        -device "pci-serial,chardev=kgdb"
    )
fi

qemuFlags+=(

    -chardev "stdio,id=stdio,signal=off"
    -chardev "socket,path=$PWD/kgdb.sock,server=on,wait=off,id=kgdb"

    -drive "file=$DISK,format=raw,if=virtio"

    -nographic
    -nodefaults
    -pidfile .qemu.pid
    -gdb tcp:127.0.0.1:1234
)

{
    sleep 1;
    sudo chown $(id -u):$(id -g) $PWD/kgdb.sock
    sudo chown $(id -u):$(id -g) $PWD/.qemu.pid
} &

function exit_function {
    if [[ $fs_type == "virtiofs" ]]; then
        kill $virtiofsd_pid
    fi
}

trap exit_function EXIT SIGINT SIGTERM

sudo qemu-system-x86_64 "${qemuFlags[@]}"
