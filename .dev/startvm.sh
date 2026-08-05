#!/usr/bin/bash

cd $(dirname $0)

memory=4G
cpus=$(nproc)
nopreempt=0
network=1
fs_type=9pfs
no_user_aslr=0
virtio_serial=0
tmux=0
bzImage=0
kgdboc=0

exec_args=""

set -e

function show_help () {
    echo "Usage: startvm.sh [OPTIONS] [--] [exec program]"
    echo "Options:"
    echo "  -m, --memory SIZE    Set the amount of memory for the VM (default: 2G)"
    echo "  -c, --cpus COUNT     Set the number of CPUs for the VM (default: 2)"
    echo "  -n, --no-network     Disable the network interface (default: no)"
    echo "  -t                   Enable tty mode on the serial console and run tmux"
    echo "  -f, --fs TYPE        Which type of root filesystem to use. Available options:"
    echo "                         9pfs (default)"
    echo "                         virtiofs (Requires virtiofsd)"
    echo "                         vhd (Uses .dev/vda.vhd)"
    echo "                           (rm .dev/vda.vhd to repopulate the disk image)"
    echo "      --no-user-aslr   Disable user-space ASLR (default: no)"
    echo "      --virtio-serial"
    echo "                       Use virtio-serial instead of PCI serial (default: no)"
    echo "      --no-preempt     Disable preemption (default: no)"
    echo "      --bzImage        use bzImage instead of vmlinux PVH"
    echo "      --kgdboc         Enable kgdboc (default: no)"
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
        -t )
            tmux=1
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
        --virtio-serial )
            virtio_serial=1
            ;;
        --no-preempt )
            nopreempt=1
            ;;
        --bzImage )
            bzImage=1
            ;;
        -h | --help )
            show_help
            ;;
        --kgdboc )
            kgdboc=1
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

VIRTIOFSD_LOCATION=$(which virtiofsd 2>/dev/null)
if [ $? -ne 0 ] && [[ $fs_type == "virtiofs" ]]; then
    if [ -e "/usr/lib/virtiofsd" ]; then
        VIRTIOFSD_LOCATION="/usr/lib/virtiofsd"
    elif [ -e "/usr/sbin/virtiofsd" ]; then
        VIRTIOFSD_LOCATION="/usr/sbin/virtiofsd"
    else
        echo "virtiofsd not found"
        exit 1
    fi
fi

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

if [[ $virtio_serial == 0 ]]; then
    console_cmd="console=ttyS0,115200"
    if [[ $kgdboc == 1 ]]; then
        console_cmd="$console_cmd kgdboc=ttyS1,115200"
    fi
else
    console_cmd="console=hvc0"
    if [[ $kgdboc == 1 ]]; then
        console_cmd="$console_cmd kgdboc=hvc1"
    fi
fi

if [[ $tmux == 1 ]]; then
    if [[ $exec_args == "" ]]; then
        exec_args="/bin/fish"
    fi
    exec_args="tmux -2 new '$exec_args'"
fi

preempt_cmd=""
if [[ $nopreempt == 1 ]]; then
    preempt_cmd="preempt=none"
fi

kernel=../vmlinux
if [ $bzImage == 1 ]; then
    kernel=../arch/x86/boot/bzImage
fi

qemuFlags=(
    -machine q35,accel=kvm
    -enable-kvm
    -cpu host
    -m $memory
    -smp $cpus

    -kernel $kernel
    -append "\
        $preempt_cmd \
        $root_cmd \
        earlycon $console_cmd \
        nokaslr no_hash_pointers loglevel=8 \
        trace_clock=local \
        init=/init.sh - \
        $exec_args
    "
)

virtiofsd_pids=()

function add_host_dir_fs () {
    local source=$1
    local dest=$2
    local access=$3
    local tag=$4
    local virtiofs_mount_opts=$5
    local v9fs_mount_opts=$6
    local virtiofsd_flags=$7
    local qemu_virtfs_flags=$8

    if [[ $access != "rw" && $access != "ro" ]]; then
        echo "Invalid access mode '$access' for host filesystem '$tag'"
        exit 1
    fi
    if [[ ! $tag =~ ^[A-Za-z][A-Za-z0-9_.-]*$ ]]; then
        echo "Invalid host filesystem tag '$tag'"
        exit 1
    fi

    if [[ $fs_type == "9pfs" || $access == "ro" ]]; then
        local readonly=off
        local mount_opts=trans=virtio
        local virtfs_config="local,path=$source,mount_tag=$tag"
        if [[ $access == "ro" ]]; then
            readonly=on
        fi
        if [[ -n $v9fs_mount_opts ]]; then
            mount_opts+=",$v9fs_mount_opts"
        fi
        virtfs_config+=",readonly=$readonly"
        if [[ -n $qemu_virtfs_flags ]]; then
            virtfs_config+=",$qemu_virtfs_flags"
        fi
        qemuFlags+=(
            -virtfs "$virtfs_config"
        )
        printf 'mount --mkdir -t 9p -o %q %q %q\n' "$mount_opts" "$tag" "$dest" >> "$ROOTFS_DIR/_runtime_init.sh"
        return
    fi

    local chardev_id="${tag}_virtiofs"
    local socket_path
    local -a virtiofs_options
    socket_path=$(mktemp -u "/tmp/${tag}-virtiofs-XXXXXXXXXXX.sock")
    read -r -a virtiofs_options <<< "$virtiofsd_flags"
    sudo "$VIRTIOFSD_LOCATION" --socket-path="$socket_path" --shared-dir="$source" "${virtiofs_options[@]}" &
    virtiofsd_pids+=("$!")
    qemuFlags+=(
        -chardev "socket,id=$chardev_id,path=$socket_path"
        -device "vhost-user-fs-pci,queue-size=1024,chardev=$chardev_id,tag=$tag"
    )
    if [[ -n $virtiofs_mount_opts ]]; then
        printf 'mount --mkdir -t virtiofs -o %q %q %q\n' "$virtiofs_mount_opts" "$tag" "$dest" >> "$ROOTFS_DIR/_runtime_init.sh"
    else
        printf 'mount --mkdir -t virtiofs %q %q\n' "$tag" "$dest" >> "$ROOTFS_DIR/_runtime_init.sh"
    fi
}

add_host_dir_fs "$LINUX_SOURCE_DIR" /linux ro linuxsrc \
    "" "" "--inode-file-handles=prefer" "security_model=passthrough"

if [[ $fs_type == "9pfs" ]]; then
    qemuFlags+=(
        -virtfs "local,path=$ROOTFS_DIR,mount_tag=root,security_model=passthrough,readonly=off"
    )
elif [[ $fs_type == "virtiofs" ]]; then
    virtiofs_socket_path=$(mktemp -u /tmp/virtiosock-XXXXXXXXXXX)
    sudo $VIRTIOFSD_LOCATION --socket-path="$virtiofs_socket_path" --shared-dir="$ROOTFS_DIR" --inode-file-handles=prefer &
    virtiofsd_pids+=("$!")
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

if [[ $virtio_serial == 0 ]]; then
    qemuFlags+=(
        -device "pci-serial,chardev=stdio"
    )
    if [[ $kgdboc == 1 ]]; then
        qemuFlags+=(
            -device "pci-serial,chardev=kgdb"
        )
    fi
else
    qemuFlags+=(
        -device "virtio-serial-pci,id=virtio-serial0"
        -device "virtconsole,chardev=stdio"
    )
    if [[ $kgdboc == 1 ]]; then
        qemuFlags+=(
            -device "virtconsole,chardev=kgdb"
        )
    fi
fi

if [[ $tmux == 1 ]]; then
    qemuFlags+=(
        -chardev "stdio,id=stdio,signal=off"
    )
else
    qemuFlags+=(
        -chardev "stdio,id=stdio,signal=on"
    )
fi

if [[ $kgdboc == 1 ]]; then
    qemuFlags+=(
        -chardev "socket,path=$PWD/kgdb.sock,server=on,wait=off,id=kgdb"
    )
fi

qemuFlags+=(
    -drive "file=$DISK,format=raw,if=virtio"

    -nographic
    -nodefaults
    -pidfile .qemu.pid
    -gdb tcp:127.0.0.1:1234
)

touch "$DISK"
truncate -s 10G "$DISK"
# on some distributions, this is in /usr/sbin even though it technically doesn't require root
export PATH=$PATH:/usr/sbin
if [[ $fs_type == "vhd" ]]; then
    mkfs_opt=(
        -d "$ROOTFS_DIR"
    )
else
    mkfs_opt=()
fi
if ! sudo mkfs.ext4 ${mkfs_opt[@]} -F "$DISK"; then
    echo "Failed to mkfs.ext4 $DISK"
    rm "$DISK"
    exit 1
fi
sudo chown $(id -u):$(id -g) "$DISK"

{
    sleep 1;
    if [[ $kgdboc == 1 ]]; then
        sudo chown $(id -u):$(id -g) $PWD/kgdb.sock
    fi
    sudo chown $(id -u):$(id -g) $PWD/.qemu.pid
} &

function exit_function {
    if [[ ${#virtiofsd_pids[@]} -gt 0 ]]; then
        kill "${virtiofsd_pids[@]}"
    fi
    if [[ $fs_type == "vhd" ]]; then
        mnt_point="$(mktemp -d /tmp/mnt-XXXXXXXXXX)"
        set +ex
        sudo mount "$DISK" "$mnt_point"
        if [ $? -eq 0 ]; then
            echo "Copying modified rootfs back to $ROOTFS_DIR"
            sudo cp -arx "$mnt_point/." "$ROOTFS_DIR"
            sudo umount "$mnt_point"
            sudo rmdir "$mnt_point"
            sudo rm "$DISK"
        else
            echo "Failed to mount $DISK"
        fi
    fi
}

trap exit_function EXIT SIGINT SIGTERM

sudo qemu-system-x86_64 "${qemuFlags[@]}"
