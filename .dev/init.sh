#!/bin/bash

if [ `id -u` -ne 0 ]; then
    echo "Don't run this outside the VM..."
    exit 1
fi

set -xe
mkdir -p /dev /proc /sys /tmp /sys /mnt
mount -t devtmpfs dev /dev
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t tmpfs tmp /tmp
mkdir -p /dev/pts /dev/shm /dev/hugepages /dev/mqueue
mount -t devpts devpts /dev/pts
mount -t tmpfs shm /dev/shm
mount -t hugetlbfs hugetlbfs /dev/hugepages
mount -t mqueue mqueue /dev/mqueue
mkdir -p /sys/kernel/security /sys/fs/cgroup /sys/fs/bpf /sys/kernel/tracing
mount -t securityfs none /sys/kernel/security
mount -t cgroup2 none /sys/fs/cgroup
mount -t bpf none /sys/fs/bpf
mount -t tracefs none /sys/kernel/tracing
mkdir /tmp/run_
mount -t tmpfs none /tmp/run_
cp -a /run/* /tmp/run_
mount --move /tmp/run_ /run
rmdir /tmp/run_
hostname -F /etc/hostname
. /_termsize.sh
uname -a
ethName=eth0
# dhcpcd -d $ethName
# dhcpcd is too slow
ip link set dev $ethName up
ip addr add 10.0.0.2/24 dev $ethName
ip route add default via 10.0.0.1 dev $ethName
/usr/sbin/sshd &
mount /dev/vda /mnt
wait
/bin/bash || true
umount /mnt
sync
echo o > /proc/sysrq-trigger
sleep infinity
