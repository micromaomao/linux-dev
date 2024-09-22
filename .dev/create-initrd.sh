#!/usr/bin/bash

set -xe

cd "$(dirname $0)"
RUNDIR=`pwd`
sudo rm -rf ./initrd
mkdir -p ./initrd
cd ./initrd

mkdir -p bin lib dev proc sys tmp mnt
cd ./bin
cp /usr/bin/busybox ./busybox
set +x
for i in $(busybox --list); do
  if [ -e $i ]; then
    continue
  fi
  ln -s busybox $i
done
set -x
cd ..
cp /lib/ld-*.so* ./lib

mkdir overlay

cat > ./init <<'EOF'
#!/bin/busybox sh
set -xe
mount -t devtmpfs none /dev
mount -t proc none /proc
mount -t sysfs none /sys
mount -t tmpfs none /tmp
mount -t tmpfs none /overlay
mkdir -p /overlay/lower /overlay/upper /overlay/work
mount -t 9p -o trans=virtio,ro roroot /overlay/lower
mount -t overlay none /mnt -olowerdir=/overlay/lower,upperdir=/overlay/upper,workdir=/overlay/work
cd /mnt
mkdir -p dev proc sys tmp
for fs in dev proc sys tmp; do
  mount --move /$fs /mnt/$fs
done
cp /environment environment
echo '#!/bin/sh' > init
echo 'set -xe' >> init
echo 'export $(cat /environment)' >> init
echo 'cd `cat /.cwd`' >> init
echo 'exec bash' >> init
chmod +x init

exec switch_root . /init
EOF
chmod +x ./init

echo "\
TERM=$TERM
PATH=$PATH
SHELL=$SHELL
" > ./environment

sudo chown -R root:root .
sudo chmod u=rwX,go=rX -R .

find . -print0 | cpio --null -o --format=newc | gzip -9 > ../initramfs.cpio.gz

cd "$RUNDIR"
sudo rm -rf ./initrd
