echo Too hard to ensure security. Don\'t use.
exit 1

if [ `id -u` -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

set -xe
cd $(dirname $0)

ROROOT_PARENT_DIR=/tmp/roroot
mkdir -p "$ROROOT_PARENT_DIR"
chmod go-rwx "$ROROOT_PARENT_DIR"
ROROOT_DIR="$ROROOT_PARENT_DIR/roroot"
mkdir -p "$ROROOT_DIR"
echo "Using $ROROOT_DIR as read-only root directory"
mount -t tmpfs tmpfs "$ROROOT_DIR"
mount --make-private "$ROROOT_DIR"

pushd "$ROROOT_DIR"
LINUX_SOURCE_DIR=`realpath ../`
mkdir -p "$ROROOT_DIR$LINUX_SOURCE_DIR"
chmod go+rX -R "$ROROOT_DIR"
for dir in etc bin sbin lib lib64 usr opt srv; do
    if [ ! -e "/$dir" ]; then
        continue
    fi
    if [ -L "/$dir" ]; then
        target=`readlink "/$dir"`
        target=`echo "$target" | sed 's/^\/?//'`
        ln -s "$target" "$dir"
        continue
    fi
    mkdir -p "$ROROOT_DIR/$dir"
    mount --bind -o ro "/$dir" "$ROROOT_DIR/$dir"
done
mount --bind -o ro "$LINUX_SOURCE_DIR" "$ROROOT_DIR$LINUX_SOURCE_DIR"
echo "$LINUX_SOURCE_DIR" | tee "$ROROOT_DIR/.cwd"
popd

# ...

umount -R "$ROROOT_DIR"
rmdir "$ROROOT_DIR"
rmdir "$ROROOT_PARENT_DIR"
