#!/usr/bin/bash
cd $(dirname $0)

set -e
if [ -e ".qemu.pid" ]; then
    pid=`sudo cat .qemu.pid`
    proc_name=`ps -p $pid -o comm=`
    echo Killing $proc_name[$pid]
    sudo kill $pid
    rm -f .qemu.pid
fi
