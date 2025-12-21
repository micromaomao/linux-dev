#!/usr/bin/bash
cd $(dirname $0)

extra_args=()
if [ "$1" == "-t" ]; then
  termsize=(`stty size`)
  termheight=${termsize[0]}
  termwidth=${termsize[1]}
  half_height=$((termheight / 2))
  extra_args+=(
    -ex 'tui enable'
    -ex "tui window height cmd $half_height"
  )
fi

gdb ../vmlinux \
  -ex 'add-auto-load-safe-path ../scripts/gdb/vmlinux-gdb.py' \
  -ex 'target remote kgdb.sock' \
  -ex 'bt' \
  "${extra_args[@]}"
