#!/usr/bin/bash
cd $(dirname $0)

extra_args=()

target_cmd='target remote kgdb.sock'

function show_help () {
    echo "Usage: kgdb.sh [OPTIONS]"
    echo "Options:"
    echo "  -t: Enable TUI mode"
    echo "  -s: Connect to QEMU GDB server instead of KGDB"
    echo ""
    exit 1
}

while [ "${1:-}" != '' ]; do
    case $1 in
        -t)
            termsize=(`stty size`)
            termheight=${termsize[0]}
            termwidth=${termsize[1]}
            half_height=$((termheight / 2))
            extra_args+=(
                # don't enable tui if we failed to connect
                -ex "python gdb.selected_inferior() and gdb.selected_inferior().connection and gdb.selected_inferior().connection.is_valid() and (gdb.execute('tui enable'), gdb.execute('tui window height cmd $half_height'))"
            )
            ;;
        -s)
            target_cmd='target remote localhost:1234'
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown argument: $1"
            show_help
            ;;
    esac
    shift
done

gdb \
  -ex "add-auto-load-safe-path ../scripts/gdb/vmlinux-gdb.py" \
  -ex "file ../vmlinux" \
  -ex "source ./gdb.py" \
  -ex "$target_cmd" \
  -ex 'bt' \
  "${extra_args[@]}"
