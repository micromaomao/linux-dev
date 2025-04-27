#!/usr/bin/bash

set -ex

cd "$(dirname "$0")/../../../../.." # linux source

ro_basic="/usr:/bin:/lib"
rw_basic="/dev/null:/dev/zero:/proc/self"

ro_files_l0="$ro_basic:/etc:/dev:/proc:/var:/opt"
rw_files_l0="$rw_basic:$HOME:$XDG_RUNTIME_DIR:/tmp"

my_shell_config="$HOME/.config/fish"

ro_files_l1="$ro_basic:$my_shell_config:/etc:$HOME/.gitconfig:$PWD"
ro_files_l1+=":$HOME/linux" # git worktree
rw_files_l1="$rw_basic"

sandboxer="samples/landlock/sandboxer"

taskset -c 8,9,10,11 \
    env LL_FS_RO="$ro_files_l0" LL_FS_RW="$rw_files_l0" \
    $sandboxer \
    env LL_FS_RO="$ro_files_l1" LL_FS_RW="$rw_files_l1" \
    $sandboxer \
    /bin/bash -c '
        echo Hello from sandbox!
        function workloads () {
            echo "Finding all files:"
            time nb_files=$(find . -type f | wc -l)
            echo "This directory currently has $nb_files files."
            echo "Git workload:"
            echo "git status:"
            time git status
            echo "number of modified files:"
            time git diff --numstat --no-renames | wc -l
            echo "number of untracked files:"
            time git ls-files -o --exclude-standard | wc -l
        }
        workloads
        echo "Will continue to run the above for 30 seconds."
        while :; do workloads; done > /dev/null 2>&1 &
        pid=$!
        sleep 30
        kill $pid
        wait
    '
