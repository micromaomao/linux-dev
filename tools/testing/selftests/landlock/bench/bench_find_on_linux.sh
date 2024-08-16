#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright © 2024 Huawei Tech. Co., Ltd.
#
# Measure openat(2) overhead for workload that executes find tool on Linux source
# code with different depths and numbers of ruleset layers.

# cf. tools/testing/selftests/kselftest.h
KSFT_PASS=0
KSFT_FAIL=1
KSFT_XFAIL=2
KSFT_XPASS=3
KSFT_SKIP=4

REL_DIR=$(dirname $(realpath $0))
FIND=/usr/bin/find
LINUX_SRC=$(realpath $REL_DIR/../../../../../)
BENCH_CMD=$REL_DIR/run.sh
TOPOLOGY=.topology
TMP=.tmp

# read
READ_ACCESS=4

# $1 - Linux src files path
# $2 - Maximum depth of files
# $3 - If $3 == 0 then only files of depth $2 is used in ruleset.
#      Otherwise, ruleset uses files of depth 1-$2 and ruleset layer
#      of each file matches depth of the file.
# $4 - Name of the file in which topology would be saved
gen_linux_src_topology()
{
	n_layers=$2
	if [[ $3 -eq 0 ]]; then
		n_layers=1
		find $1 -mindepth $2 -maxdepth $2 -fprintf $4 '1 %p\n'
	else
		find $1 -mindepth 1 -maxdepth $2 -fprintf $4 '%d %p\n'
	fi

	# Allow access to FIND
	for depth in $(seq 1 $n_layers);
	do
		echo $depth /usr/bin/find >> $4
		echo $depth /usr/bin/file >> $4
		echo $depth /lib >> $4
		echo $depth /etc >> $4
	done
}

if [ ! -f "$BENCH_CMD" ]; then
	echo $BENCH_CMD does not exist
	exit $KSFT_SKIP
fi

if [ ! -f "$FIND" ]; then
	echo $FIND does not exist
	exit $KSFT_SKIP
fi

# $1 - depth
# $2 - If $2 == 0 then only files of depth $2 is used in ruleset.
#      Otherwise, ruleset uses files of depth 1-$2 and ruleset layer
#      of each file matches depth of the file.
# $3 - Number of iterations of this sample
run_sample()
{
	n_layers=$1
	if [[ $2 -eq 0 ]]; then
		n_layers=1
	fi

	echo Running find on $n_layers layers, $1 depth, $3 iterations...
	gen_linux_src_topology $LINUX_SRC $1 $2 $TOPOLOGY

	$BENCH_CMD -s -r $3 -b -t fs:$TOPOLOGY:$READ_ACCESS -e openat \
		$FIND $LINUX_SRC -mindepth $1 -maxdepth $1 -exec file '{}' \;
}

run_sample 5 0 10
run_sample 5 1 10
run_sample 10 0 500
run_sample 10 1 500
