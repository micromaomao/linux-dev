#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright © 2024 Huawei Tech. Co., Ltd.
#
# Measure overhead of Landlock hooks for the specified workload.

# cf. tools/testing/selftests/kselftest.h
KSFT_PASS=0
KSFT_FAIL=1
KSFT_XFAIL=2
KSFT_XPASS=3
KSFT_SKIP=4

REL_DIR=$(dirname $(realpath $0))
PERF_BIN=/usr/bin/perf
SANDBOXER_BIN=$REL_DIR/sandboxer
MICROBENCH_BIN=$REL_DIR/microbench
CUSTOM_TRACER_BIN=$REL_DIR/tracer
TASKSET=/usr/bin/taskset
NICE=/usr/bin/nice

LL_TRACE_DUMP=.tmp.ll
BASE_TRACE_DUMP=.tmp.base
TMP_BUF=.tmp.buf
TMP_BUF2=.tmp.buf2
OUTPUT=

SANDBOXER_ARGS=
ACCESS=
TRACED_SYSCALLS=
MICROBENCH=false
WORKLOAD=
SILENCE=false
TRACE_CMD=

CPU_AFFINITY=0
SANDBOX_DELAY=300 # msecs
REPEAT=5
MICROBENCH_INITIAL_ITERATIONS=10000000
STDDEV_STABLE=0.1 # %

err()
{
	echo $@ >&2
	exit $KSFT_SKIP
}

help()
{
	echo "Usage: $0 [OPTIONS] [WORKLOAD_CMD]"
	echo "   or: $0 [OPTIONS] -m"
	echo "Measure overhead of Landlock hooks for the specified workload."
	echo
	echo "Options:"
	echo "  -e TRACED_SYSCALLS  specify syscalls which would be traced while benchmarking"
	echo "  -m                  run microbenchmark workload for TRACED_SYSCALLS"
	echo "  -p PERF_BINARY      use PERF_BINARY instead of /usr/bin/perf"
	echo "  -D MSECS            wait MSECS msecs before tracing sandboxed workload"
	echo "                      (default: $SANDBOX_DELAY)"
	echo "  -r COUNT            repeat WORKLOAD_CMD for COUNT times, show avg and stddev"
	echo "                      (default: $REPEAT)"
	echo "  -o FILE             save result into FILE"
	echo "  -c CPU              use CPU affinity (default: $CPU_AFFINITY)"
	echo "  -s                  hide stdout output for WORKLOAD_CMD"
	echo "  -h                  show this help message"
	echo
	echo "  -t {fs|net}:FILE:ACCESS"
	echo "                      add Landlock topology which describes how workload"
	echo "                      should be sandboxed by Landlock."
	echo "                      * FILE contains lines of following format: \"NR KEY\\n\""
	echo "                        (e.g. \"1 /usr/bin/find\n\").  When sandboxing, a rule"
	echo "                        on the NR layer with ACCESS access_mask will be added"
	echo "                        for each key KEY"
	echo "                      * ACCESS has binary string format. Sets ruleset"
	echo "                        handled_access and access_mask for each key."
	echo

	exit $KSFT_XFAIL
}

add_sandboxer_args()
{
	ACCESS=$(echo $1 | cut -d':' -f3)

	rule_type=$(echo $1 | cut -d':' -f1)
	args=$(echo $1 | cut -d':' -f2,3)
	SANDBOXER_ARGS+=$(echo ' '--$rule_type $args)
}

parse_and_check_arguments()
{
	while getopts smbp:e:r:o:t:D:c:h arg
	do
		case $arg in
			e) TRACED_SYSCALLS=$OPTARG ;;
			m) MICROBENCH=true ;;
			t) add_sandboxer_args $OPTARG ;;
			p) PERF_BIN=`realpath $OPTARG` ;;
			D) SANDBOX_DELAY=$OPTARG ;;
			r) REPEAT=$OPTARG ;;
			o) OUTPUT=$OPTARG ;;
			c) CPU_AFFINITY=$OPTARG ;;
			s) SILENCE=true ;;
			h) help ;;
		esac
	done

	shift $(($OPTIND - 1))
	WORKLOAD=$@

	if [ ! -f $SANDBOXER_BIN ]; then
		err Sandboxer binary does not exist
	fi

	# At least one must be present.
	if [ -z "$WORKLOAD" ] && ! $MICROBENCH ; then
		err Specify workload cmd or -m flag
	fi

	if [ $MICROBENCH ] && [ ! -f $SANDBOXER_BIN ]; then
		err Binary of microbenchmarking script does not exist
	fi

	if [ -z "$TRACED_SYSCALLS" ]; then
		err Specify traced syscalls
	fi

	if [ ! -z "$WORKLOAD" ] && [ ! -f $PERF_BIN ]; then
		err Perf binary does not exist
	fi
	if [ ! -z "$WORKLOAD" ] && [ -z "$SANDBOXER_ARGS" ]; then
		err Landlock topology is not specified
	fi
}

# perf trace
header='/^[[:space:]]*$/d;'
header+=';/^.* ([0-9]*), [0-9]* events, .*%$/d;'
header+=';/^   syscall            calls  errors  total       min       avg       max       stddev$/d'
header+=';/^                                     (msec)    (msec)    (msec)    (msec)        (%)$/d'
header+=';/^   --------------- --------  ------ -------- --------- --------- ---------     ------$/d'
header+=';/^ Summary of events:$/d'

rm_headers()
{
	sed -i "$header" $1
}

print()
{
	fmt=$1
	shift 1
	if [ ! -z "$OUTPUT" ]; then
		printf "$fmt" $@ >> $OUTPUT
	else
		printf "$fmt" $@
	fi
}

dump_avg_durations_epoch()
{
	awk '{
		calls[$1]+=$2
		durations[$1]+=$4
	}
	END {
		for(i in calls) {
			if (calls[i] != 0 && durations[i] != 0) {
				print i, durations[i] / calls[i] * 1000, calls[i]
			}
		}
	}' $1
}

dump_avg_durations()
{
	awk '{
		count[$1]+=1
		dur[$1, count[$1]]+=$2
		calls[$1]+=$3
	}
	END {
		for(sys in calls) {
			if (calls[sys] == 0 || count[sys] == 0)
				continue
			min = 1000000000
			max = 0
			total = 0
			for (i = 1; i <= count[sys]; i++) {
				min = (min < dur[sys, i]) ? min : dur[sys, i]
				max = (max > dur[sys, i]) ? max : dur[sys, i]
				total += dur[sys, i]
			}
			stddev = 0
			avg = total / count[sys]
			for (i = 1; i <= count[sys]; i++) {
				stddev += (dur[sys, i] - avg) * (dur[sys, i] - avg)
			}
			if (total && count[sys] > 1 && avg)
				stddev = sqrt(stddev / (count[sys] - 1)) / avg * 100

			printf("%-20s %8d %7.2Lf %7.2Lf %7.2Lf %5.2Lf%%\n",
				sys, calls[sys], avg, min, max, stddev);
		}
	}' $1
}

print_overhead()
{
	dump_avg_durations $BASE_TRACE_DUMP > $TMP_BUF && mv $TMP_BUF $BASE_TRACE_DUMP
	dump_avg_durations $LL_TRACE_DUMP > $TMP_BUF && mv $TMP_BUF $LL_TRACE_DUMP

	print "overhead:\n"
	print "    %-20s %10s %10s %23s\n" "syscall" "bcalls" "scalls" "duration+overhead(us)"
	print "    %-20s %10s %10s %23s\n" "=======" "======" "======" "====================="

	while read -r base_line
	do
		base_line=$(echo "$base_line" | sed 's/ \+ / /g')
		sys_name=$(echo "$base_line" | cut -d " " -f 1)
		ll_line=$(cat $LL_TRACE_DUMP | grep -w $sys_name | sed 's/ \+ / /g')

		base_duration=$(echo "$base_line" | cut -d " " -f 3)
		base_calls=$(echo "$base_line" | cut -d " " -f 2)

		ll_duration=$(echo "$ll_line" | cut -d " " -f 3)
		ll_calls=$(echo "$ll_line" | cut -d " " -f 2)

		overhead=$(bc -l <<< "scale=2; $ll_duration/$base_duration*100 - 100")
		overhead_us=$(bc -l <<< "scale=2; $ll_duration - $base_duration")

		if (( $(bc -l <<< "$overhead < 0") )); then
			overhead_str=$(printf "%.2Lf%.2Lf(%.1Lf%%)" \
									$base_duration $overhead_us $overhead)
		else
			overhead_str=$(printf "%.2Lf+%.2Lf(+%.1Lf%%)" \
									$base_duration $overhead_us $overhead)
		fi

		print "    %-20s %10d %10d %23s\n" $sys_name $base_calls $ll_calls $overhead_str
	done < $BASE_TRACE_DUMP
}

print_overhead_workload()
{
	print "\nTracing results\n"
	print "===============\n"
	print "cmd: "
	print "%s " $WORKLOAD
	print "\n"
	print "syscalls: %s\n" $TRACED_SYSCALLS
	print "access: %s\n" $ACCESS

	print_overhead
}

print_overhead_microbench()
{
	print "\nTracing results\n"
	print "===============\n"
	print "cmd: Microbenchmarks\n"
	print "syscalls: %s\n" $TRACED_SYSCALLS

	print_overhead
}

form_trace_cmd()
{
	trace_cmd=$TRACE_CMD
	trace_cmd+=" -e $1 -D $SANDBOX_DELAY -o $TMP_BUF"
	trace_cmd+=" $TASKSET -c $CPU_AFFINITY"
	trace_cmd+=" $NICE -n -19"

	echo $trace_cmd
}

run_traced_workload()
{
	trace_cmd=$(form_trace_cmd $TRACED_SYSCALLS)

	if [ $1 == 0 ]; then
		output=$BASE_TRACE_DUMP
	else
		output=$LL_TRACE_DUMP
		trace_cmd+="$SANDBOXER_BIN $SANDBOXER_ARGS"
	fi

	echo '' > $output

	start=$(date +%s%3N)

	for i in $(seq 1 $REPEAT);
	do
		if $SILENCE; then
			$trace_cmd $WORKLOAD > /dev/null
		else
			$trace_cmd $WORKLOAD
		fi

		res=$?
		if [ $res != 0 ]; then
			exit $KSFT_FAIL
		fi

		rm_headers $TMP_BUF
		output_avg="$(dump_avg_durations_epoch $TMP_BUF)"
		echo "$output_avg" >> $output
	done

	end=$(date +%s%3N)

	duration=$((end - start))
	sec=$((duration / 1000))
	msec=$((duration % 1000))

	echo "${sec}.${msec}s elapsed"
}

run_traced_microbench()
{
	if [ $1 == 0 ]; then
		output=$BASE_TRACE_DUMP
		sandbox_opt=
	else
		output=$LL_TRACE_DUMP
		sandbox_opt=-s
	fi

	echo '' > $output

	syscalls_to_parse=$(echo $TRACED_SYSCALLS | sed 's/,/\n/g')

	for syscall in $syscalls_to_parse; do
		n_iters=$MICROBENCH_INITIAL_ITERATIONS
		trace_cmd=$(form_trace_cmd $syscall)

		while
			$trace_cmd $MICROBENCH_BIN -e $syscall -n $n_iters $sandbox_opt
			res=$?
			if [ $res != 0 ]; then
				exit $KSFT_FAIL
			fi

			rm_headers $TMP_BUF
			output_avg="$(dump_avg_durations_epoch $TMP_BUF)"
			echo "$output_avg" > $TMP_BUF2

			stddev=$(cat $TMP_BUF | sed 's/ \+ / /g' | cut -d " " -f $stddev_col)
			stddev=${stddev::-1}

			echo syscall: $syscall, stddev: $stddev%, iterations: $n_iters

			n_iters=$(bc -l <<< "$n_iters*2")
		[ $(bc -l <<< "$stddev < $STDDEV_STABLE") == 0 ]
		do true; done
		cat $TMP_BUF2 >> $output
	done
}

trap "exit $KSFT_SKIP" INT

parse_and_check_arguments $@

if [ ! -z "$OUTPUT" ]; then
	echo '' > $OUTPUT
fi

if $CUSTOM_TRACER; then
	TRACE_CMD=$CUSTOM_TRACER_BIN
else
	TRACE_CMD="$PERF_BIN trace -s"
fi

if [ ! -z "$WORKLOAD" ]; then
	echo "Tracing baseline workload..."
	run_traced_workload 0

	echo "Tracing sandboxed workload..."
	run_traced_workload 1

	print_overhead_workload
fi

if $MICROBENCH; then
	echo "Tracing baseline microbenchmarks..."
	run_traced_microbench 0

	echo "Tracing sandboxed microbenchmarks..."
	run_traced_microbench 1

	print_overhead_microbench
fi
