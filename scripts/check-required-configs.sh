#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Usage: check-required-configs.sh <path-to-.config>
# Prints one line per required config option as:
#   CONFIG_NAME<TAB>STATUS
# where STATUS is ✅ when the option is enabled (=y or =m), and ❌ otherwise.

set -euo pipefail

usage() {
	cat >&2 <<'EOF'
Usage: check-required-configs.sh <path-to-.config>

Report required kernel config options as:
  CONFIG_NAME<TAB>STATUS

An option is considered enabled when it is set to y or m.
EOF
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
CONFIG_TOOL="${SCRIPT_DIR}/config"
readonly CONFIG_TOOL
readonly REQUIRED_CONFIGS=(
	EXT4_FS
	VFAT_FS
	ISO9660_FS
	XFS_FS
	SQUASHFS
	BTRFS_FS
	BLK_DEV_DM
	DM_VERITY
	DM_MULTIPATH
	HUGETLBFS
	IO_URING
	SCSI_ISCSI_ATTRS
	ISCSI_TCP
	CIFS_UPCALL
	FTRACE
	KPROBES
	FTRACE_SYSCALLS
	BPF_JIT
)

if (($# == 1)) && [[ "$1" == "-h" || "$1" == "--help" ]]; then
	usage
	exit 0
fi

if (($# != 1)); then
	usage
	exit 1
fi

config_file=$1

if [[ ! -f "$config_file" ]]; then
	printf "Error: '%s' does not exist or is not a regular file.\n" "$config_file" >&2
	exit 1
fi

if [[ ! -r "$config_file" ]]; then
	printf "Error: '%s' is not readable.\n" "$config_file" >&2
	exit 1
fi

if [[ ! -x "$CONFIG_TOOL" ]]; then
	printf "Error: required helper '%s' is not executable.\n" "$CONFIG_TOOL" >&2
	exit 1
fi

for config_name in "${REQUIRED_CONFIGS[@]}"; do
	if ! state="$("${CONFIG_TOOL}" --file "${config_file}" --state "${config_name}")"; then
		printf "Error: failed to read '%s' from '%s'.\n" "${config_name}" \
			"${config_file}" >&2
		exit 1
	fi

	case "${state}" in
	y | m)
		status='✅'
		;;
	*)
		status='❌'
		;;
	esac

	printf '%s\t%s\n' "${config_name}" "${status}"
done
