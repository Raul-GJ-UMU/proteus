#!/usr/bin/env sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
data_dir="$project_root/data"

if [ ! -d "$data_dir" ]; then
	printf '%s\n' "Data directory not found: $data_dir" >&2
	exit 1
fi

find "$data_dir" -maxdepth 1 -type f -name 'session_*.json' -delete
