#!/usr/bin/env sh
# Run the deterministic OpenAPI compatibility policy. Keep this wrapper small
# so CI and local callers use the same Python implementation without shell
# interpolation of file or tool paths.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$script_dir/openapi_breaking_check.py" "$@"
