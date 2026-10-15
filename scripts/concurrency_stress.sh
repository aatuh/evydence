#!/usr/bin/env sh
# Repeat the supported single-writer/worker contention invariants under race.
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
exec python3 scripts/concurrency_stress.py
