#!/bin/sh
set -eu

fail() {
	printf '%s\n' "integration-check: $1" >&2
	exit 2
}

if [ "$#" -ne 0 ]; then
	fail "this command accepts no arguments"
fi
if [ "${ENV:-}" = "production" ]; then
	fail "refusing to run with ENV=production"
fi
if [ -z "${EVYDENCE_TEST_DATABASE_URL:-}" ]; then
	fail "EVYDENCE_TEST_DATABASE_URL is required"
fi
if [ -z "${EVYDENCE_TEST_S3_ENDPOINT:-}" ] || [ -z "${EVYDENCE_TEST_S3_ACCESS_KEY_ID:-}" ] || [ -z "${EVYDENCE_TEST_S3_SECRET_ACCESS_KEY:-}" ]; then
	fail "EVYDENCE_TEST_S3_ENDPOINT, EVYDENCE_TEST_S3_ACCESS_KEY_ID, and EVYDENCE_TEST_S3_SECRET_ACCESS_KEY are required"
fi
if [ -n "${EVYDENCE_DATABASE_URL:-}" ] && [ "$EVYDENCE_TEST_DATABASE_URL" = "$EVYDENCE_DATABASE_URL" ]; then
	fail "test and runtime database URLs must differ"
fi
if [ -n "${EVYDENCE_S3_ENDPOINT:-}" ] && [ "$EVYDENCE_TEST_S3_ENDPOINT" = "$EVYDENCE_S3_ENDPOINT" ]; then
	fail "test and runtime S3 endpoints must differ"
fi
case "$EVYDENCE_TEST_S3_ENDPOINT" in
	localhost:*|127.0.0.1:*) ;;
	*) fail "EVYDENCE_TEST_S3_ENDPOINT must be a loopback MinIO endpoint" ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

workdir=tmp/integration-check
mkdir -p "$workdir"
umask 077
phase=preflight
status=failed
write_summary() {
	printf '{"profile":"disposable-postgresql-minio","phase":"%s","status":"%s","credentials":"redacted"}\n' "$phase" "$status" > "$workdir/integration-summary.json"
}
trap write_summary EXIT

phase=postgres
go test ./internal/adapters/postgres -count=1
phase=minio
go test ./internal/adapters/objectstore/s3 -count=1 -run '^TestMinIOIntegration'
status=passed
