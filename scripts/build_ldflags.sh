#!/usr/bin/env sh
set -eu

value_or() {
  value="$1"
  fallback="$2"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return
  fi
  printf '%s' "$fallback"
}

git_value() {
  git "$@" 2>/dev/null || printf '%s' "unknown"
}

version="$(value_or "${EVYDENCE_BUILD_VERSION:-}" "dev")"
commit="$(value_or "${EVYDENCE_BUILD_COMMIT:-}" "$(git_value rev-parse --verify HEAD)")"
build_time="$(value_or "${EVYDENCE_BUILD_TIME:-}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
go_version="$(value_or "${EVYDENCE_BUILD_GO_VERSION:-}" "$(go env GOVERSION 2>/dev/null || printf '%s' unknown)")"
release_manifest_digest="$(value_or "${EVYDENCE_BUILD_RELEASE_MANIFEST_DIGEST:-}" "unknown")"

if [ -n "${EVYDENCE_BUILD_DIRTY+x}" ]; then
  dirty="$EVYDENCE_BUILD_DIRTY"
elif git status --porcelain --untracked-files=all 2>/dev/null | grep -q .; then
  dirty="true"
else
  dirty="false"
fi

case "$dirty" in
  true|false) ;;
  *) printf '%s\n' "build_ldflags: EVYDENCE_BUILD_DIRTY must be true or false" >&2; exit 2 ;;
esac

for value in "$version" "$commit" "$build_time" "$go_version" "$release_manifest_digest"; do
  case "$value" in
    ''|*[!A-Za-z0-9._:+/@=-]*)
      printf '%s\n' "build_ldflags: build metadata must not contain whitespace or shell metacharacters" >&2
      exit 2
      ;;
  esac
done

prefix="github.com/aatuh/evydence/internal/runtimeinfo"
printf '%s' "-X ${prefix}.Version=${version} -X ${prefix}.Commit=${commit} -X ${prefix}.BuildTime=${build_time} -X ${prefix}.Dirty=${dirty} -X ${prefix}.GoVersion=${go_version} -X ${prefix}.ReleaseManifestDigest=${release_manifest_digest}"
