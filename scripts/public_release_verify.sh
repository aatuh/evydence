#!/usr/bin/env bash
set -euo pipefail

repo="${EVYDENCE_RELEASE_REPO:-aatuh/evydence}"
tag="${1:-${TAG:-v0.1.0-rc.7}}"

if [[ ! "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "EVYDENCE_RELEASE_REPO must look like owner/name" >&2
  exit 2
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$ ]]; then
  echo "release candidate tag must look like v0.1.0-rc.7" >&2
  exit 2
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required to download public release assets" >&2
  exit 2
fi

workdir="$(mktemp -d "${TMPDIR:-/tmp}/evydence-release-verify.XXXXXX")"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

echo "Downloading ${repo} ${tag} into ${workdir}"
gh release download "$tag" --repo "$repo" --dir "$workdir"

commit="$(gh api "repos/${repo}/commits/${tag}" --jq .sha)"
if [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "could not resolve ${repo} ${tag} to a commit" >&2
  exit 2
fi

required=(
  "SHA256SUMS"
  "openapi.yaml"
  "openapi.sha256"
  "evydence-release-sbom.cdx.json"
  "evydence-release-provenance.json"
  "evydence-release-provenance.intoto.jsonl"
  "migrations.sha256"
  "coverage.out"
  "release-check-summary.txt"
  "release-notes.md"
  "evydence-release-manifest.json"
  "evydence-release-manifest.sig.json"
  "evydence-release-manifest.sig"
  "evydence_${tag}_linux_amd64.tar.gz"
  "evydence_${tag}_linux_arm64.tar.gz"
  "evydence_${tag}_darwin_amd64.tar.gz"
  "evydence_${tag}_darwin_arm64.tar.gz"
  "evydence_${tag}_windows_amd64.zip"
)
for asset in "${required[@]}"; do
  if [[ ! -f "$workdir/$asset" ]]; then
    echo "required public release asset missing: $asset" >&2
    exit 2
  fi
done

(cd "$workdir" && sha256sum -c SHA256SUMS)
(cd "$workdir" && sha256sum -c openapi.sha256)
sha256sum -c "$workdir/migrations.sha256"

archive="$workdir/evydence_${tag}_linux_amd64.tar.gz"
if [[ ! -f "$archive" ]]; then
  echo "linux amd64 release archive missing: ${archive}" >&2
  exit 2
fi
tar -C "$workdir" -xzf "$archive"
cli="$workdir/evydence_${tag}_linux_amd64/evydence"
"$cli" release verify \
  --manifest "$workdir/evydence-release-manifest.json" \
  --signature "$workdir/evydence-release-manifest.sig.json"

if [[ -f "$workdir/evydence-release-manifest.sig" ]]; then
  cmp -s "$workdir/evydence-release-manifest.sig.json" "$workdir/evydence-release-manifest.sig"
fi
python3 - "$workdir" "$tag" "$commit" <<'PY'
import json
import sys
from pathlib import Path

workdir = Path(sys.argv[1])
tag = sys.argv[2]
commit = sys.argv[3]

manifest = json.loads((workdir / "evydence-release-manifest.json").read_text(encoding="utf-8"))
if manifest.get("schema_version") != "evydence-release-artifacts.v1.0.0":
    raise SystemExit("release manifest schema is unsupported")
manifest_artifacts = manifest.get("artifacts")
if not isinstance(manifest_artifacts, list) or not manifest_artifacts:
    raise SystemExit("release manifest has no artifacts")
manifest_names = {item.get("path") for item in manifest_artifacts if isinstance(item, dict)}
if len(manifest_names) != len(manifest_artifacts) or not all(isinstance(name, str) and "/" not in name and name for name in manifest_names):
    raise SystemExit("release manifest artifact identities are ambiguous")

checksums = set()
for line in (workdir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    parts = line.split(maxsplit=1)
    if len(parts) != 2 or len(parts[0]) != 64 or any(ch not in "0123456789abcdef" for ch in parts[0].lower()):
        raise SystemExit("SHA256SUMS has an invalid entry")
    checksums.add(parts[1].lstrip(" *"))
if not checksums <= manifest_names:
    raise SystemExit("release manifest does not bind every checksum-listed asset")

provenance = json.loads((workdir / "evydence-release-provenance.json").read_text(encoding="utf-8"))
subject = provenance.get("subject")
if not isinstance(subject, dict) or subject.get("name") != "evydence" or subject.get("version") != tag or subject.get("commit") != commit:
    raise SystemExit("release provenance subject does not match the expected tag and commit")
materials = provenance.get("materials")
if not isinstance(materials, list) or not materials:
    raise SystemExit("release provenance materials are missing")
material_digests = {item.get("path"): item.get("sha256") for item in materials if isinstance(item, dict)}
if len(material_digests) != len(materials) or not set(material_digests) <= manifest_names:
    raise SystemExit("release provenance materials are ambiguous or are not bound by the manifest")

line = (workdir / "evydence-release-provenance.intoto.jsonl").read_text(encoding="utf-8").strip()
if "\n" in line:
    raise SystemExit("release provenance must contain exactly one in-toto statement")
statement = json.loads(line)
if statement.get("_type") != "https://in-toto.io/Statement/v0.1":
    raise SystemExit("release provenance is not an in-toto statement")
predicate = statement.get("predicate")
if not isinstance(predicate, dict) or predicate.get("subject") != subject:
    raise SystemExit("in-toto provenance subject does not match release provenance")
intoto_subjects = statement.get("subject")
if not isinstance(intoto_subjects, list) or {item.get("name"): item.get("digest", {}).get("sha256") for item in intoto_subjects if isinstance(item, dict)} != material_digests:
    raise SystemExit("in-toto provenance subjects do not match release provenance materials")
if "not a SLSA level claim" not in json.dumps(statement, sort_keys=True):
    raise SystemExit("release provenance limitations are missing")
PY

echo "public release verified: ${repo} ${tag}"
