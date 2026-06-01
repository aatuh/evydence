#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

fail() {
  printf '%s\n' "reviewer-package-workflow-check: $*" >&2
  exit 1
}

workdir="${EVYDENCE_REVIEWER_WORKFLOW_DIR:-tmp/reviewer-package-workflow}"
case "$workdir" in
  tmp/*) ;;
  *) fail "EVYDENCE_REVIEWER_WORKFLOW_DIR must stay under tmp/" ;;
esac

manifest="examples/end-to-end-release-evidence/sample-customer-package-manifest.json"
manifest_sum="examples/end-to-end-release-evidence/sample-customer-package-manifest.sha256"
archive="examples/end-to-end-release-evidence/sample-customer-package.zip"

for path in "$manifest" "$manifest_sum" "$archive" "docs/how-to/review-customer-package.md"; do
  [[ -f "$path" ]] || fail "missing $path"
done

rm -rf -- "$workdir"
mkdir -p -- "$workdir"

(
  cd "$(dirname "$manifest")"
  sha256sum -c "$(basename "$manifest_sum")" >/dev/null
)

go run ./cmd/evydence package verify \
  --manifest "$manifest" \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example \
  >"$workdir/manifest-verify.txt"

go run ./cmd/evydence package verify \
  --archive "$archive" \
  --expected-package-id csp_example \
  --expected-product-id prod_example \
  --expected-release-id rel_example \
  >"$workdir/archive-verify.txt"

python3 - "$manifest" "$archive" "$workdir" <<'PY'
import json
import pathlib
import sys
import zipfile

manifest_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
workdir = pathlib.Path(sys.argv[3])
extract_dir = workdir / "extracted"
extract_dir.mkdir(parents=True, exist_ok=True)

manifest = json.loads(manifest_path.read_text())
required_manifest = [
    "reviewer_checklist",
    "readiness_summary",
    "verification_material",
    "limitations",
    "non_claims",
    "vulnerability_decisions",
]
missing = [key for key in required_manifest if key not in manifest]
if missing:
    raise SystemExit(f"manifest missing reviewer sections: {', '.join(missing)}")

checklist_ids = set()
for item in manifest["reviewer_checklist"]:
    if not isinstance(item, dict):
        raise SystemExit("reviewer_checklist entries must be objects")
    checklist_ids.add(item.get("id", ""))
for key in ("package_scope", "included_evidence", "excluded_evidence", "hash_signature_verification", "non_claims", "escalation_path"):
    if key not in checklist_ids:
        raise SystemExit(f"reviewer_checklist missing {key}")

for forbidden in ("payload_ref", "object_key", "private_key", "token_hash", "internal note", "raw scanner payload"):
    if forbidden in json.dumps(manifest, sort_keys=True).lower():
        raise SystemExit(f"manifest leaked forbidden marker {forbidden}")

with zipfile.ZipFile(archive_path) as zf:
    names = set(zf.namelist())
    required_archive = {"manifest.json", "package.json", "verification.json", "report.html"}
    missing_archive = sorted(required_archive - names)
    if missing_archive:
        raise SystemExit(f"archive missing {', '.join(missing_archive)}")
    for info in zf.infolist():
        target = extract_dir / info.filename
        resolved = target.resolve()
        if not str(resolved).startswith(str(extract_dir.resolve()) + "/") and resolved != extract_dir.resolve():
            raise SystemExit(f"archive path escapes extraction root: {info.filename}")
        if info.file_size > 2 * 1024 * 1024:
            raise SystemExit(f"archive entry too large for reviewer fixture: {info.filename}")
        if info.is_dir():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zf.read(info.filename))

report = (extract_dir / "report.html").read_text()
report_lower = report.lower()
for expected in ("limitations", "non-claims", "verification", "vulnerability"):
    if expected not in report_lower:
        raise SystemExit(f"report.html missing {expected}")
for forbidden in ("payload_ref", "object_key", "private_key", "token_hash", "internal note", "<script"):
    if forbidden in report_lower:
        raise SystemExit(f"report.html leaked forbidden marker {forbidden}")

verification = json.loads((extract_dir / "verification.json").read_text())
package_metadata = json.loads((extract_dir / "package.json").read_text())
if verification.get("manifest_hash") != package_metadata.get("manifest_hash"):
    raise SystemExit("verification manifest_hash does not match package metadata")

(workdir / "summary.txt").write_text(
    "\n".join(
        [
            "reviewer package workflow passed",
            f"package_id={manifest['package_id']}",
            f"product_id={manifest['product']['id']}",
            f"release_id={manifest['release']['id']}",
            f"manifest_hash={package_metadata['manifest_hash']}",
            "checked=manifest checksum, manifest verifier, archive verifier, safe archive extraction, report limitations",
        ]
    )
    + "\n"
)
PY

grep -F "customer package verified" "$workdir/manifest-verify.txt" >/dev/null
grep -F "customer package verified" "$workdir/archive-verify.txt" >/dev/null
grep -F "reviewer package workflow passed" "$workdir/summary.txt" >/dev/null

printf '%s\n' "reviewer-package-workflow-check: passed"
