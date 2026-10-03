#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"

for tool in curl go jq openssl python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "local-ci-simulation-check: missing required tool: $tool" >&2
    exit 2
  fi
done

mkdir -p tmp
# Treat the override as a prefix and own only the fresh directory created here.
# Never recursively remove a pre-existing operator-selected path.
workdir="$(mktemp -d -- "${EVYDENCE_LOCAL_CI_SIMULATION_DIR:-tmp/local-ci-simulation}.XXXXXX")"
api_pid=""

cleanup() {
  if [ -n "$api_pid" ] && kill -0 "$api_pid" >/dev/null 2>&1; then
    kill "$api_pid" >/dev/null 2>&1 || true
    wait "$api_pid" >/dev/null 2>&1 || true
  fi
  if [ "${EVYDENCE_LOCAL_CI_KEEP_ARTIFACTS:-}" != "1" ]; then
    rm -rf "$workdir"
  fi
}
trap cleanup EXIT INT TERM

mkdir -p "$workdir/.evydence"

port="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)"
api_url="http://127.0.0.1:$port"

go build -o "$workdir/evydence-api" ./cmd/evydence-api
go build -o "$workdir/evydence" ./cmd/evydence

EVYDENCE_ADDR="127.0.0.1:$port" \
EVYDENCE_RUNTIME_PROFILE=local_memory \
EVYDENCE_API_KEY_PEPPER="local-ci-simulation-pepper" \
EVYDENCE_OBJECT_STORE=filesystem \
EVYDENCE_OBJECT_DIR="$workdir/objects" \
EVYDENCE_BOOTSTRAP_TENANT="Local CI Simulation Tenant" \
EVYDENCE_PRINT_BOOTSTRAP_SECRET=true \
"$workdir/evydence-api" >"$workdir/api.stdout" 2>"$workdir/api.stderr" &
api_pid="$!"

for _ in $(seq 1 80); do
  if curl -fsS "$api_url/v1/ready" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$api_pid" >/dev/null 2>&1; then
    printf '%s\n' "local-ci-simulation-check: API process exited during startup" >&2
    sed -n '1,120p' "$workdir/api.stderr" >&2 || true
    exit 1
  fi
  sleep 0.25
done

if ! curl -fsS "$api_url/v1/ready" >/dev/null 2>&1; then
  printf '%s\n' "local-ci-simulation-check: API did not become ready" >&2
  sed -n '1,120p' "$workdir/api.stderr" >&2 || true
  exit 1
fi

if ! api_key="$(jq -er '.secret' "$workdir/api.stdout")"; then
  : >"$workdir/api.stdout"
  printf '%s\n' "local-ci-simulation-check: bootstrap secret output was not parseable" >&2
  exit 1
fi
: >"$workdir/api.stdout"

api() {
  method="$1"
  path="$2"
  idem="$3"
  body="$4"
  if [ "$method" = "GET" ]; then
    curl -fsS "${api_url}${path}" \
      -H "Authorization: Bearer ${api_key}"
  else
    curl -fsS -X "$method" "${api_url}${path}" \
      -H "Authorization: Bearer ${api_key}" \
      -H "Idempotency-Key: ${idem}" \
      -H "Content-Type: application/json" \
      --data "$body"
  fi
}

product="$(api POST /v1/products local-ci-product '{"name":"Local CI Product","slug":"local-ci-product"}')"
printf '%s\n' "$product" >"$workdir/product.json"
product_id="$(printf '%s' "$product" | jq -er '.data.id')"

project_payload="$(jq -cn --arg product_id "$product_id" '{product_id:$product_id,name:"api"}')"
project="$(api POST /v1/projects local-ci-project "$project_payload")"
printf '%s\n' "$project" >"$workdir/project.json"
project_id="$(printf '%s' "$project" | jq -er '.data.id')"

release_payload="$(jq -cn --arg product_id "$product_id" '{product_id:$product_id,version:"1.0.0-local-ci"}')"
release="$(api POST /v1/releases local-ci-release "$release_payload")"
printf '%s\n' "$release" >"$workdir/release.json"
release_id="$(printf '%s' "$release" | jq -er '.data.id')"

artifact_digest="$("$workdir/evydence" hash "$workdir/evydence")"
artifact_size="$(wc -c <"$workdir/evydence" | tr -d ' ')"
artifact_payload="$(jq -cn --arg digest "$artifact_digest" --argjson size "$artifact_size" '{name:"evydence-cli",media_type:"application/octet-stream",digest:$digest,size:$size}')"
artifact="$(api POST /v1/artifacts local-ci-artifact "$artifact_payload")"
printf '%s\n' "$artifact" >"$workdir/artifact.json"
artifact_id="$(printf '%s' "$artifact" | jq -er '.data.id')"

cat >"$workdir/.evydence/sbom.cdx.json" <<JSON
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "application",
      "name": "evydence-local-ci",
      "version": "1.0.0-local-ci",
      "purl": "pkg:github/aatuh/evydence@local-ci"
    }
  ]
}
JSON

cat >"$workdir/.evydence/grype.json" <<JSON
{
  "matches": []
}
JSON

python3 - "$artifact_digest" "$workdir/.evydence" <<'PY'
import base64
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

digest = sys.argv[1].removeprefix("sha256:")
out_dir = Path(sys.argv[2])
os.umask(0o077)
statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "evydence-cli", "digest": {"sha256": digest}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://evydence.local/build/local-ci",
            "externalParameters": {"mode": "local-ci-simulation"},
            "resolvedDependencies": [],
        },
        "runDetails": {"builder": {"id": "local-ci-simulation"}},
    },
}
payload_type = b"application/vnd.in-toto+json"
payload = json.dumps(statement, sort_keys=True).encode()
pae = b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type + b" " + str(len(payload)).encode() + b" " + payload
with tempfile.TemporaryDirectory(prefix="dsse-sign-", dir=out_dir) as key_dir:
    key_path = Path(key_dir) / "private.pem"
    pae_path = Path(key_dir) / "payload.pae"
    pae_path.write_bytes(pae)
    subprocess.run(["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key_path)], check=True, capture_output=True)
    public_der = subprocess.run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    if not public_der.startswith(bytes.fromhex("302a300506032b6570032100")) or len(public_der) != 44:
        raise ValueError("unexpected Ed25519 public key format")
    signature = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key_path), "-in", str(pae_path)], check=True, capture_output=True).stdout
envelope = {
    "payloadType": payload_type.decode(),
    "payload": base64.b64encode(payload).decode(),
    "signatures": [{"keyid": "local-ci-test-key", "sig": base64.b64encode(signature).decode()}],
}
(out_dir / "attestation.dsse.json").write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
trust_root = {
    "name": "Local CI ephemeral test root",
    "key_id": "local-ci-test-key",
    "algorithm": "Ed25519",
    "public_key": base64.b64encode(public_der[-32:]).decode(),
    "allowed_predicate_types": ["https://slsa.dev/provenance/v1"],
    "expected_builder_ids": ["local-ci-simulation"],
    "required_claims": ["builder_id", "build_type", "external_parameters"],
}
(out_dir / "trust-root.json").write_text(json.dumps(trust_root, sort_keys=True) + "\n", encoding="utf-8")
PY

EVYDENCE_API_URL="$api_url" \
EVYDENCE_API_KEY="$api_key" \
GITHUB_RUN_ID="1001" \
GITHUB_RUN_ATTEMPT="1" \
GITHUB_SHA="0123456789abcdef0123456789abcdef01234567" \
GITHUB_REPOSITORY="aatuh/evydence" \
GITHUB_WORKFLOW_REF="aatuh/evydence/.github/workflows/evydence-release-evidence.yml@refs/heads/main" \
GITHUB_JOB="local-ci-simulation" \
GITHUB_ACTOR="local-ci" \
GITHUB_REF="refs/heads/main" \
"$workdir/evydence" github-actions upload-build \
  --url "$api_url" \
  --api-key "$api_key" \
  --project-id "$project_id" \
  --release-id "$release_id" \
  --artifact-id "$artifact_id" \
  --artifact-digest "$artifact_digest" \
  --attestation-path "$workdir/.evydence/attestation.dsse.json" \
  --started-at "2026-06-01T12:00:00Z" \
  >"$workdir/upload-build.stdout"

attestation_id="$(awk '$1 == "attestation" && $2 == "uploaded:" {print $3}' "$workdir/upload-build.stdout")"
case "$attestation_id" in
  att_*) ;;
  *) printf '%s\n' 'local-ci-simulation-check: missing uploaded attestation id' >&2; exit 1 ;;
esac
trust_root="$(api POST /v1/dsse-trust-roots local-ci-dsse-root "$(jq -c . "$workdir/.evydence/trust-root.json")")"
printf '%s\n' "$trust_root" >"$workdir/trust-root-response.json"
verification="$(api POST "/v1/build-attestations/$attestation_id/verify-signature" local-ci-attestation-verify '{}')"
printf '%s\n' "$verification" >"$workdir/attestation-verification.json"
jq -e '.data.result == "passed"' "$workdir/attestation-verification.json" >/dev/null

python3 scripts/github_release_evidence_manifest.py \
  --out "$workdir/.evydence/upload-manifest.json" \
  --release-id "$release_id" \
  --artifact-id "$artifact_id" \
  --target-ref "pkg:github/aatuh/evydence@0123456789abcdef0123456789abcdef01234567" \
  --idempotency-prefix "local-ci-1001-1" \
  --cyclonedx-sbom "$workdir/.evydence/sbom.cdx.json" \
  --grype-json "$workdir/.evydence/grype.json" \
  --include-release-bundle

"$workdir/evydence" upload validate-manifest \
  --manifest "$workdir/.evydence/upload-manifest.json" \
  >"$workdir/validate-manifest.stdout"

"$workdir/evydence" ci preflight \
  --url "$api_url" \
  --api-key "$api_key" \
  --product-id "$product_id" \
  --project-id "$project_id" \
  --release-id "$release_id" \
  --artifact-id "$artifact_id" \
  --manifest "$workdir/.evydence/upload-manifest.json" \
  >"$workdir/preflight.stdout"

"$workdir/evydence" upload manifest \
  --url "$api_url" \
  --api-key "$api_key" \
  --manifest "$workdir/.evydence/upload-manifest.json" \
  >"$workdir/upload-manifest.stdout"

profile_payload='{"preset":"customer_safe"}'
profile="$(api POST /v1/redaction-profiles local-ci-redaction-profile "$profile_payload")"
printf '%s\n' "$profile" >"$workdir/redaction-profile.json"
profile_id="$(printf '%s' "$profile" | jq -er '.data.id')"

package_expiry="$(python3 - <<'PY'
from datetime import datetime, timedelta, timezone

print((datetime.now(timezone.utc) + timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ'))
PY
)"
package_payload="$(jq -cn --arg product_id "$product_id" --arg release_id "$release_id" --arg profile_id "$profile_id" --arg expires_at "$package_expiry" '{product_id:$product_id,release_id:$release_id,redaction_profile_id:$profile_id,title:"Local CI release evidence",expires_at:$expires_at}')"
package="$(api POST /v1/customer-packages local-ci-customer-package "$package_payload")"
printf '%s\n' "$package" >"$workdir/customer-package.json"
jq -e '.data.id and .data.manifest.limitations and .data.manifest.non_claims' "$workdir/customer-package.json" >/dev/null

readiness="$(api GET "/v1/reports/release-readiness?release_id=${release_id}" "" "")"
printf '%s\n' "$readiness" >"$workdir/release-readiness.json"
jq -e --arg release_id "$release_id" '.data.release_id == $release_id and .data.result == "passed"' "$workdir/release-readiness.json" >/dev/null

audit="$(api GET /v1/audit-chain/verify "" "")"
printf '%s\n' "$audit" >"$workdir/audit-chain-verification.json"
jq -e '.data.result == "passed"' "$workdir/audit-chain-verification.json" >/dev/null

if find "$workdir" -type f \( -name '*.json' -o -name '*.stdout' -o -name '*.stderr' \) -exec grep -I -l 'evy_' {} + | grep -q .; then
	printf '%s\n' "local-ci-simulation-check: generated artifacts leaked an API key-like secret" >&2
	exit 1
fi

printf '%s\n' "local-ci-simulation-check: local CI preflight, upload, readiness, package, and audit-chain flow passed"
