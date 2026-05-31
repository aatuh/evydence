#!/usr/bin/env sh
set -eu

: "${EVYDENCE_URL:=http://localhost:8080}"
: "${EVYDENCE_API_KEY:?EVYDENCE_API_KEY is required}"

outdir="${EVYDENCE_DEMO_OUTDIR:-tmp/end-to-end-release-evidence}"
mkdir -p "$outdir"

api() {
  method="$1"
  path="$2"
  idem="$3"
  body="$4"
  if [ "$method" = "GET" ]; then
    curl -sS "${EVYDENCE_URL}${path}" \
      -H "Authorization: Bearer ${EVYDENCE_API_KEY}"
  else
    curl -sS -X "$method" "${EVYDENCE_URL}${path}" \
      -H "Authorization: Bearer ${EVYDENCE_API_KEY}" \
      -H "Idempotency-Key: ${idem}" \
      -H "Content-Type: application/json" \
      --data "$body"
  fi
}

product="$(api POST /v1/products demo-product '{"name":"Demo Payments API","slug":"demo-payments-api"}')"
printf '%s\n' "$product" > "$outdir/product.json"
product_id="$(printf '%s' "$product" | jq -r '.data.id')"

release="$(api POST /v1/releases demo-release "{\"product_id\":\"$product_id\",\"version\":\"1.0.0\"}")"
printf '%s\n' "$release" > "$outdir/release.json"
release_id="$(printf '%s' "$release" | jq -r '.data.id')"

artifact="$(api POST /v1/artifacts demo-artifact "{\"release_id\":\"$release_id\",\"name\":\"payments-api.tar.gz\",\"media_type\":\"application/gzip\",\"digest\":\"sha256:ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb\",\"size\":42}")"
printf '%s\n' "$artifact" > "$outdir/artifact.json"
artifact_id="$(printf '%s' "$artifact" | jq -r '.data.id')"

sbom="$(api POST /v1/sboms demo-sbom "{\"release_id\":\"$release_id\",\"artifact_id\":\"$artifact_id\",\"payload\":{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"openssl\",\"purl\":\"pkg:apk/openssl@3.1.0\"}]}}")"
printf '%s\n' "$sbom" > "$outdir/sbom.json"

scan="$(api POST /v1/vulnerability-scans demo-scan "{\"release_id\":\"$release_id\",\"scanner\":\"grype\",\"target_ref\":\"pkg:oci/payments-api\",\"findings\":[{\"vulnerability\":\"CVE-2026-0099\",\"component\":\"pkg:apk/openssl@3.1.0\",\"severity\":\"critical\",\"state\":\"open\"}]}")"
printf '%s\n' "$scan" > "$outdir/vulnerability-scan.json"
finding_id="$(printf '%s' "$scan" | jq -r '.data.findings[0].id')"

decision="$(api POST "/v1/vulnerability-findings/${finding_id}/decisions" demo-decision '{"status":"not_affected","justification":"Demo decision; replace with release-specific technical analysis."}')"
printf '%s\n' "$decision" > "$outdir/vulnerability-decision.json"

bundle="$(api POST /v1/release-bundles demo-release-bundle "{\"release_id\":\"$release_id\"}")"
printf '%s\n' "$bundle" > "$outdir/release-bundle.json"

profile="$(api POST /v1/redaction-profiles demo-redaction-profile '{"name":"Demo customer redaction","allowed_types":["sbom","vulnerability_scan","release_bundle"],"excluded_fields":["raw_payload","secrets"]}')"
printf '%s\n' "$profile" > "$outdir/redaction-profile.json"
profile_id="$(printf '%s' "$profile" | jq -r '.data.id')"

package="$(api POST /v1/customer-packages demo-customer-package "{\"product_id\":\"$product_id\",\"release_id\":\"$release_id\",\"redaction_profile_id\":\"$profile_id\",\"title\":\"Demo customer release evidence\",\"expires_at\":\"2026-06-30T00:00:00Z\"}")"
printf '%s\n' "$package" > "$outdir/customer-package.json"

readiness="$(api GET "/v1/reports/release-readiness?release_id=${release_id}" "" "")"
printf '%s\n' "$readiness" > "$outdir/release-readiness.json"

audit="$(api GET /v1/audit-chain/verify "" "")"
printf '%s\n' "$audit" > "$outdir/audit-chain-verification.json"

printf 'wrote demo evidence outputs to %s\n' "$outdir"
printf 'release_id=%s\n' "$release_id"
