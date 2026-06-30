# Customer Package Manifest

Customer packages use `customer-security-package.v2.0.0` manifests. The
manifest is a scoped, redacted JSON summary for technical evidence review. It is
not legal compliance proof, certification, complete SBOM proof, an authoritative
vulnerability result, or a secure-release guarantee.

## Required Top-Level Fields

| Field | Purpose |
| --- | --- |
| `schema_version` / `package_version` | Stable manifest schema version. |
| `package_id` / `id` | Package identifier used by API responses and ZIP exports. |
| `title` | Operator-provided package title. |
| `generated_at` | UTC generation timestamp. |
| `tenant`, `organization`, `product`, `release` | Scoped metadata for the package subject. |
| `redaction_profile` | Redaction profile id, allowed types, excluded fields, and schema version. |
| `evidence_ids` | Included evidence metadata identifiers after redaction profile filtering. |
| `artifact_digests` | Artifact IDs, names, media types, sizes, and digests linked to the release. |
| `readiness_summary` | Deterministic readiness checks, gaps, and limitations. |
| `customer_decision_export` | Optional archive file metadata for the package-scoped customer-safe decision export. |
| `customer_safe_gaps` | Optional customer-visible gap records filtered through the package redaction profile. |
| `verification_material` | Hash algorithm, canonicalization profile, release bundle hashes, and audit-chain summary. |
| `reviewer_checklist` | Optional proof-path checklist covering package scope, included evidence, excluded evidence, verification, non-claims, and escalation path. |
| `limitations`, `non_claims` | Required package limitations and conservative product-language boundaries. |

## Optional Sections

Sections appear only when the redaction profile allows the relevant type and
matching release-scoped records exist:

- `sboms`: SBOM metadata such as format, spec version, component count, and evidence ID.
- `vulnerability_scans`: scanner metadata, target reference, summary counts, and finding count.
- `vex_documents`: VEX metadata, statement counts, status summary, and evidence ID.
- `vulnerability_decisions`: active customer-visible decision summaries only,
  including `reviewed_at` and optional `review_due_at` freshness metadata when
  recorded, plus safe `sbom_id`, `sbom_component_purl`, and
  `sbom_component_name` context when a same-release SBOM component matched the
  finding, and optional `supporting_refs` with first-class same-release record
  type/id pairs.
- `api_contracts`: OpenAPI contract metadata, normalized operation summaries,
  deterministic contract diff results, and API-contract limitations.
- `approvals`: release or product approval records.
- `exceptions`: approved, unexpired release exceptions.
- `waivers`: approved, unexpired product or release waivers.
- `object_lock_proofs`: tenant object-retention verification records, included
  only when the profile explicitly allows `object_lock_proof`.
- `provenance`: build runs and build attestation metadata.

The `api_contracts` section contains `openapi_contracts` and `contract_diffs`.
OpenAPI contract entries include IDs, evidence IDs, product/release scope,
version, SHA-256 hash, path and operation counts, and normalized operation
labels, methods, paths, operation IDs, required-request indicators, required
request fields, and response statuses. Contract diff entries include the base
and target contract IDs, result, breaking and non-breaking change summaries,
schema version, and timestamp. The section deliberately omits raw OpenAPI
document bytes, object-store references, and private/internal document
extensions.

When customer-visible vulnerability decisions are present, generated package
archives also include `vulnerability-decisions.json`. That file is scoped to the
package, repeats only customer-safe decision fields, records the source manifest
hash, and includes assumptions and limitations. The package verifier validates
the file when `verification.json` declares `decision_export_file`.

## Exclusions

Customer package manifests exclude raw tenant evidence payload bytes,
object-store payload references, bearer tokens, private keys, API key hashes,
SSO/session token hashes, and tenant-internal vulnerability decision notes.
Customer-visible vulnerability decisions require `impact_statement`; internal
notes are not copied into `vulnerability_decisions`. Decision `supporting_refs`
include only validated record type and id values. They do not copy approval
reason internals, exception payloads, incident timeline details, object-store
paths, raw payloads, or token/key material.

`object_lock_proofs` entries include policy identifiers, object-scope presence
indicators, retention mode/days, verification checks, verification hash, and
limitations. They do not include raw object payloads, object-store paths, or
storage credentials, and they do not prove legal compliance, IAM correctness,
lifecycle policy completeness, or complete WORM enforcement.

## Customer-Safe Gaps

`customer_safe_gaps` contains factual missing-evidence records only when the
missing evidence type is allowed by the package redaction profile. For example,
an SBOM gap can appear in a `customer_safe` package because `sbom` is included,
while build-attestation or internal provenance gaps are omitted unless the
profile explicitly includes `build` or `build_attestation`. Internal-only gaps
remain outside the package manifest.

## Reviewer Checklist

`reviewer_checklist` is a customer-safe proof-path summary. The checked sample
package uses it to show:

- package scope;
- included evidence;
- excluded evidence;
- hash and signature verification;
- non-claims;
- escalation path for missing or broader evidence.

Checklist entries are summaries only. They must not include raw payloads,
object-store paths, bearer credentials, signing material, token hashes, tenant
internal notes, or customer data outside the package scope.

## Presets

`POST /v1/redaction-profiles` accepts either an explicit `allowed_types` list or
a server-defined `preset`. Presets reject caller-supplied `allowed_types` or
`excluded_fields` overrides so the package policy remains predictable.

| Preset | Intended use | Default shape |
| --- | --- | --- |
| `customer_safe` | Customer release-evidence review. | Includes artifact, SBOM, vulnerability scan, VEX, active customer-visible decisions, release bundle, approval, exception, and waiver summaries. Excludes build provenance, internal URLs, raw payloads, token/key material, and internal notes. |
| `security_review` | Broader technical security review. | Includes the customer-safe families plus build provenance, build attestations, security-scan/manual-review categories, and API/security-review records where present. Still excludes raw payloads, object-store references, secrets, token material, and private keys. |

Custom profiles must supply at least one `allowed_types` entry. An empty custom
profile is rejected because it would make package contents depend on implicit
defaults instead of explicit operator scope.

## Viewer Compatibility

The local package viewer at `site/package-viewer/index.html` loads v2 manifests
directly from disk. A non-sensitive sample is available at
`examples/end-to-end-release-evidence/sample-customer-package-manifest.json`;
the matching archive fixture is
`examples/end-to-end-release-evidence/sample-customer-package.zip`.
The viewer renders the optional `reviewer_checklist` with text-only DOM APIs so
operator-provided package text is displayed as text, not interpreted as HTML.

Runtime ZIP exports also include `report.html`, a self-contained static HTML
rendering of the redacted manifest. It shows release summary, VEX and
vulnerability-decision tables, questionnaire answer-library entries when
included, object-lock proof records when included, API contract evidence when
included, readiness checks, verification material, limitations, and non-claims
without requiring a server or loading remote assets. Portal ZIP downloads can
also include `WATERMARK.txt` and a visible report watermark for
customer-specific distribution. The watermark is not a secret and does not
change the canonical package manifest hash. The HTML report is generated from
package-scoped data only and excludes raw evidence payload bytes, object-store
references, token material, private keys, and internal decision notes.

Server-backed portal access records can be named for an external reviewer with
optional reviewer name and email labels. Those labels support access review,
watermarking, and audit triage only; the portal token remains the credential and
is returned once, stored only as a hash, and omitted from package manifests,
archives, logs, and list responses.

## Reviewer UX Boundary

The package review surface is deliberately narrow:

- operators use the API and CLI to create packages, access records, downloads,
  redaction profiles, and audit evidence;
- local reviewers may use `site/package-viewer/index.html` or archive
  `report.html` after they already possess package files;
- browser-facing server review at `/v1/customer-portal/package/view` must reuse
  the same customer portal token exchange, expiry, NDA, package scope,
  watermark, and audit behavior as the JSON and ZIP endpoints.

The local viewer and static reports are not authorization mechanisms. They do
not verify that a reviewer should receive a package and they do not grant access
to tenant data. Server-hosted review pages must accept portal tokens in request
bodies rather than URLs, disable caching of package responses, escape
operator-provided package text, and omit raw payloads, object-store references,
internal notes, token material, signing private material, and unrelated customer
data.

## Redaction Leakage Guard

Customer package generation is tested with canary values for API key secrets,
internal decision notes, raw scanner payload bytes, internal URLs, object-store
paths, signing private material, tenant secrets, and internal-only evidence
fields. Runtime package archives and the checked sample fixture must not contain
those canaries, raw payload references, object-store URLs, source identity
metadata, uploader identifiers, or canonical evidence hashes.

The sample manifest is also protected by
`examples/end-to-end-release-evidence/sample-customer-package-manifest.sha256`.
Intentional fixture or manifest-shape changes must update the JSON fixture and
checksum together, and the fixture schema version must match the current
`customer-security-package.v2.0.0` domain version.

## Offline Verification

The CLI verifies a package manifest without contacting the API:

```sh
go run ./cmd/evydence package verify \
  --manifest examples/end-to-end-release-evidence/sample-customer-package-manifest.json \
  --expected-product-id prod_example \
  --expected-release-id rel_example
```

For exported ZIP packages, verify archive metadata and the manifest hash:

```sh
go run ./cmd/evydence package verify \
  --archive evydence-customer-package-csp_123.zip \
  --hash sha256:<canonical-manifest-hash>
```

The archive verifier accepts only clean top-level ZIP entries and rejects
path-traversal entries, nested paths, absolute paths, backslash-separated paths,
empty names, and duplicate entries before trusting `manifest.json`,
`package.json`, `verification.json`, or `vulnerability-decisions.json`.

The checked sample ZIP includes `vulnerability-decisions.json` for the
package-scoped decision export. The verifier checks the export scope and source
manifest hash alongside `manifest.json`, `package.json`, and
`verification.json`.

When an evidence bundle is supplied, the verifier also checks the bundle
manifest hash, included signatures, and package evidence-id coverage:

```sh
go run ./cmd/evydence package verify \
  --manifest package-manifest.json \
  --bundle evidence-bundle.json \
  --expected-signing-key-id sk_123
```

Verification proves the local files match their recorded hashes and available
signatures. It does not prove legal compliance, certification, complete SBOM
coverage, vulnerability scanner authority, or release security status.
