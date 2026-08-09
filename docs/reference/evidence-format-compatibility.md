# Evidence Format Compatibility

This reference defines the evidence-document shapes that the current Evydence
source tree actually accepts and tests. It is a technical ingestion contract,
not a claim that Evydence implements every feature of the named standards,
proves evidence completeness, treats scanner output as authoritative, or makes
a compliance or release-security determination.

## Contract vocabulary

- **Tested contract** means repository tests cover the listed shape and the
  public API documents the route.
- **Structurally accepted** means today's reduced parser may accept a version or
  field without making that external standard/version a compatibility promise.
- **Unsupported** means callers must not rely on ingestion succeeding.
- **Raw preserved** means accepted source bytes remain immutable evidence; it
  does not mean every source field appears in normalized records.

Parser acceptance alone is not standards support. EVY-502 through EVY-506 own
the broader conformance, fixture-corpus, replay, and parser-version work.

## Current matrix

| Input | Stability | Tested contract | Retained parser identity | Public HTTP form / effective limit |
| --- | --- | --- | --- | --- |
| CycloneDX SBOM JSON | `core` | Public route remains reduced; shared EVY-502 parser fixtures use `specVersion: 1.6` | `cyclonedx-json.v1.3.3` on durable `parse_sbom` job | Native `application/vnd.cyclonedx+json`: 20 MiB; JSON envelope: 64 KiB |
| SPDX SBOM JSON | `core` | Reduced shape; fixtures use `SPDX-2.3` | `spdx-json.v1` in evidence metadata | JSON envelope: 64 KiB |
| OpenVEX JSON | `core` | Reduced shape; fixtures use `https://openvex.dev/ns/v0.2.0` | `openvex-json.v1.0.0` on import report and `parse_vex` job | Native `application/vnd.openvex+json`: 20 MiB; JSON envelope: 64 KiB |
| CycloneDX VEX JSON | `core` | Reduced shape; fixtures use `specVersion: 1.6` | `cyclonedx-vex-json.v1.0.0` on import report and `parse_vex` job | JSON envelope: 64 KiB |
| DSSE + in-toto statement JSON | `core` | Structural profile; fixtures use in-toto Statement v1 and SLSA provenance v1 | `dsse-in-toto-json.v1.0.0` on `verify_attestation` job | JSON request: 64 KiB |
| Generic vulnerability-scan JSON | `core` | Evydence-owned normalized scanner schema | `generic-vulnerability-scan-json.v1.0.0` on `parse_vulnerability_scan` job | Streamed `application/json`: 20 MiB |
| Generic/SARIF security-scan JSON | `experimental` | Reduced summary; fixtures use SARIF `2.1.0` | No stable parser-version contract | JSON envelope: 64 KiB |

The parser-version strings identify Evydence behavior, not external scanner
versions. `scanner: "grype"` is metadata and does not select a Grype parser.
Native Grype, Trivy, OSV-Scanner, Dependency-Track, and similar exports are not
currently supported; convert them to the generic vulnerability-scan schema
until EVY-505 adds versioned adapters.

## Format details and current limitations

### CycloneDX SBOM JSON

`POST /v1/sboms` still exposes the legacy reduced public contract while EVY-502
is being activated end to end. That route reads `bomFormat`, `specVersion`, and
`components[].{type,name,version,purl}` and rejects unknown fields. Raw bytes are
preserved and normalized components retain name/version/purl.

The shared EVY-502 CycloneDX parser is broader and separately tested with
CycloneDX 1.6 official fixtures plus Syft/Trivy fixture shapes. It accepts
standard fields that Evydence does not normalize, records those omitted paths as
warnings/limitations, normalizes dependencies and deterministic component
identities, and requires component `type` and `name` at nested component
locations as well as the root `components` array. This shared parser currently
identifies its interpretation as `cyclonedx-json.v1.3.3`.

The conformant upload transaction also binds schema validation and
normalization to the same bounded byte stream and verifies the source's declared
size and SHA-256 before normalized data is trusted. The production public-route
switch remains pending until the pinned official CycloneDX 1.6 root schema is
embedded and verified. Worker `parse_sbom` replay also still has a legacy
reduced decoder; `internal/app/cyclonedx_replay.go` now provides the shared
projection that will replace it. These pending activation steps are why this
matrix does not yet advertise full CycloneDX 1.6 public compatibility.

Evidence: `internal/app/parsers/cyclonedx`,
`internal/app/cyclonedx_ingestion.go`, `internal/app/cyclonedx_upload.go`,
`internal/app/cyclonedx_replay.go`, `internal/app/parser_versions.go`, and the
CycloneDX parser/ingestion/upload/replay tests.

### SPDX SBOM JSON

`POST /v1/sboms/spdx` reads `spdxVersion`, package name/version, and external
reference type/locator; the first `purl` reference becomes the normalized purl.
Package names are required and unknown fields are rejected. The parser only
checks the `SPDX-` prefix, so the compatibility claim is the tested SPDX 2.3
reduced shape, not every structurally accepted `SPDX-*` value. Relationships,
checksums, licenses, document metadata, and annotations are not normalized.

Evidence: `internal/app/risk_workflows.go` (`UploadSPDXSBOM`) and
`TestSecurityScansManualDocsSPDXAndSBOMDiff`.

### OpenVEX JSON

`POST /v1/vex` requires author, RFC 3339 timestamp, at least one statement,
`vulnerability.name`, product `@id`, a supported status
(`affected`, `not_affected`, `fixed`, `under_investigation`), and justification.
Nested product subcomponents are validated. Unknown fields are rejected by the
reduced model. Context/version is recorded rather than allowlisted; the tested
contract uses namespace `https://openvex.dev/ns/v0.2.0`. Mapping failures are
recorded in import reports instead of silently attaching a statement to another
finding.

Evidence: `internal/app/vex.go`, `ParserVersionOpenVEXJSON`,
`TestOpenVEXIngestionCreatesDecisionAndRejectsMalformedInput`,
`TestOpenVEXImportReportTracksSupersessionAndMappingFailures`, and
`TestVEXImportPreviewIsAdvisoryAndDoesNotMutateLedger`.

### CycloneDX VEX JSON

`POST /v1/vex/cyclonedx` reads `bomFormat`, `specVersion`, vulnerabilities,
`affects[].ref`, and analysis state/justification/detail/response. Unknown fields
are rejected. Missing IDs or unsupported states become import-report issues and
are skipped; all-invalid input fails. Duplicate mapping does not duplicate
decision effects. The tested reduced contract is CycloneDX 1.6; other version
strings being structurally accepted are not supported-version evidence.

Evidence: `internal/app/risk_workflows.go`,
`ParserVersionCycloneDXVEXJSON`,
`TestCycloneDXVEXVulnerabilityWorkflowContractDiffAndPolicyV2`, and
`TestCycloneDXVEXImportReportTracksIssuesDuplicatesAndOutbox`.

### DSSE and in-toto JSON

`POST /v1/builds/{id}/attestations` requires DSSE `payloadType`, base64 payload,
non-empty signatures, and an inner statement with `_type`, `predicateType`, and
subjects containing valid SHA-256 digests. At least one digest must match a
registered build output. The envelope rejects unknown fields; the inner
statement uses ordinary JSON unmarshalling, so unmodeled inner fields can be
ignored. Fixtures exercise in-toto Statement v1, SLSA provenance v1, and
`application/vnd.in-toto+json`; other non-empty type values are not a supported
profile claim. Structural acceptance is separate from trust-root signature
verification.

Evidence: `internal/app/builds.go` (`parseDSSEAttestation`),
`ParserVersionDSSEInTotoJSON`, `TestDSSETrustRootVerification`,
`TestBuildValidationTenantIsolationAndMalformedAttestation`, and
`TestUploadBuildAttestationCanDeferParserSideEffectsToWorker`.

### Generic vulnerability-scan JSON

`POST /v1/vulnerability-scans` is an Evydence-owned schema, not a native scanner
export. It requires scanner, target ref, release ID, and findings with
vulnerability and severity; component/state are optional, missing state becomes
`open`, severity is lowercased, and unknown fields are rejected. The route
streams up to 20 MiB and preserves raw bytes.

Evidence: `internal/app/ledger.go` (`UploadVulnerabilityScanPayload`),
`ParserVersionGenericVulnerabilityJSON`,
`TestUploadVulnerabilityScanCanDeferParserSideEffectsToWorker`,
`TestParsersRejectMalformedInputs`, and HTTP streaming/limit tests under
`internal/adapters/httpapi`.

### Experimental security-scan JSON

`POST /v1/security-scans` and `/v1/api-security-scans` are experimental. SARIF
mode reads only non-empty version and `runs[].results[].level`; tests use 2.1.0
but the version is not allowlisted. Generic mode reads only finding severity.
Unknown fields are rejected. This is not full SARIF or native scanner support.

Evidence: `internal/app/risk_workflows.go` (`parseSecurityScan`) and security
scan tests in `risk_workflows_more_test.go` and
`security_document_uow_test.go`.

## Unsupported inputs and failure guidance

The current matrix is JSON-only. XML SBOMs, YAML VEX, protobuf, scanner-native
exports, and standard/version combinations not named above are unsupported.
Several reduced parsers record an external version instead of allowlisting it;
incidental acceptance must not be advertised as compatibility.

Malformed/unsupported public inputs fail as `400` RFC 9457 Problem Details with
stable code `VALIDATION_FAILED`. Callers should select a listed JSON contract or
transform to the generic scanner schema rather than retrying unchanged bytes.
VEX syntax acceptance and finding mapping are separate; mapping failures remain
visible in import reports/previews.

## Resource bounds

`internal/app/payload_limits.go` is the transport/application source of truth.
The effective HTTP limit is the smaller transport/application limit:

- small JSON requests: 65,536 bytes;
- evidence documents: 20,971,520 bytes (20 MiB).

The EVY-502 CycloneDX parser additionally enforces format-specific defaults of
64 JSON levels, 100,000 semantic component objects, 200,000 dependency rows or
aggregate dependency/provision edges, 1 MiB per JSON string/key, and 1,000,000
visited JSON values. These limits apply to the shared parser path; the public
compatibility claim remains reduced until the conformant route is activated.

Other evidence families listed here do not yet have equivalent independent
maximum JSON-depth, component/package/statement/subject/finding-count limits
unless their format-specific implementation states otherwise. Broader support
claims must remain tied to the bounds actually enforced by each parser.

## Parser version and compatibility

OpenVEX/CycloneDX VEX persist parser version on import reports and parser jobs;
SPDX stores `spdx-json.v1` in evidence metadata; CycloneDX SBOM, generic scan,
and DSSE/in-toto store parser version on durable subject-linked outbox jobs.
CycloneDX SBOM jobs now carry `cyclonedx-json.v1.3.3`. The worker rejects parser
jobs whose version it does not know, but CycloneDX worker replay still needs to
switch from its legacy reduced decoder to the shared replay projection before
EVY-502 can claim end-to-end interpretation parity. This identifies current
interpretation but is not yet the full EVY-506 replay/migration model. Raw bytes
remain historical source evidence.

The current public release is prerelease. Correctness/security fixes may still
change documented parser behavior, but must update this matrix, fixtures,
OpenAPI when relevant, parser version when interpretation changes, and release
notes/changelog. For a future stable `v0.1.x` patch line, tested core inputs are
intended to remain accepted unless a documented security/correctness exception
requires otherwise; changed normalization requires a new parser version and
must preserve raw evidence. Experimental formats do not receive that promise.

Broaden this matrix only with repository evidence. Do not infer support from a
parser library version, an external standard example, or one successful ad hoc
upload.
