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
| CycloneDX SBOM JSON | `core` | Official-schema CycloneDX 1.6 JSON; the shared bounded parser/validator corpus targets official fixtures plus Syft/Trivy output shapes | `cyclonedx-json.v1.3.4` on durable `parse_sbom` jobs and evidence metadata | Native `application/vnd.cyclonedx+json`: 20 MiB; JSON envelope: 64 KiB |
| SPDX SBOM JSON | `core` | Bounded SPDX JSON `SPDX-2.2` and `SPDX-2.3`; the shared corpus covers a standards-shaped document plus Syft/Trivy output shapes | `spdx-json.v2.0.0` on durable `parse_sbom` jobs and evidence metadata | Native `application/spdx+json`: 20 MiB; JSON envelope: 64 KiB |
| OpenVEX JSON | `core` | Bounded OpenVEX JSON using maintained `github.com/openvex/go-vex` model; tested against the OpenVEX specification's minimal example | `openvex-json.v2.0.0` on import report and `parse_vex` job | Native `application/vnd.openvex+json`: 20 MiB; JSON envelope: 64 KiB |
| CycloneDX VEX JSON | `core` | Bounded CycloneDX VEX JSON 1.4–1.7 using maintained `github.com/CycloneDX/cyclonedx-go`; tested against the official CycloneDX 1.4 VEX example | `cyclonedx-vex-json.v2.0.0` on import report and `parse_vex` job | JSON envelope: 64 KiB |
| DSSE + in-toto statement JSON | `core` | Offline trusted-attestation profile: DSSE `application/vnd.in-toto+json`, in-toto Statement v1, and SLSA provenance v1 only | `dsse-in-toto-json.v1.0.0` on `verify_attestation` job; versioned verification receipt | JSON request: 64 KiB |
| Generic vulnerability-scan JSON | `core` | Evydence-owned normalized scanner schema | `scanner-adapters-json.v1.0.0` on new `parse_vulnerability_scan` jobs | Streamed `application/json`: 20 MiB |
| Grype JSON | `core` | Versioned `grype-json.v1` envelope around the native `matches` report | `scanner-adapters-json.v1.0.0` | Streamed `application/json`: 20 MiB |
| Trivy JSON | `core` | Versioned `trivy-json.v1` envelope around the native `Results` report | `scanner-adapters-json.v1.0.0` | Streamed `application/json`: 20 MiB |
| OSV-Scanner JSON | `core` | Versioned `osv-scanner-json.v1` envelope around native package findings | `scanner-adapters-json.v1.0.0` | Streamed `application/json`: 20 MiB |
| Dependency-Track JSON | `core` | Versioned `dependency-track-json.v1` envelope around exported component findings | `scanner-adapters-json.v1.0.0` | Streamed `application/json`: 20 MiB |
| Generic/SARIF security-scan JSON | `experimental` | Reduced summary; fixtures use SARIF `2.1.0` | No stable parser-version contract | JSON envelope: 64 KiB |

The parser-version strings identify Evydence behavior, not external scanner
versions. Native adapters are selected only by the explicit `scanner` and
`source_schema` envelope fields. Unknown versions are rejected; a report is
never guessed or silently flattened. The generic schema remains supported for
producers that already normalize findings. Syft/Trivy CycloneDX 1.6 outputs are
used as EVY-502 interoperability fixtures for the supported CycloneDX route.

## Format details and current limitations

### CycloneDX SBOM JSON

`POST /v1/sboms` validates CycloneDX 1.6 documents with the pinned official
schema before publishing evidence. Valid standard fields outside Evydence's
normalized subset remain raw preserved and appear as parser limitations.

The conformant EVY-502 implementation exists separately and is covered by parser
and app tests. It pins CycloneDX 1.6 plus the SPDX/JSF companion schemas,
disables external schema resolution, and refuses to compile a root unless the
reconstructed bytes match the recorded upstream Git object. The embedded root is
262,666 bytes and matches that pinned object before the validator is constructed.

The shared parser is tested with CycloneDX 1.6 official fixtures plus Syft/Trivy
CycloneDX fixture shapes. It accepts standard fields that Evydence does not
normalize, records those omitted paths as warnings/limitations/import-report
metadata, normalizes dependencies and deterministic component identities, and
requires component `type` and `name` at nested component locations as well as
the root `components` array. It rejects duplicate JSON object keys before
normalization so interpretation cannot depend on last-value-wins decoder
behavior. This shared parser identifies its interpretation as
`cyclonedx-json.v1.3.4`.

The conformant upload transaction binds schema validation and normalization to
the same bounded byte stream and verifies the source's declared size and SHA-256
before normalized data is trusted. Authorization happens before attacker-
controlled payload parsing, while object staging and evidence publication happen
only after schema validation and normalization succeed. Accepted source bytes
remain byte-for-byte raw evidence; fields outside the normalized subset are not
silently represented as trusted normalized data.

Current-version `parse_sbom` worker replay uses
`internal/app/cyclonedx_replay.go` and the same shared bounded parser, so a
current `v1.3.4` replay does not maintain a second reduced JSON interpretation.
EVY-506 still owns historical parser-version migration, compatibility windows
for already-enqueued jobs, and the broader replay/conformance corpus; current-
version replay parity is not a claim that older parser versions have been
migrated.

Evidence: `internal/app/parsers/cyclonedx`,
`internal/app/cyclonedx_ingestion.go`, `internal/app/cyclonedx_upload.go`,
`internal/app/cyclonedx_validator.go`, `internal/app/release_evidence_service.go`,
`internal/app/cyclonedx_replay.go`, `internal/app/parser_versions.go`,
`cmd/evydence-worker/main.go`, and the CycloneDX parser/ingestion/upload/replay
tests.

### SPDX SBOM JSON

`POST /v1/sboms/spdx` accepts only SPDX JSON `SPDX-2.2` and `SPDX-2.3`. The
native `application/spdx+json` form supports a 20 MiB payload and requires the
release id in `X-Evydence-Release-ID`; the JSON envelope is retained for small
requests. The shared bounded parser rejects duplicate keys and oversized,
deep, or overlarge package/relationship/checksum/external-reference graphs.

Package names, versions, SPDX identifiers, PURLs, relationships, checksums,
licenses, and external-reference counts are parsed deterministically. A PURL
is the cross-format component identity when present. PURL-less components use
their SPDX identifier, avoiding a false merge with a CycloneDX component that
happens to have the same name and version. The immutable raw payload retains
the complete source document. Standard or legal extension fields outside the
normalized subset are accepted and reported as parser warnings and import
report metadata rather than silently normalized or rejected.

The upload transaction authorizes release and artifact targets before opening
the raw source, binds normalization to the declared source size and SHA-256,
then stages the same source as immutable evidence. Current-version worker
replay dispatches by the durable parser version and uses the shared SPDX parser.
This does not claim historical parser-version migration or prove SBOM
completeness.

Evidence: `internal/app/parsers/spdx`, `internal/app/spdx_ingestion.go`,
`internal/app/spdx_upload.go`, `internal/app/spdx_replay.go`,
`internal/app/parser_versions.go`, `cmd/evydence-worker/main.go`, and SPDX
parser/upload/replay tests.

### OpenVEX JSON

`POST /v1/vex` accepts bounded OpenVEX JSON through the maintained
`github.com/openvex/go-vex` model plus duplicate-key and resource-bound
preflight. It requires author, RFC 3339 timestamp, at least one statement,
`vulnerability.name`, product `@id`, and a supported status (`affected`,
`not_affected`, `fixed`, `under_investigation`). Nested product subcomponents
are included in matching. Standard fields and vendor extensions outside the
normalized decision subset remain in immutable raw evidence and appear as
import warnings rather than causing rejection. The parser records source
justification vocabulary unchanged. It supports the OpenVEX specification's
`https://openvex.dev/ns/v0.2.0` example but does not establish source identity,
signature trust, or legal sufficiency.

Finding mapping first scopes candidates to the tenant and release, then matches
the vulnerability and exact product/subcomponent identifier. A statement with
no product reference may apply only when one candidate exists. A statement with
several explicit product identifiers may apply one unique finding per identifier.
Duplicate candidates for an identifier, a candidate with no identifier, or any
other multi-candidate case produces `ambiguous_finding` in the import report or
preview and creates no decision. This policy also applies during worker replay.

Evidence: `internal/app/vex.go`, `ParserVersionOpenVEXJSON`,
`TestOpenVEXIngestionCreatesDecisionAndRejectsMalformedInput`,
`TestOpenVEXImportReportTracksSupersessionAndMappingFailures`, and
`TestVEXImportPreviewIsAdvisoryAndDoesNotMutateLedger`.

### CycloneDX VEX JSON

`POST /v1/vex/cyclonedx` supports bounded CycloneDX VEX JSON `specVersion`
1.4–1.7 through `github.com/CycloneDX/cyclonedx-go` and normalizes
`vulnerabilities`, `affects[].ref`, and analysis
state/justification/detail/response. It maps `resolved` and
`resolved_with_pedigree` to `fixed`, `not_affected` and `false_positive` to
`not_affected`, `exploitable` to `affected`, and `in_triage` to
`under_investigation`; the original justification is retained. Standard fields
and extensions remain in raw evidence and are reported as warnings. Missing IDs
or unsupported states become import-report issues and are skipped; all-invalid
input fails. The same explicit ambiguity policy above prevents a VEX statement
from silently changing more than one plausible finding.

Evidence: `internal/app/risk_workflows.go`,
`ParserVersionCycloneDXVEXJSON`,
`TestCycloneDXVEXVulnerabilityWorkflowContractDiffAndPolicyV2`, and
`TestCycloneDXVEXImportReportTracksIssuesDuplicatesAndOutbox`.

### DSSE and in-toto JSON

`POST /v1/builds/{id}/attestations` preserves the original DSSE envelope and
requires a DSSE `payloadType`, base64 payload, non-empty signatures, an in-toto
Statement v1, and subjects with valid SHA-256 digests. Every uploaded subject
must match a registered build output. The maintained DSSE and in-toto libraries
parse the envelope and statement; the envelope rejects unknown fields.

`POST /v1/build-attestations/{id}/verify-signature` is an explicit offline
assurance step. A passing receipt requires DSSE PAE and Ed25519 signature
verification against one configured tenant root, payload type
`application/vnd.in-toto+json`, predicate type `https://slsa.dev/provenance/v1`,
all attested subjects registered for the build's release, the configured builder
identity, and configured required claims (`builder_id`, `build_type`, and/or
`external_parameters`). Each root records its immutable policy when created.
Unsupported payload or predicate types return `not_verified`; they never count
as trusted provenance or release-readiness evidence. This profile is offline
only and does not claim certificate-chain trust, revocation, transparency-log
inclusion, CI-provider runtime integrity, or provenance completeness.

Evidence: `internal/adapters/verification/dsse`, `internal/app/builds.go`,
`internal/app/governance_packages.go`, `ParserVersionDSSEInTotoJSON`,
`TestVerifyAttestationEnforcesPAEAndTrustedPolicy`,
`TestDSSETrustRootVerification`, and
`TestBuildValidationTenantIsolationAndMalformedAttestation`.

The verifier directly uses tagged `github.com/in-toto/attestation v1.2.0`
(Apache-2.0) and `github.com/secure-systems-lab/go-securesystemslib v0.11.0`
(MIT). Both were already present transitively through the existing Sigstore
stack, so promoting them to direct requirements adds no new module-graph
footprint. The standard library does not provide DSSE PAE or in-toto protobuf
models; the fallback is to reject attestations rather than reimplement either
security-critical format. `make vuln` reports no reachable vulnerabilities;
dependency update and vulnerability monitoring remain governed by EVY-1407.

### Generic vulnerability-scan JSON

`POST /v1/vulnerability-scans` accepts the Evydence-owned generic schema and
versioned native adapter envelopes. The generic form requires scanner, target
ref, release ID, and findings with vulnerability and severity; component/state
are optional, missing state becomes `open`, severity is lowercased, and unknown
fields are rejected. The route
streams up to 20 MiB and preserves raw bytes.

Native envelopes require `source_schema` (`grype-json.v1`, `trivy-json.v1`,
`osv-scanner-json.v1`, or `dependency-track-json.v1`) and an unmodified native
JSON object in `payload`. Their findings retain CVE, GHSA, OSV, vendor advisory,
PURL, CPE, severity source, and fix-version fields when supplied. Differing
identifiers of the same kind are rejected rather than selected arbitrarily;
PURLs remain ecosystem-qualified, so packages are not conflated across
ecosystems. Scanner data is evidence for review, not scanner authority.

Evidence: `internal/app/ledger.go` (`UploadVulnerabilityScanPayload`),
`ParserVersionScannerAdaptersJSON`,
`internal/app/parsers/scanners`,
`TestUploadVulnerabilityScanCanDeferParserSideEffectsToWorker`, and HTTP
streaming/limit tests under `internal/adapters/httpapi`.

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
visited JSON values. Depth, value-count, string/key bounds, and duplicate-key
rejection are applied by the streaming token preflight before full JSON-tree
materialization; structural checks are repeated on the decoded representation.
These parser limits apply to the public conformant path and current-version
worker replay.

Other evidence families listed here do not yet have equivalent independent
maximum JSON-depth, component/package/statement/subject/finding-count limits
unless their format-specific implementation states otherwise. Broader support
claims must remain tied to the bounds actually enforced by each parser.

## Parser version and compatibility

OpenVEX/CycloneDX VEX persist parser version on import reports and parser jobs;
SPDX stores `spdx-json.v2.0.0` in evidence metadata; CycloneDX SBOM, generic scan,
and DSSE/in-toto store parser version on durable subject-linked outbox jobs.
CycloneDX `parse_sbom` jobs use `cyclonedx-json.v1.3.4`, and current worker replay
uses that shared parser projection. The worker rejects parser jobs whose version
it does not know. EVY-506 still needs to define and test historical parser-
version compatibility/migration policy rather than silently replaying older jobs
under the current interpretation. Raw bytes remain historical source evidence
and are the basis for those future migrations.

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
