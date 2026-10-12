# CycloneDX 1.6 schema provenance

The CycloneDX validator is pinned to these three files from
`CycloneDX/specification` commit
`e02a34ae42a48239f54e04f75280b9000b29f1fb`:

| Local representation | Upstream path | Expected upstream Git blob | Repository state |
| --- | --- | --- | --- |
| `bom-1.6.part-001.fragment` ... `bom-1.6.part-023.fragment` | `schema/bom-1.6.schema.json` | `b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba` | Vendored exact-byte slices; reconstructed and verified |
| `spdx.schema.json` | `schema/spdx.schema.json` | `2dccc87e3cb3c3438d3f1623a3483657ee8d4189` | Vendored and embedded exactly |
| `jsf-0.82.schema.json` | `schema/jsf-0.82.schema.json` | `f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2` | Vendored and embedded exactly |

The pinned upstream BOM root is 262,666 bytes and Git blob
`b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba`. The 23 opaque byte slices are
joined without separators. `embeddedPinnedBOMSchema` requires the expected part
count, exact length, and pinned whole-file Git object ID before any schema
compiler sees the root. Do not relax those checks or normalize fragment bytes.

The fragments use a `.fragment` suffix rather than `.json` because no individual
fragment is a standalone JSON document and generic JSON validation tooling must
not treat one as such.

`schema_provenance_test.go` verifies the committed SPDX and JSF resources by
recomputing their Git blob object IDs. `pinned_root_test.go` independently
reconstructs the embedded BOM root and requires its byte length and Git object
ID before compiling the offline validator.

`NewPinnedSchemaValidator` verifies any explicitly supplied root bytes against
`PinnedBOMSchemaGitBlobSHA` before schema compilation. SHA-1 is used there only
because the expected value is Git's content-addressed blob identifier. It is not
used as a general authenticity or application-signing primitive.

The conformant CycloneDX transaction remains implemented and tested internally:
schema validation and normalization consume the same bounded source bytes,
source size/SHA-256 are bound before trusted normalization, authorization occurs
before attacker-controlled parsing, and object staging/evidence publication
occur only after validation succeeds. Current-version `parse_sbom` worker replay
uses `ParseCycloneDXReplayProjection` and the same shared bounded parser.
Historical parser-version migration and replay compatibility remain separate
replay/versioning work.

The exported public `Ledger.UploadSBOM` and `Ledger.UploadSBOMPayload` facade
uses the conformant transaction after the embedded root is verified. The
transaction validates and normalizes one bounded byte stream before staging or
publishing evidence.

The CycloneDX BOM and JSF schemas state Apache-2.0 terms in their schema
comments; the upstream CycloneDX specification repository is Apache-2.0. The
SPDX helper schema is vendored only as a referenced validation resource from the
same pinned specification revision.

Validation uses `github.com/santhosh-tekuri/jsonschema/v6` v6.0.2, already in
Evydence's dependency graph before EVY-502 and now imported directly. Its module
LICENSE is Apache-2.0. The validator loads schema resources locally, caps each
schema resource at 4 MiB, and disables external schema resolution while
processing evidence.

Do not mark EVY-502 complete or advertise the official-schema public ingestion
path until the root resource is exact and these required local gates pass:

- `go test ./internal/app/parsers/cyclonedx ./internal/app`
- `go test -fuzz=FuzzCycloneDX -fuzztime=30s ./internal/app/parsers/cyclonedx`
- `make production-check`
