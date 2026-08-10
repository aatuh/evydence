# CycloneDX 1.6 schema provenance

The CycloneDX validator is pinned to these three files from
`CycloneDX/specification` commit
`e02a34ae42a48239f54e04f75280b9000b29f1fb`:

| Local representation | Upstream path | Expected upstream Git blob | Repository state |
| --- | --- | --- | --- |
| `bom-1.6.part-001.json` ... `bom-1.6.part-023.json` | `schema/bom-1.6.schema.json` | `b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba` | Vendored as exact line-preserving fragments and embedded |
| `spdx.schema.json` | `schema/spdx.schema.json` | `2dccc87e3cb3c3438d3f1623a3483657ee8d4189` | Vendored and embedded |
| `jsf-0.82.schema.json` | `schema/jsf-0.82.schema.json` | `f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2` | Vendored and embedded |

The root BOM schema is split only as a repository transport representation. The
23 fragments preserve upstream lines 1-5699 in order and omit the line-ending
byte after each fragment. `embeddedPinnedBOMSchema` appends exactly one `\n`
after every fragment, reconstructing the upstream 262,666-byte file before any
schema compiler sees it. Reconstruction fails closed unless the part count, byte
length, and Git blob object ID all match the pinned values above.

`schema_provenance_test.go` verifies the committed SPDX and JSF resources by
recomputing their Git blob object IDs. `pinned_root_test.go` independently
reconstructs the embedded BOM root, checks its byte length and Git object ID,
compiles the offline validator, rejects a schema-invalid document, and exercises
representative Syft and Trivy CycloneDX 1.6 fixtures through schema validation
and normalization.

`NewPinnedSchemaValidator` also verifies any explicitly supplied root bytes
against `PinnedBOMSchemaGitBlobSHA` before schema compilation. SHA-1 is used
there only because the expected value is Git's content-addressed blob identifier.
It is not used as a general authenticity or application-signing primitive. The
same provenance guard is therefore enforced for both embedded and explicitly
supplied roots.

The exported `Ledger.UploadSBOM` and `Ledger.UploadSBOMPayload` paths now use a
process-cached `NewEmbeddedPinnedSchemaValidator` and the conformant CycloneDX
transaction. Validation and normalization are performed on the same bounded
bytes before evidence publication or object-store staging. The worker replay
path remains separately versioned work and is not made conformant by this
schema activation.

The CycloneDX BOM and JSF schemas state Apache-2.0 terms in their schema
comments; the upstream CycloneDX specification repository is Apache-2.0. The
SPDX helper schema is vendored only as a referenced validation resource from the
same pinned specification revision.

Validation uses `github.com/santhosh-tekuri/jsonschema/v6` v6.0.2, already in
Evydence's dependency graph before EVY-502 and now imported directly. Its module
LICENSE is Apache-2.0. The validator loads schema resources locally, caps each
schema resource at 4 MiB, and disables external schema resolution while
processing evidence.

Do not mark EVY-502 complete or broaden compatibility claims beyond the tested
public CycloneDX 1.6 ingestion contract until the ticket's required local
validation gates pass. Worker replay parity remains owned by the replay work.
