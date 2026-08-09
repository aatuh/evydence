# CycloneDX 1.6 schema provenance

The CycloneDX validator is pinned to these three files from
`CycloneDX/specification` commit
`e02a34ae42a48239f54e04f75280b9000b29f1fb`:

| Local file | Upstream path | Expected upstream Git blob | Repository state |
| --- | --- | --- | --- |
| `bom-1.6.schema.json` | `schema/bom-1.6.schema.json` | `b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba` | Pending exact-byte admission |
| `spdx.schema.json` | `schema/spdx.schema.json` | `2dccc87e3cb3c3438d3f1623a3483657ee8d4189` | Vendored and embedded |
| `jsf-0.82.schema.json` | `schema/jsf-0.82.schema.json` | `f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2` | Vendored and embedded |

`schema_provenance_test.go` verifies the committed SPDX and JSF resources by
recomputing their Git blob object IDs. The root BOM schema remains deliberately
absent until its exact bytes can be admitted; a filename match or reserialized
JSON document is not sufficient provenance.

`NewPinnedSchemaValidator` also verifies the supplied root bytes against
`PinnedBOMSchemaGitBlobSHA` before schema compilation. SHA-1 is used there only
because the expected value is Git's content-addressed blob identifier. It is not
used as a general authenticity or application-signing primitive. This runtime
guard ensures an accidentally modified or differently serialized root cannot be
activated even if it reaches the constructor.

The CycloneDX BOM and JSF schemas state Apache-2.0 terms in their schema
comments; the upstream CycloneDX specification repository is Apache-2.0. The
SPDX helper schema is vendored only as a referenced validation resource from the
same pinned specification revision.

Validation uses `github.com/santhosh-tekuri/jsonschema/v6` v6.0.2, already in
Evydence's dependency graph before EVY-502 and now imported directly. Its module
LICENSE is Apache-2.0. The validator loads schema resources locally, caps each
schema resource at 4 MiB, and disables external schema resolution while
processing evidence.

Do not switch the public CycloneDX upload path or claim complete CycloneDX 1.6
schema conformance until the root resource is present, its Git blob ID matches
the value above, and the ticket's required local validation gates pass.
