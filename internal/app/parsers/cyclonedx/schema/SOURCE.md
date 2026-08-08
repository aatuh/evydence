# CycloneDX 1.6 schema provenance

The production CycloneDX validator is intended to embed these three files from
`CycloneDX/specification` commit
`e02a34ae42a48239f54e04f75280b9000b29f1fb`:

| Local file | Upstream path | Expected upstream Git blob |
| --- | --- | --- |
| `bom-1.6.schema.json` | `schema/bom-1.6.schema.json` | `b6c096a999d6ee9e408a9c3ae6c6227d6981c9ba` |
| `spdx.schema.json` | `schema/spdx.schema.json` | `2dccc87e3cb3c3438d3f1623a3483657ee8d4189` |
| `jsf-0.82.schema.json` | `schema/jsf-0.82.schema.json` | `f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2` |

The CycloneDX BOM and JSF schemas state Apache-2.0 terms in their schema
comments; the upstream CycloneDX specification repository is Apache-2.0. The
SPDX helper schema is vendored only as a referenced validation resource from the
same pinned specification revision.

Validation uses `github.com/santhosh-tekuri/jsonschema/v6` v6.0.2, already in
Evydence's dependency graph before EVY-502 and now imported directly. Its module
LICENSE is Apache-2.0. The validator loads every schema resource locally; it
must not fetch schemas or references over the network while processing evidence.

Before these JSON files are committed, verify their Git blob IDs against the
values above. A filename match alone is not sufficient provenance.
