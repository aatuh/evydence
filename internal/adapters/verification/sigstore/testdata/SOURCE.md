# Sigstore fixture provenance

This reference records the upstream identity of two test-only fixtures. They
are byte-identical to these files in `sigstore/sigstore-go` v1.3.0, commit
`22d3691c7b8e0c5530fae3c05577690bfef5cd00`:

| Local fixture | Upstream path |
| --- | --- |
| `official-othername.bundle.json` | `pkg/testing/data/bundles/othername.sigstore.json` |
| `official-scaffolding.trusted-root.json` | `pkg/testing/data/trusted-roots/scaffolding.json` |

The repository's LICENSE declares Apache-2.0; its COPYRIGHT.txt notice is
preserved alongside it under `testdata/licenses/`. The catalog at
`testdata/fixture-provenance.v1.json` binds the file digests and pinned upstream
paths. This is a checked source equivalence, not a claim that the initial
EVY-602 import recorded that version. These samples are test material and are
not production trust roots or trusted publisher identities.
