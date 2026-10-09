# CycloneDX 1.6 fixture provenance

These fixtures are copied from `CycloneDX/specification` commit
`e02a34ae42a48239f54e04f75280b9000b29f1fb` under the upstream Apache-2.0
schema/test-material terms. They are kept byte-equivalent in data semantics;
JSON whitespace is normalized only where noted by Git diff review.

| Local fixture | Upstream path | Upstream Git blob |
| --- | --- | --- |
| `valid-dependency-1.6.json` | `tools/src/test/resources/1.6/valid-dependency-1.6.json` | `1e87f38efb6e82876e3dc0ad73ee26c0ed24606d` |
| `valid-properties-1.6.json` | `tools/src/test/resources/1.6/valid-properties-1.6.json` | `ad62c6f98407e66bfceadd502ed37e3b50816585` |
| `valid-standard-1.6.json` | `tools/src/test/resources/1.6/valid-standard-1.6.json` | `3150227b6e5e5b08e30a5fed3c2082b750260ad3` |

The official 1.6 JSON schema at the same upstream commit states in its `$comment`
that the CycloneDX JSON schema is published under Apache License 2.0. These
fixtures are test evidence, not a claim that all CycloneDX 1.6 constructs are
normalized by Evydence.
