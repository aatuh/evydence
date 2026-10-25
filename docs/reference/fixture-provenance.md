# Fixture Provenance

This reference is for maintainers reviewing redistributed fixtures and vendored
schema resources. [`testdata/fixture-provenance.v1.json`](../../testdata/fixture-provenance.v1.json)
owns the file digests, source transformations, pinned upstream references and
notice mapping. Verbatim notices live in `testdata/licenses/`; the project's
own source notice remains [`LICENSE`](../../LICENSE).
Git attributes preserve the copied notice bytes across checkout platforms. The
upstream Trivy NOTICE's trailing space is retained; its file-specific whitespace
attribute leaves digest and upstream-identity checks in force.

The catalog covers 56 files in 34 logical records, including the 23 ordered
CycloneDX schema slices as one reconstructed resource. It also covers parser
examples, Sigstore samples, project test vectors, lint snippets and historical
release-verification samples in the checker's declared fixture roots. It is
not an inventory of every source file or every dependency in a built artifact.

## Source Records

- `bytes` requires exact SHA-256 and Git blob identity. The latter identifies
  Git content; SHA-256 independently binds bytes and neither authenticates a
  publisher by itself.
- `json` allows JSON whitespace/key-order normalization. Canonical comparison
  preserves array order and JSON types; duplicate keys and nonfinite values fail.
- `markdown-json` selects a numbered JSON fenced block from a pinned document.
  Other fenced languages are tracked separately; surrounding prose is not
  treated as a JSON document.
- `project` records project-authored fixtures under the existing root source
  license. The two scanner inputs already declared CC0-1.0 by the corpus retain
  that declaration; this check grants no new license or exception.
- `recorded-generated` retains the documented generator record and the SPDX
  document's `dataLicense`. It does not rerun historical generator versions.

The catalog corrects four unsupported corpus source/license labels without
changing fixture payloads or expected parser summaries:

| Corpus fixture | Checked record |
| --- | --- |
| CycloneDX official standard 1.6 | Apache-2.0 notice at the pinned specification revision |
| Synthetic SPDX 2.3 example | Project-authored test input under AGPL-3.0-only; not an upstream specification example |
| OpenVEX minimal example | CC0-1.0 notice; first JSON block in the pinned specification |
| CycloneDX VEX example | CC0-1.0 notice at the pinned examples revision |

These are recorded declarations and source equivalences, not legal
compatibility decisions or approval of every dependency. Example vulnerability,
package-license and `dataLicense` fields do not establish fixture source rights
or real vulnerabilities in Evydence. Sigstore samples are test material, not
production trust roots.

## Checks

```sh
make fixture-provenance-check
make fixture-provenance-upstream-check
```

The first is offline and included in `make docs-check`. It rejects changed,
missing, duplicate, unclassified or symlinked fixture files, notice drift,
invalid source records and disagreement with the parser corpus. New fixtures
need an intentional catalog/source update. Notices are read only from root
`LICENSE` or flat `testdata/licenses/` files. Source notes use `SOURCE.md` or
`SOURCES.md` within the declared fixture roots; unrelated local paths are
refused. Grouping files cannot override the
existing project license declarations. An upstream fixture must reference a
covering license notice from the same repository and commit; an unrelated
repository's permissive notice cannot establish its declaration.

The upstream target additionally uses authenticated, read-only `gh api` calls
to exact repository paths at full commit IDs. It checks content size, encoding,
SHA-256, Git blob identity and every declared transformation. Requests and
retained response bytes are bounded; shared source files are fetched once.
Use the host RAM coordinator for upstream collection and Go-backed gates.

The general dependency snapshot includes the catalog records, copied notice
metadata and separate notice-text classifications. Generation uses a bounded
snapshot of all checked fixture inputs, verifies local digests and rejects edits
or new unclassified files before publishing a report. Live upstream equivalence
has the separate target above; run it when source/notice references change.
This provenance check does not produce a final admission verdict. The
[combined caller](dependency-review.md#qualification-limits) owns hosted fixture
license admission; its allowed/disallowed-fixture controls have separate
source-bound evidence.
