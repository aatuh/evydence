# VEX parser fixture provenance

- `openvex/openvex-spec-minimal.json` matches the first JSON fenced block in
  [OPENVEX-SPEC.md at `d29fab0c`](https://github.com/openvex/spec/blob/d29fab0c81cfea04159436d54c3edc32947039ac/OPENVEX-SPEC.md).
  JSON whitespace is normalized; data semantics match. The repository's
  [license at that commit](https://github.com/openvex/spec/blob/d29fab0c81cfea04159436d54c3edc32947039ac/LICENSE)
  declares CC0-1.0.
- `cyclonedx-vex/official-vex-1.4.json` matches
  [VEX/vex.json at `7d9172d0`](https://github.com/CycloneDX/bom-examples/blob/7d9172d00c88c05a8f1ccb90589d111870fc9d86/VEX/vex.json)
  after JSON whitespace normalization. The repository's
  [license at that commit](https://github.com/CycloneDX/bom-examples/blob/7d9172d00c88c05a8f1ccb90589d111870fc9d86/LICENSE)
  declares CC0-1.0.

The original import notes recorded retrieval on 2026-08-15 using branch URLs.
The revisions above existed by that date and provide pinned byte/notice
references for the current files. Corpus labels formerly stated Apache-2.0 and
CC-BY-4.0 respectively; they have been corrected to the checked source notices.
The fixture payloads are unchanged. Full source/hash records and verbatim
notices live in `testdata/fixture-provenance.v1.json` and `testdata/licenses/`.

These fixtures establish parser compatibility only. They do not establish source authenticity or a finding-to-release mapping.
