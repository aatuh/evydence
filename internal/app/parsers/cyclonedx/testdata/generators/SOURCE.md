# Generator fixture provenance

These CycloneDX 1.6 fixtures come from real generator repositories and are used
to guard compatibility with emitted documents rather than hand-written reduced
models. JSON whitespace is normalized locally; data semantics are preserved.

| Generator | Source commit | Upstream fixture | Upstream Git blob | License |
| --- | --- | --- | --- | --- |
| Syft | `949ac703694941369ea979f4cd6172097a2823da` | `syft/format/cyclonedxjson/testdata/identify/1.6.json` | `9f4cb7bdcf3a39a76ae589e0993044e2dfdd55c3` | Apache-2.0 |
| Trivy | `780e90eed9571363c63f7be45d84adee07601425` | `pkg/sbom/cyclonedx/testdata/happy/nested-packages-bom.json` | `fd7623c7302811c608df678540b10cc1d14023dc` | Apache-2.0 |

The licenses were verified from each repository's `LICENSE` file at the pinned
commit. These fixtures prove parser compatibility with the captured outputs;
they do not make Syft or Trivy scanner findings authoritative.
