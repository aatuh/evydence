# SPDX fixture provenance

`spdx-2.3-example.json` is a synthetic Evydence fixture introduced by
`09a40c0cc4502ce93e520e01df004de5065631dd` (EVY-503), covered by the
project's `AGPL-3.0-only` source license. It is not copied from the SPDX
specification repository. Its example `dataLicense` value is parser input;
it does not establish an upstream source or license grant for this fixture.
The corpus previously attributed this file to the specification's CC-BY terms;
that unsupported attribution has been corrected without changing its bytes.

`spdx-spec-v2.2-example.json` is the unmodified SPDX 2.2 JSON example from
the SPDX specification repository tag `v2.3`, fetched from:

`https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/examples/SPDXJSONExample-v2.2.spdx.json`

SHA-256: `1b126f76a0eaa42dfde8ca1575fe6f158431518ebb289be00b007ca97c3841a4`.

`syft-1.46.0-spdx-2.3.json` was generated locally on 2026-08-15 with:

```sh
syft dir:/tmp/evydence-spdx-generator-input -o spdx-json
```

Syft version: `1.46.0`; SHA-256:
`154115724fd24b8b97f14f8f04ca7ab373762e2cf02cc36c76842440c0f35f43`.

`trivy-0.58.1-spdx-2.3.json` was generated locally on 2026-08-15 with the
image `aquasec/trivy:0.58.1@sha256:ab70a02200597efa04748f210f793936eb647cbcdb0ea69cc30b226d6f5a22c7`:

```sh
trivy filesystem --format spdx-json /scan
```

SHA-256: `96813d9272ac50bb5033676ee85992390db95de6c8cbd0a2b8d07e2968919954`.

The generator fixtures intentionally retain generator timestamps and document
namespace IDs. They test accepted output shapes, not byte-for-byte reproducible
generator output. The immutable source file captures every unnormalized field.
Their `CC0-1.0` catalog entries record the documents' `dataLicense` declarations.
The commands above are retained generation records; the provenance check does
not rerun those historical generator versions.

Pinned source references, file digests and the copied specification notice are
recorded in `testdata/fixture-provenance.v1.json` and `testdata/licenses/`.
