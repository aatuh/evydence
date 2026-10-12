# SPDX fixture provenance

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
