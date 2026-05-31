# Upload Manifest

The upload manifest is a local CLI file for batching existing `/v1` create
requests. It is useful in CI when scanner, SBOM, VEX, provenance, approval, and
package-export payloads are produced as files before upload.

The schema file is [schemas/upload-manifest.v1.schema.json](../../schemas/upload-manifest.v1.schema.json).
The current schema version is `evydence-upload-manifest.v1.0.0`.

## Shape

```json
{
  "schema_version": "evydence-upload-manifest.v1.0.0",
  "requests": [
    {
      "kind": "sbom",
      "path": "/v1/sboms",
      "idempotency_key": "release-123-sbom",
      "payload_file": "sbom-cyclonedx-upload.json"
    }
  ]
}
```

Each request must include:

- `path`: a `/v1` create/action endpoint.
- `idempotency_key`: the exact idempotency key sent to the API.
- exactly one of `payload` or `payload_file`.

`payload_file` is resolved relative to the manifest directory and must stay
inside that directory after symlink resolution. The CLI validates JSON before it
sends any request.

`kind` is optional for backward compatibility, but recommended. It documents the
request intent and lets the CLI reject obvious path mistakes:

| Kind | Supported paths |
| --- | --- |
| `artifact` | `/v1/artifacts` |
| `sbom` | `/v1/sboms`, `/v1/sboms/spdx` |
| `scan`, `vulnerability_scan` | `/v1/vulnerability-scans` |
| `vex` | `/v1/vex`, `/v1/vex/cyclonedx` |
| `provenance`, `build`, `build_attestation` | `/v1/builds`, `/v1/builds/{id}/attestations` |
| `approval` | `/v1/approvals`, release approval paths |
| `package_export`, `customer_package` | `/v1/customer-packages` |
| `release_bundle` | `/v1/release-bundles` |
| `evidence` | `/v1/evidence` |

## Commands

Validate without network access:

```sh
go run ./cmd/evydence upload validate-manifest \
  --manifest .evydence/upload-manifest.json
```

Upload after validation:

```sh
go run ./cmd/evydence upload manifest \
  --url "$EVYDENCE_API_URL" \
  --api-key "$EVYDENCE_API_KEY" \
  --manifest .evydence/upload-manifest.json
```

The upload command validates the manifest again before sending requests. It does
not print the API key or raw payload bodies.

## Supported Evidence Flow

The manifest supports the release evidence path used by the GitHub and GitLab
examples:

- artifact registration through `/v1/artifacts`;
- CycloneDX or SPDX SBOM upload;
- generic vulnerability scan upload;
- OpenVEX or CycloneDX VEX upload;
- build provenance or attestation upload;
- approval records;
- release bundle creation;
- customer package export.

Scanner output remains evidence for review. It is not complete or authoritative
vulnerability coverage by itself.
