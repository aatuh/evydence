# Air-Gapped Installation

This is a how-to guide for offline or disconnected environments.

Prepare the package on a connected build host:

```sh
go build -o dist/evydence-api ./cmd/evydence-api
go build -o dist/evydence-worker ./cmd/evydence-worker
go build -o dist/evydence ./cmd/evydence
cp -R migrations openapi.yaml deploy/helm/evydence docs/air-gapped.md dist/
evydence release manifest --out dist/evydence-release-manifest.json dist/evydence-api dist/evydence-worker dist/evydence
evydence release keygen --private-out dist/release-private.key --public-out dist/release-public.key
evydence release sign --manifest dist/evydence-release-manifest.json --private-key dist/release-private.key --out dist/evydence-release-manifest.sig.json
```

Transfer only the package, public key, checksums, and signature through the approved media path. Do not transfer private signing keys into the target environment unless that is the controlled signing location.

Verify offline:

```sh
evydence release verify --manifest evydence-release-manifest.json --signature evydence-release-manifest.sig.json
```

For CI systems that cannot call the API, write an evidence bundle in CI, move it through the same controlled transfer process, then upload it from the connected side:

```sh
evydence import-bundle upload \
  --url "$EVYDENCE_API_URL" \
  --api-key "$EVYDENCE_API_KEY" \
  --path evidence-bundle.json
```

The package manifest at `deploy/airgap/manifest.yaml` lists expected package contents. It is not a backup and does not replace database, object-store, or key-management restore procedures.
