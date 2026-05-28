# Air-Gapped Installation

This is a how-to guide for offline or disconnected environments.

## Build The Package

Prepare the package on a connected build host:

```sh
go build -o dist/evydence-api ./cmd/evydence-api
go build -o dist/evydence-worker ./cmd/evydence-worker
go build -o dist/evydence ./cmd/evydence
cp -R migrations openapi.yaml deploy/helm/evydence docs/air-gapped.md dist/
./dist/evydence release manifest --out dist/evydence-release-manifest.json dist/evydence-api dist/evydence-worker dist/evydence
./dist/evydence release keygen --private-out dist/release-private.key --public-out dist/release-public.key
./dist/evydence release sign --manifest dist/evydence-release-manifest.json --private-key dist/release-private.key --out dist/evydence-release-manifest.sig.json
```

Expected package contents include:

- `evydence-api`
- `evydence-worker`
- `evydence`
- `migrations/`
- `openapi.yaml`
- `deploy/helm/evydence/`
- `docs/air-gapped.md`
- `evydence-release-manifest.json`
- `evydence-release-manifest.sig.json`
- `release-public.key`

The package manifest at `deploy/airgap/manifest.yaml` lists expected package contents. Keep it with release evidence.

## Transfer

Transfer only the package, public key, checksums, and signature through the approved media path. Do not transfer private signing keys into the target environment unless that environment is the controlled signing location.

Record transfer approvals, media handling, and hash verification as separate operational evidence where your process requires it.

## Verify Offline

Run the verifier from the transferred package directory. Use `./evydence` for the packaged binary unless your operating procedure installs the same binary as `evydence` on `PATH`.

```sh
./evydence release verify --manifest evydence-release-manifest.json --signature evydence-release-manifest.sig.json
```

Expected result: the command exits successfully and reports that the manifest signature and referenced artifact hashes verify.

Evidence bundles and audit-chain exports can also be checked without API access:

```sh
./evydence verify-evidence-bundle evidence-bundle.json
./evydence verify-audit-chain audit-chain.json
```

`verify-evidence-bundle` always checks the canonical manifest hash. If the bundle file includes `signature_refs`, `signatures`, and `signing_keys`, it also verifies an Ed25519 signature over the manifest hash. `verify-audit-chain` checks sequence continuity, previous-entry linkage, canonical entry hashes, and entry hashes. These checks validate the exported bytes and included public material; they do not contact external transparency logs or key-management systems.

## Import Evidence Bundles

For CI systems that cannot call the API, write an evidence bundle in CI, move it through the same controlled transfer process, then upload it from the connected side:

```sh
./evydence import-bundle upload \
  --url "$EVYDENCE_API_URL" \
  --api-key "$EVYDENCE_API_KEY" \
  --path evidence-bundle.json
```

Expected result: Evydence verifies and records the imported bundle manifest through the tenant-scoped API path.

Air-gapped package manifests are not backups and do not replace database, object-store, or key-management restore procedures. Pair package evidence with the backup guidance in [Production hardening review](production-hardening.md).
