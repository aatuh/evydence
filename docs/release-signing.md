# Release Artifact Signing

This is an operator how-to for Evydence release artifacts.

The examples below use `./dist/evydence`, the CLI binary built from this checkout:

```sh
go build -o dist/evydence ./cmd/evydence
```

If your release environment installs the same binary on `PATH`, replace `./dist/evydence` with `evydence`.

Create a release artifact manifest:

```sh
./dist/evydence release manifest --out evydence-release-manifest.json dist/evydence-api dist/evydence-worker dist/evydence
```

Generate a local Ed25519 keypair for development signing:

```sh
./dist/evydence release keygen --private-out release-private.key --public-out release-public.key
```

Sign and verify:

```sh
./dist/evydence release sign --manifest evydence-release-manifest.json --private-key release-private.key --out evydence-release-manifest.sig.json
./dist/evydence release verify --manifest evydence-release-manifest.json --signature evydence-release-manifest.sig.json
```

Production release signing should use controlled key custody and publish the manifest, signature, public key, and image digest references together. Verification proves that the manifest and listed artifact bytes match the signature; it does not prove that a deployment is secure.

For Evydence evidence exports, use the same CLI for offline ledger checks:

```sh
./dist/evydence verify-evidence-bundle evidence-bundle.json
./dist/evydence verify-audit-chain audit-chain.json
```

Evidence-bundle verification checks the canonical manifest hash and, when the export includes `signature_refs`, `signatures`, and `signing_keys`, verifies an included Ed25519 signature over the manifest hash. Audit-chain verification checks local hash continuity for the exported chain. Neither command makes legal compliance, external transparency, or secure-release claims.
