# Release Artifact Signing

This is an operator how-to for Evydence release artifacts.

Create a release artifact manifest:

```sh
evydence release manifest --out evydence-release-manifest.json dist/evydence-api dist/evydence-worker dist/evydence
```

Generate a local Ed25519 keypair for development signing:

```sh
evydence release keygen --private-out release-private.key --public-out release-public.key
```

Sign and verify:

```sh
evydence release sign --manifest evydence-release-manifest.json --private-key release-private.key --out evydence-release-manifest.sig.json
evydence release verify --manifest evydence-release-manifest.json --signature evydence-release-manifest.sig.json
```

Production release signing should use controlled key custody and publish the manifest, signature, public key, and image digest references together. Verification proves that the manifest and listed artifact bytes match the signature; it does not prove that a deployment is secure.
