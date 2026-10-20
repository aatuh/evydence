# Release Artifact Signing

This how-to is for release maintainers and operators verifying Evydence assets.
The trust policy is [`release/signing-policy.json`](../release/signing-policy.json).
It separates publisher identity from a signature's byte-integrity check.

## Current rollout status

EVY-1404 remains incomplete. After maintainer approval on 2026-10-20,
`release-production` was created with required reviewer `aatuh`, solo-maintainer
self-review permitted, and exactly one deployment branch policy: `master` of
type Branch. The live policy validator passed, and before/after provider reads
confirmed the existing master protection and rulesets were unchanged.

Both environment publisher-secret entries are still absent. The repository
release signing key and publication-token entries are retained until replacement
environment entries are confirmed. Full signing custody therefore remains
unverified. No new keyless release publication is established by this setup.

Existing public RC.7 assets and the historical container retain their original
assurance limits. New workflow/source identity requirements do not establish
that old artifacts were built under those controls.

## Verify public releases

Use a trusted checkout containing the signing policy and GitHub CLI with the
flags listed by `gh attestation verify --help`. The observed local CLI was
2.102.0 on 2026-10-20. New-format public releases use:

```sh
make public-release-verify TAG=<vX.Y.Z-rc.N>
```

Before extracting or executing a downloaded CLI, the helper authenticates the
manifest and signature file through their Sigstore attestation bundle, verifies
every manifest-listed file's size/digest, and checks checksums and evidence
subjects. The downloaded CLI receives a private home and minimal environment,
without the caller's GitHub, cloud or application credentials.

The certificate policy requires all of:

- repository `aatuh/evydence` and issuer
  `https://token.actions.githubusercontent.com`;
- exact identity
  `https://github.com/aatuh/evydence/.github/workflows/release-artifacts.yml@refs/heads/master`;
- source ref `refs/heads/master`, GitHub-hosted runners, and source/signer
  digests equal to the selected tag's commit;
- a source commit absent from the policy's `revoked_sources` list.

No wildcard identity or fallback to a self-selected signing key is allowed.
The policy uses the [GitHub CLI attestation verifier](https://cli.github.com/manual/gh_attestation_verify)
for certificate, signature and transparency verification. Builder predicate
fields alone are not a certificate identity.

The historical release requires explicit compatibility:

```sh
EVYDENCE_RELEASE_ALLOW_LEGACY_EVIDENCE=1 make public-release-verify TAG=v0.1.0-rc.7
```

This accepts only the committed repository/tag/commit, exact published manifest
SHA-256 and public-key fingerprint. The pins were read from the published
release on 2026-10-20; they are a reviewed bootstrap trust decision rather than
proof of historical protected signing. Changed bytes, keys or retargeted tags
fail. This path verifies historical content and its signature, without the new
artifact-bound SBOM or keyless workflow assurance.

## Configure protected publication

The maintainer must approve changes to GitHub settings and credentials. Prepare
`release-production` in repository **Settings → Environments** with:

- required reviewer `aatuh` (user ID `1116211`);
- self-review permitted for the documented solo-maintainer model;
- selected deployment branches: exactly `master`, type **Branch**; no tag or
  wildcard patterns.

This is a human approval gate, without an independent-review claim.
Administrators retain authority to edit provider settings; API observations
do not prove immutable governance or historical approval decisions.

After the approved environment exists, the account owner creates two publisher
tokens and enters them there:

1. For `EVYDENCE_RELEASE_PUBLISH_TOKEN`, create a
   [fine-grained token](https://github.com/settings/personal-access-tokens/new?name=Evydence%20release%20publisher&target_name=aatuh&expires_in=30&contents=write).
   Select **Only select repositories → aatuh/evydence** and **Contents → Read and
   write**, with a bounded expiration and recorded recovery owner. The link
   pre-fills the name, owner, 30-day lifetime and permission; repository selection
   still needs review in GitHub. The workflow uses an existing tag on the trusted
   master source. GitHub additionally requires Workflows write permission when a
   release target modifies workflows relative to the default branch; keep this
   profile's target on the current reviewed master source. See
   [release API permissions](https://docs.github.com/en/rest/releases/releases#create-a-release).
2. For `EVYDENCE_GHCR_PUBLISH_TOKEN`, create a
   [classic token with `write:packages`](https://github.com/settings/tokens/new?scopes=write:packages).
   Set a bounded expiration and confirm the intended package owner. This scope
   includes package reads; this profile does not need `repo` or `delete:packages`.
   GitHub's [container authentication guide](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)
   documents the scope-only link, which avoids the UI's automatic broad `repo`
   selection. Classic package-token access follows the account's package grants;
   it is not limited to one repository by a fine-grained repository selector.
3. Run these commands interactively in the owner's terminal. Each command prompts
   for its token; the value stays out of shell command arguments and history:

   ```sh
   gh secret set EVYDENCE_RELEASE_PUBLISH_TOKEN --repo aatuh/evydence --env release-production
   gh secret set EVYDENCE_GHCR_PUBLISH_TOKEN --repo aatuh/evydence --env release-production
   ```

GitHub Settings is an alternative entry path. Existing Actions secret values
cannot be retrieved through the API. Do not copy the operator's broad `gh` login
token into publication jobs. Review scope, expiration and recovery ownership
with the maintainer; the automated check sees secret names and custody locations,
not token values or their effective grants. No token-entry or publication success
is established by these instructions.

Once environment entries are confirmed, remove their repository-scoped copies
and retire `EVYDENCE_RELEASE_SIGNING_PRIVATE_KEY_B64` from repository Actions
secrets. New public workflows use per-run Ed25519 manifest keys and keyless
GitHub OIDC identity. Removing an Actions secret does not destroy other copies
of a private key or revoke a provider token. Do not send credential values in
chat, logs, PRs or evidence files.

Before dispatching publication, run:

```sh
make release-signing-policy-test
make release-signing-check
```

The first target is offline regression validation. The second additionally
reads real environment/reviewer/branch rules and secret inventories. Missing
provider access, a missing approval gate, root-scoped release credentials or
missing environment secrets fail the check; they are not skipped successes.

Keep the existing strict app-bound branch checks and protected release tags.
Qualify the candidate locally first, create the reviewed protected RC tag at
the current `master` commit, then dispatch **Release Artifacts** from protected
`master` with that tag. Tag-push execution and source/tag mismatches are rejected.
The package, attestation and publication jobs each enforce the protected
workflow context and read the live environment policy before proceeding.

Only the attestation job receives `id-token: write`, `attestations: write`
and `artifact-metadata: write`. Contents access stays read-only. Draft-release
publication uses its separate protected-environment token and preserves existing
assets. The keyless bundle is `evydence-release-attestations.sigstore.json`.

## Verify new container identities

Dispatch **Container Image** from protected `master`. Its selected source must
resolve to the same commit as the trusted workflow; checkout of arbitrary input
code before access to publication credentials is not supported.

For a new-profile image, supply its independently selected commit and digest:

```sh
cosign verify \
  --certificate-identity 'https://github.com/aatuh/evydence/.github/workflows/container-image.yml@refs/heads/master' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate-github-workflow-repository aatuh/evydence \
  --certificate-github-workflow-ref refs/heads/master \
  --certificate-github-workflow-sha "$EXPECTED_COMMIT" \
  --certificate-github-workflow-trigger workflow_dispatch \
  "ghcr.io/aatuh/evydence@sha256:$IMAGE_SHA256"
```

These options were checked against the existing pinned cosign v2.6.1 source.
A matching image label or producer JSON alone is insufficient. Historical
images require their own reviewed identity profile rather than a wildcard
that grants them the new protected-workflow assurance.

## Compromise and rotation

1. Stop release dispatches and disable affected signing/publication authority.
   Revoke exposed provider tokens in GitHub/registry settings, restrict the
   environment and restore protected-branch/tag controls without bypassing CI.
2. Preserve run IDs, artifact digests and certificate/transparency evidence.
   Do not overwrite published assets or rewrite their history.
3. Review and add compromised source commits to `revoked_sources`. Current
   verifiers reject them before provider verification or signing. If an entire
   workflow or issuer is untrusted, fail publication and revise the trusted
   policy through the normal reviewed path before accepting more artifacts.
4. Rotate publishing tokens into the protected environment, verify custody
   again and publish a newly reviewed tag/artifact set. Retired long-lived
   signing material must not be reintroduced as a fallback.
5. Update the trust policy and security advisory for consumers. Already signed
   transparency entries are not erased; consumers retaining an old policy may
   continue to trust them. Historical pin removal must also update the explicit
   legacy allowlist consistently.

Do not include token values, private keys or raw OIDC tokens in incident records.

## Local byte-integrity checks

These developer commands do not authenticate a public publisher:

```sh
go build -o dist/evydence ./cmd/evydence
./dist/evydence release manifest --out evydence-release-manifest.json dist/evydence-api dist/evydence-worker dist/evydence
./dist/evydence release keygen --private-out release-private.key --public-out release-public.key
./dist/evydence release sign --manifest evydence-release-manifest.json --private-key release-private.key --out evydence-release-manifest.sig.json
./dist/evydence release verify --manifest evydence-release-manifest.json --signature evydence-release-manifest.sig.json
```

Keep development keys outside Git and delete disposable keys after use. A
signature checked against its embedded public key proves byte consistency;
publisher trust requires the public verification profile above.

## Attestation dependency review

The official [actions/attest v4.2.2](https://github.com/actions/attest/tree/1e69f48acb82d1966a394da916b4c1698aa569d6)
is pinned to `1e69f48acb82d1966a394da916b4c1698aa569d6` (MIT). It has six direct
runtime dependencies in its committed package manifest. Upstream's latest
release was published on 2026-08-06; its published-advisory endpoint returned
zero entries at the 2026-10-20 review. That observation is not a vulnerability-free
claim. Version 4 of `attest-build-provenance` delegates to this action and
recommends it for new use. The existing GitHub CLI performs verification;
no new application Go crypto dependency is added. Review the action pin,
permissions, token exposure and verifier constraints together when updating it.

Attestations and matched signatures do not prove complete SBOM coverage, legal
compliance, certification, a SLSA level or a secure release.

For evidence exports, `./dist/evydence verify-evidence-bundle evidence-bundle.json`
checks the canonical hash and included signatures; `./dist/evydence
verify-audit-chain audit-chain.json` checks local chain continuity. They do not
replace the public publisher trust policy.
