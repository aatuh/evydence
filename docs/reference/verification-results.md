# Verification Results And Assurance Profiles

Verification APIs return versioned results describing the checks that were
actually evaluated. They organize technical evidence for review; they do not
make a legal compliance conclusion, grant certification, prove an SBOM is
complete, treat a scanner as authoritative, or guarantee a secure release.

## Machine Result States

| State | Meaning |
| --- | --- |
| `passed` | Every check required by the result's assurance profile is present and recorded as `passed`. |
| `failed` | At least one required check recorded `failed`. |
| `not_verified` | No complete assurance profile or evaluation evidence was recorded. |
| `limited` | A required check is absent, warning, unknown, or otherwise not a clean pass; mixed passed/skipped checks are also limited. |
| `skipped` | Every required check was deliberately recorded as `skipped`. |
| `error` | Evaluation of at least one required check recorded an error. |

`error` takes precedence over `failed`, and `failed` takes precedence over a
missing or limited check. This prevents a partial result from hiding a known
failure. The result calculation is deterministic: profile check names and
profile lists are normalized before the required checks are evaluated.

A `passed` result is forbidden when any profile-required check is missing,
warning, skipped, unknown, or errored. Individual check values may retain
additional diagnostic states such as `warning`; those values conservatively
produce `limited` unless a higher-priority `failed` or `error` is present.

## Assurance Profile

Every current result carries a profile with
`verification-profile.v1.0.0` semantics. Its fields are:

| Field | Meaning |
| --- | --- |
| `id`, `version` | Stable profile identity and profile schema version. |
| `required_checks` | The exact checks that must pass before the result can be `passed`. |
| `trust_material` | Non-secret identifiers or classes of trust material evaluated, never trust-root bytes or credentials. |
| `identity_policy` | The identity binding or policy that was evaluated, if any. |
| `transparency_proof` | Whether and how inclusion/proof treatment was evaluated. |
| `payload_scope`, `payload_digest` | The payload fields or digest evaluated; payload bytes are not copied into the profile. |
| `limitations` | Scope boundaries and evidence gaps that remain after the evaluation. |

The result itself uses `verification-result.v2.0.0`. Cosign receipts use
`cosign-verification.v3.0.0` and additionally record safe verifier-library,
trust-root-version, and verification-mode values while embedding the same
profile shape. They never store raw bundles, certificates, public keys, or
trust-root bytes.

## Named Verification Profiles and Endpoint Mapping

The code-owned registry in
[`internal/domain/verification_profiles.go`](../../internal/domain/verification_profiles.go)
defines each named profile's canonical input, hash and signature algorithm,
trusted root, identity and issuer policy, transparency, clock, revocation,
required offline inputs, and mandatory/optional checks. Those inputs are never
inferred from submitted metadata.

| Operation | Named profile | Required checks | Current outcome boundary |
| --- | --- | --- | --- |
| `POST /v1/verify` with `audit_chain` | `audit-chain-integrity.v1` | tenant scope, sequence continuity, previous hash link, canonical entry hash | Local append-only-chain integrity; no external anchoring claim. |
| `POST /v1/verify` with `audit_chain_checkpoint` | `audit-chain-merkle-checkpoint.v1` | checkpoint range, Merkle root, checkpoint signature | Local signed checkpoint over its sequence range. |
| `POST /v1/verify` with `audit_chain_release_manifest` | `audit-chain-release-manifest-checkpoint.v1` | checkpoint range, release manifest hash, checkpoint signature | Local release-manifest checkpoint; no publication claim. |
| `POST /v1/verify` with `evidence_item` | `evidence-canonical-hash.v1` | canonical hash | Canonical evidence fields only, not origin or completeness. |
| `POST /v1/verify` or `POST /v1/release-bundles/{id}/verify` with a release bundle | `release-bundle-signature.v1` | manifest hash, bundle signature | Tenant-signing receipt over the canonical manifest hash. |
| `POST /v1/verify` with an artifact signature | `artifact-signature-metadata.v1` | digest binding, signature material, cryptographic verification, identity policy, transparency proof | Deliberately limited metadata assessment until EVY-602. |
| `POST /v1/artifact-signatures/{id}/verify-cosign` | `cosign-full-verification.v1` | bundle syntax, subject digest, cryptographic signature, embedded Rekor proof, Fulcio trust root/certificate validity, keyless identity/issuer policy or configured public key | Explicit offline Sigstore verification; online-required requests are rejected, not downgraded. |
| `POST /v1/build-attestations/{id}/verify-signature` | `dsse-attestation-signature.v1` | DSSE signature | Current Ed25519 decoded-payload/root check only; EVY-603 adds DSSE PAE and in-toto policy. |
| `POST /v1/merkle-batches/{id}/verify` | `merkle-checkpoint.v1` | Merkle root, checkpoint signature | Local signed Merkle checkpoint; external log inclusion is not evaluated. |
| `POST /v1/public-transparency-log-entries/{id}/verify` | `transparency-inclusion-proof.v1` | leaf hash, inclusion path, root hash, tree size, checkpoint | Resource-level proof checks today; EVY-606 standardizes a profile-bearing receipt. |
| `POST /v1/object-retention-policies/{id}/verify` | `object-retention-provider-policy.v1` | object scope, retention mode, retention-until, legal hold | Resource-level provider-policy checks today; live provider evidence is required for a provider-truth claim. |
| `POST /v1/backup-manifests/{id}/verify` | `backup-manifest-consistency.v1` | manifest hash, state hash, resource counts | Local backup consistency; a restore rehearsal is separate optional evidence. |
| `evydence verify customer-package` | `customer-package-manifest-integrity.v1` | manifest schema/hash, archive metadata, redaction, evidence bundle | Offline package integrity and redaction shape; not a manifest-signature claim. |
| `evydence release verify` | `release-artifact-manifest-signature.v1` | manifest schema, artifact hashes, manifest signature | Offline Ed25519 verification with a supplied public key; no live revocation claim. |

For a profile that requires online transparency or revocation evidence, network
failure cannot silently produce a `passed` result or downgrade to metadata-only
assessment. Offline success requires every root, bundle, proof, checkpoint, and
clock input specified by the profile. See
[ADR 0002](../adr/0002-cryptographic-trust-model.md) for the full decision,
threat boundaries, and migration rules.

## Persistence And Legacy Records

Migration `20260722000100_verification_assurance_taxonomy` adds the profile,
limitations, and result-schema fields to generic verification results and the
profile fields to Cosign and provider receipts. It preserves each historical
record while assigning an explicit legacy profile and limitation.

Legacy `passed` values without a recorded assurance profile are migrated to
`limited`; stored `failed` and `error` values remain unchanged. This is a
conservative compatibility mapping, not a re-evaluation of historical
evidence. The original record identity, subject, checks, and timestamp remain
intact.

## Customer Packages

Customer package manifests include release-scoped verification summaries in
`verification_material` when such results exist. Each summary carries the
result, checks, profile, limitations, and schema version so a reviewer can see
what was and was not evaluated. Package redaction excludes raw payloads,
signature bytes, tokens, private keys, and trust-root material. Refer to the
[customer package manifest](customer-package-manifest.md) for the manifest
shape and exclusion rules.
