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

The result itself uses `verification-result.v2.0.0`. Cosign and provider
verification receipts have their own v2 schema versions while embedding the
same profile shape. The deprecated Cosign metadata route remains intentionally
limited because the current deployment does not provide a configured
cryptographic verifier and tenant trust policy.

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
