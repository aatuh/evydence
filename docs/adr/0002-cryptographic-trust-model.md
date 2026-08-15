# ADR 0002: Cryptographic Trust Model and Verification Profiles

- Status: accepted
- Date: 2026-08-15
- Decision owners: Evydence maintainers

## Context

Evydence stores high-trust technical evidence. A digest, parsed document, or
recorded signature is useful evidence, but it is not automatically proof that
the bytes were signed by a permitted identity, that a provider was trusted, or
that a transparency log included the statement. Those are separate claims with
different inputs and failure modes.

The product needs a durable way to state exactly what a verification receipt
means across API responses, customer packages, offline commands, parser and
schema upgrades, key rotation, and unavailable providers. The previous receipt
shape carried required checks but did not provide one registry of named
profiles and their cryptographic policy inputs.

## Decision

Every verification result is interpreted through a named profile. The stable
profile IDs and their required and optional checks live in
[`internal/domain/verification_profiles.go`](../../internal/domain/verification_profiles.go).
The result taxonomy and endpoint mapping are maintained in
[`docs/reference/verification-results.md`](../reference/verification-results.md).

A profile specifies all of the following, even when its value is explicitly
`not evaluated`:

- canonical bytes or structured inputs;
- hash and signature algorithms;
- trusted-root source and versioning expectations;
- identity and issuer policy;
- transparency, clock, and revocation behavior; and
- exact offline inputs and limitations.

`passed` is a narrow machine result: every required check in the named profile
must be present and recorded as `passed`. It is not a synonym for "secure",
"trusted", complete, or a legal conclusion for a particular regulator. A
structurally parsed document, a matching digest, and a recorded
signature are each distinct from cryptographic validity and identity trust.

### Assurance layers

Receipts distinguish four layers rather than combining them in one status:

| Layer | Meaning | Does not establish |
| --- | --- | --- |
| Recorded metadata | Fields, identifiers, or signature material were persisted. | That bytes, signer, root, or log proof are valid. |
| Cryptographically valid | The declared algorithm verified the exact profile input with a permitted key or certificate chain. | That the signer is an allowed workload or organization. |
| Identity trusted | A cryptographically valid identity satisfies the profile's caller-supplied identity and issuer policy. | That a transparency proof or revocation check was valid. |
| Transparency verified | The profile-required inclusion proof and checkpoint validate against the configured log root. | That the log operator, provider, or release is independently trustworthy. |

No layer can be inferred from a later layer's metadata. For example, a
certificate identity copied from a signature record does not satisfy an
identity policy until it has been recovered from a verified certificate and
compared to an expectation supplied by the caller or tenant policy.

### Canonical payloads

| Subject | Profile input | Current verification boundary |
| --- | --- | --- |
| Evidence item | Versioned canonical evidence fields | Recomputes the stored canonical SHA-256; it does not establish origin or completeness. |
| Audit-chain entry and checkpoint | Versioned entry canonical form; ordered entry hashes and root | Verifies local continuity, hashes, and configured tenant signatures. A local checkpoint is not external publication. |
| Release bundle | Canonical JSON manifest and its SHA-256 | Verifies the manifest hash and the tenant-signing receipt over that hash. |
| Artifact signature | OCI/artifact subject digest and detached-signature material | The current metadata profile is deliberately limited until Sigstore/Cosign policy verification is implemented. |
| DSSE attestation | Current v1: decoded envelope payload | Current code checks Ed25519 over the decoded payload against an active tenant root. It does **not** yet evaluate DSSE PAE, in-toto policy, builder identity, or historical root validity. |
| Merkle/public-log proof | Ordered leaf and proof hashes, root, tree size, checkpoint | Local Merkle verification and configured public-log proof verification have separate profiles. |
| Customer package | Package manifest JSON, archive member hashes, and optional bundle | Offline verification checks integrity and redaction shape; it does not currently require a package-manifest signature. |
| Release artifact manifest | Canonical manifest JSON, artifact hashes, and detached release signature | The CLI verifier uses an explicitly supplied public key; it has no live revocation source. |

### Trust inputs and failure policy

- Trust roots are operator- or tenant-configured references. Receipts record
  non-secret identifiers and versions, never private keys, bearer tokens, raw
  trust-root material, or unredacted payload bytes.
- An identity or issuer expectation must be supplied by a tenant policy or the
  caller. A value copied from the submitted signature, certificate, or provider
  metadata is not an expectation.
- Profiles that require transparency verification fail closed when the required
  proof, checkpoint, configured root, or network evidence is unavailable. They
  may not silently become metadata-only or offline profiles.
- Offline verification succeeds only when every input named by that profile's
  offline policy is supplied. Missing network evidence is reported as a
  limitation or failure according to the profile; it is never silently
  accepted.
- A historical-validity claim needs the key/certificate version, its validity
  interval, and revocation evidence applicable at the verification time. An
  active key today is not proof that it was valid when old evidence was signed.

### Algorithm agility and migrations

Profile IDs are immutable once published. New canonicalization, hash,
signature, trust-root, identity, transparency, clock, or revocation semantics
require a new profile version. New receipts use that version; historical
receipts retain their recorded profile and result. Reinterpretation is an
append-only new verification receipt linked to the original subject, never an
in-place edit of historical evidence.

Deprecating an algorithm means: stop issuing new receipts with its profile,
retain the old verifier and test vectors for historical inspection while
supported, document the end-of-support date, and return `limited`, `failed`,
or `not_verified` when the required historical material is unavailable. It
does not silently relabel prior results as a newer profile.

## Endpoint mapping

The current route-to-profile mapping is part of the verification reference.
Routes that return a generic verification result embed the named profile.
Object-retention and public-transparency endpoints currently persist their
checks on resource records; their named profile defines the mandatory semantics
that EVY-606 will standardize into durable verification receipts.

## Threat boundaries and non-goals

This decision covers the tenant caller, API, durable receipt store, object
storage payload, signing-key or trust-root configuration, external issuer,
transparency log, and local offline verifier boundaries. Tenant authorization
is evaluated before a result is read or created; verification does not widen
access to raw evidence, private keys, provider tokens, or trust material.

It does not claim that a privileged database administrator cannot rewrite all
local data and keys; that a local checkpoint proves third-party publication;
that provider metadata proves provider identity; that parsed evidence is
complete or authoritative; or that a receipt proves compliance, certification,
regulator acceptance, or a secure release.

## Consequences

Future Sigstore/Cosign, DSSE/in-toto, signing-provider, key-history, and
transparency work must use a named profile and produce check-level receipts.
It must reject ambiguous or missing policy inputs rather than infer them from
the uploaded material. Test vectors must cover invalid signature, wrong
subject, identity, issuer, clock, revocation, and required-proof cases where
those checks apply.
