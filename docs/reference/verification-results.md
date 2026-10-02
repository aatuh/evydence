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
| `POST /v1/verify` with an artifact signature | `artifact-signature-metadata.v1` | digest binding, signature material, cryptographic verification, identity policy, transparency proof | Deliberately limited metadata assessment; full Cosign verification uses its separate route. |
| `POST /v1/artifact-signatures/{id}/verify-cosign` | `cosign-full-verification.v1` | bundle syntax, subject digest, cryptographic signature, embedded Rekor proof, Fulcio trust root/certificate validity, keyless identity/issuer policy or configured public key | Explicit offline Sigstore verification; online-required requests are rejected, not downgraded. |
| `POST /v1/build-attestations/{id}/verify-signature` | `dsse-attestation-signature.v1` | DSSE PAE signature, configured root, payload type, SLSA predicate, registered subject digest, builder identity, and policy claims | Explicit offline Ed25519-root verification of a DSSE/in-toto Statement v1. Unsupported types are `not_verified`, never passed. |
| `GET /v1/merkle-batches/{id}/verify`, `POST /v1/verify` with `merkle_batch` | `merkle-checkpoint.v1` | covered sequence hashes, Merkle root, checkpoint signature | Local signed Merkle checkpoint; canonical entry contents and external log inclusion are not evaluated. |
| `POST /v1/public-transparency-log-entries/{id}/verify` | `transparency-inclusion-proof.v1` | leaf hash, inclusion path, root hash, tree size, checkpoint | Resource-level proof checks today; EVY-606 standardizes a profile-bearing receipt. |
| `POST /v1/object-retention-policies/{id}/verify` | `object-retention-provider-policy.v1` | object scope, retention mode, retention-until, legal hold | Resource-level provider-policy checks today; live provider evidence is required for a provider-truth claim. |
| `GET /v1/backup-manifests/{id}/verify`, `POST /v1/verify` with `backup_manifest` | `backup-manifest-consistency.v1` | recorded consistency checks, backup manifest presence | Replays recorded checks; does not freshly compare a state export, counts, or restore outcome. |
| `evydence verify customer-package` | `customer-package-manifest-integrity.v1` | manifest schema/hash, archive metadata, redaction, evidence bundle | Offline package integrity and redaction shape; not a manifest-signature claim. |
| `evydence release verify` | `release-artifact-manifest-signature.v1` | manifest schema, artifact hashes, manifest signature | Offline Ed25519 verification with a supplied public key; no live revocation claim. |

For a profile that requires online transparency or revocation evidence, network
failure cannot silently produce a `passed` result or downgrade to metadata-only
assessment. Offline success requires every root, bundle, proof, checkpoint, and
clock input specified by the profile. See
[ADR 0002](../adr/0002-cryptographic-trust-model.md) for the full decision,
threat boundaries, and migration rules.

## Merkle Batch Creation

`POST /v1/merkle-batches` in the PostgreSQL profile uses a focused command,
not the Ledger's tenant-state maps. Tenant-wide `keys:admin` authorization is
checked before reads; human actors also need a matching tenant grant. The
transaction captures chain count and sequence boundaries, rejects gaps and
empty hashes across the chain, and selects only the requested sequence/hash
pairs. Audit bodies and unrelated resources are not loaded. Omitted or zero
`from_sequence` means 1; omitted or zero `to_sequence` means the captured head.
Negative, inverted or incomplete ranges fail validation. Explicit JSON nulls
are rejected according to the existing non-nullable integer schema.

Selection is limited to 4096 leaves, 1 KiB per stored hash and 8 MiB encoded
sequence/hash material. Oversized ranges return conflict without partial
writes; a smaller explicit range can be selected from a longer chain. Tenant,
projection and audit-writer fences plus selected-row locks keep the range and
local signing-key selection stable through commit.

The existing Merkle algorithm and signature format are unchanged: odd levels
duplicate the final node, parent hashes use SHA-256 over the two hashes joined
by a newline, and the local Ed25519 signature covers the root string. The
highest-version active local key is selected, with ID ascending breaking ties.
Malformed, expired, future-valid, revoked or compromised selected keys fail
closed, without falling back to another active key. If no local key is active,
a new key at the next local version is prepared and committed with the
signature, batch and audit entry in one transaction. Generated transient
private bytes are cleared; persisted material retains the existing local-key
storage model, not a new encryption-at-rest or HSM guarantee. No outbox job is
created, and successful idempotent replay signs nothing again.

Creation signs **stored hashes**, not freshly recomputed canonical audit
contents. It does not assert chain integrity, provider verification or external
anchoring. Use the distinct verification profiles below for those local checks.
Historical batches are not rewritten. Explicit local-memory mode retains its
compatibility command; startup Ledger retirement remains EVY-905 work.

Source/test evidence: `internal/verification/app/merkle_creation.go`,
`internal/adapters/postgres/repositories/merkle_creation.go`,
`internal/adapters/postgres/repositories/merkle_signer.go`,
`internal/platform/wiring/merkle_creation_test.go` and
`internal/adapters/httpapi/merkle_creation_test.go`.

## Recorded External Transparency Checkpoints

`POST /v1/transparency-checkpoints` records an operator-supplied provider and
external ID or URL against a tenant-owned Merkle batch. In the PostgreSQL
profile, a focused command checks tenant-wide `keys:admin` authorization before
reading the selected batch's ID and root hash. It does not load leaf hashes,
signature references, audit bodies, keys or other tenant resources. Tenant and
batch share locks and the existing exclusive tenant projection fence keep that
root stable through checkpoint and audit commit, in audit-writer lock order.
Failed writes roll back both records; successful idempotent replay creates
neither record again. This operation retains its existing no-outbox behavior.

The timestamp hash is the existing normalized-JSON SHA-256 over `batch_id`,
`root_hash`, `provider`, `external_url` and `external_id`. State remains
`recorded`. No URL is fetched and no provider signature, timestamp, publication
or external inclusion proof is verified by this command. It is not a
verification receipt or evidence that a batch was externally anchored.

Inputs are trimmed, valid UTF-8 without NUL bytes, with a 1 KiB batch-ID limit
and a combined 1 MiB text budget. At least one external ID or URL is required;
either may be omitted or empty, but explicit JSON nulls are rejected in the
PostgreSQL path according to the non-nullable request schema. Selected stored
roots above 1 KiB or malformed text fail closed without partial writes. Local
memory shares input and hash construction policy through its compatibility
adapter. Historical checkpoint records and schema remain unchanged.

Source/test evidence: `internal/verification/app/transparency_checkpoint_commands.go`,
`internal/adapters/postgres/repositories/transparency_checkpoint.go`,
`internal/platform/wiring/transparency_checkpoint_commands_test.go` and
`internal/adapters/httpapi/transparency_checkpoint_commands_test.go`.

## Generic Subject Dispatch

In the PostgreSQL runtime profile, `POST /v1/verify` uses a closed dispatcher
composed from focused commands for `audit_chain`, `audit_chain_checkpoint`,
`audit_chain_release_manifest`, `evidence_item`, `release_bundle`,
`build_attestation`, `artifact_signature`, `merkle_batch` and `backup_manifest`.
The dispatcher checks actor identity and `verify:read` scope before selecting a
command. Each command retains its subject-specific resource authorization,
bounded durable reads, profile and atomic receipt/audit/outbox policy. It does
not resolve services dynamically or fall back to Ledger on an unknown type or
command failure. An authorized request for an unsupported type retains the
existing validation error (HTTP 400), without inspecting tenant content. Missing
or foreign IDs for supported types remain not found (HTTP 404).

Requests must be JSON objects with non-null string fields. `subject_id` may be
omitted or empty only for `audit_chain`; a nonempty ID for that type is rejected.
After trimming, type labels are limited to 64 bytes and IDs to 1 KiB, with valid
UTF-8 and no NUL bytes. Successful idempotent replay returns the stored response
without repeating verification. Failed generic POST verification rolls back
receipt, audit and outbox effects; the existing safe failed-idempotency marker
is separate from a verification receipt. Explicit local-memory mode retains
its compatibility path; this dispatch migration does not remove startup Ledger
construction or migrate other command routes.

Source/test evidence: `internal/verification/app/subject_verification.go`,
`internal/adapters/httpapi/subject_verification_test.go` and
`internal/platform/wiring/subject_verification_test.go`.

## Tenant-Scoped Backup-Manifest Generation

`POST /v1/backup-manifests` in the PostgreSQL profile uses a focused command
with tenant-wide `admin` authorization before reads; human actors need a tenant
grant. An empty JSON object (or omitted body) is accepted. Non-object bodies,
unknown fields and duplicate fields are rejected. The command creates
`backup-manifest.v2.0.0` with `tenant-relational-state.v1` state-hash semantics.
The response field layout and eight legacy resource-count names are unchanged.

The commitment covers the full declared tenant-owned relational metadata set in
[`backup_commitment_catalog.go`](../../internal/adapters/postgres/repositories/backup_commitment_catalog.go),
including evidence, decisions, releases, identity authorization metadata,
signing public metadata, existing manifests and audit records. It is not merely
a hash of counts or a chain head. One bounded SQL statement supplies one MVCC
view across all resources; rows stream into a digest without rebuilding tenant
maps. Tenant, projection and chain fences keep the audit view stable for fresh
canonical-chain and referenced-local-signature consistency checks. Failed
consistency observations remain failed in the generated manifest.

Credential hashes, private signing bytes, replay records, compatibility
`ledger_state`, cached `resource_index`, migration bookkeeping, worker
payloads/lease tokens/raw errors and raw VEX failure detail are explicitly
excluded. Replay records are excluded even when the enclosing HTTP transaction
has inserted its pending record. Raw object-store payload bytes are never read.
Other tenants' rows do not contribute. Known metadata may contain sensitive
tenant information; it contributes only to the digest, not response row copies.

SHA-256 covers newline-framed JSON: first the profile, tenant and ordered
resource/column declaration; then each `resource`, `key`, `row` record in byte
order. PostgreSQL serialization uses UTC timestamps; Go JSON serialization
sorts object keys and preserves decoded number spellings without float64
rounding. This is a profile-specific encoding, not RFC 8785/JCS. See
[`backup_commitment.go`](../../internal/verification/app/backup_commitment.go)
for the exact framing. Changing declared fields or identity/ownership rules
requires a new commitment profile.

Limits are 32768 total rows and 8 MiB encoded commitment material, including
framing and declarations. Oversized records or exhausted budgets return
conflict without a partial digest or manifest. Fresh audit inspection has its
separate 8 MiB budget. The captured view precedes this command's manifest and
audit append; those two records commit atomically with HTTP replay state, with
no outbox job. Successful replay performs no new hashing or writes.

Historical `backup-manifest.v1.0.0` records are not rewritten. Their hashes use
the old whole-instance Ledger snapshot encoding, excluding raw signing-private
bytes, and are not comparable to v2 tenant commitments. Explicit local-memory
mode retains that v1 compatibility path. Clients must inspect `schema_version`
and recorded limitations rather than assume identical hash scopes.

Neither version is a restorable backup, proof that a backup completed, or proof
of a successful restore. Operators still need synchronized database/object-store
backups and a restore rehearsal. Generation does not prove external anchoring.
The verification operation below continues to replay recorded checks; it does
not freshly reconstruct either state commitment.

Source/test evidence: `internal/verification/app/backup_generation.go`,
`internal/platform/wiring/backup_generation_test.go` and
`internal/adapters/httpapi/backup_generation_test.go`.

## Recorded Backup-Manifest Verification

`GET /v1/backup-manifests/{id}/verify` and `POST /v1/verify` with
`subject_type: backup_manifest` use `backup-manifest-consistency.v1`.
The receipt preserves the manifest's recorded `consistency_checks`, appends
passed `backup_manifest_present` with the recorded state hash, and requires
every emitted check name. Aggregation preserves failed/error facts and
incomplete states; it does not replace them with the presence check. An empty
recorded check list retains its historical presence-only receipt.

This operation **does not recompute the state hash, rehash an exported state,
compare current resource counts, reverify today's audit chain, or perform a
restore rehearsal**. A passed receipt means its recorded checks and presence
check passed, not that a current backup can be restored. The broader profile
catalog lists manifest/state/count checks for backup consistency; those names
do not create fresh observations in this legacy recorded-check receipt.
Fresh restore and storage-generation evidence must be obtained separately.

The PostgreSQL command requires tenant-wide `verify:read` before reading
content. Human product/release grants are insufficient. It selects only one
tenant-owned manifest's state hash and recorded checks, keeping the tenant and
manifest rows share-locked through atomic receipt, audit and outbox persistence.
It does not load resource-count maps, stored limitations, other manifests,
private keys or raw payloads. Limits are 4096 recorded checks and 8 MiB encoded
checks plus state hash; names are limited to 128 bytes, result labels to 64,
details and IDs/state hashes to 1 KiB. Malformed or oversized projections fail
closed with no receipt, not a truncated passing assessment.

Dedicated GET and direct verification persist completed negative receipts.
Failed generic POST verification rolls back; successful idempotent replay adds
no effects. Existing check names/order, profile strings, state-hash digest and
response/storage fields are unchanged. Explicit local-memory mode shares the
same recorded-check inspector and bounds. Backup generation uses a versioned
tenant commitment in PostgreSQL and retains v1 compatibility in local memory; no
historical record is rewritten here.

Source/test evidence: `internal/verification/app/backup_verification.go`,
`internal/adapters/postgres/repositories/backup_verification.go`,
`internal/platform/wiring/backup_verification_test.go` and
`internal/adapters/httpapi/backup_verification_test.go`.

## Full Audit Chain Verification

`GET /v1/audit-chain/verify` and `POST /v1/verify` with
`subject_type: audit_chain` use `audit-chain-integrity.v1`. The subject ID is
empty or omitted. Each recorded entry retains its tenant, schema, sequence,
previous-hash, canonical-hash, entry-hash and referenced-signature checks,
followed by the overall `audit_chain` check. Empty chains retain the single
overall integrity check. Profiles, check names and response shapes are unchanged.

The PostgreSQL command requires tenant-wide `verify:read`; human actors also
need a tenant grant. Product/release grants are insufficient. Authorization
precedes content reads. Existing exclusive per-tenant projection and audit
transaction fences hold a stable chain count/head while the reader loads pages
of at most 128 entries and only their referenced signed-object hashes, signatures
and public key lifecycle records. Selected rows remain share-locked. Audit
metadata is needed for v2 canonical hashing; unrelated tenant resources and
private signing material are not selected. Audit appends and worker projection
mutations for that tenant wait until this verification transaction ends.

The total selected content and accumulated check material each have an 8 MiB
budget. Oversized records, exhausted budgets, repeated/truncated pages, or an
inconsistent captured head/count return conflict without partial receipts; the
command never silently verifies a prefix. Recorded entry IDs and signed-object
coordinates/digests are bounded to 1 KiB; selected signature/public-key text to
16 KiB. Legitimate chains exceeding the synchronous budget are not assessed as
passed or partially verified by this command.

Versioned canonical hashing is shared with the legacy compatibility path.
`audit-chain-entry.v1.0.0` retains reconstruction of sub-microsecond timestamps
lost in PostgreSQL storage; v2 includes IDs, request/idempotency context and
metadata with microsecond timestamps. Referenced signatures bind to their
recorded tenant-owned release/evidence bundle, Merkle batch or signing operation
and use the existing valid-at-signing/compromise policy. No schema or historical
hash/receipt rewrite is performed.

Direct and dedicated GET verification persist completed failed receipts;
generic failed idempotent POST verification rolls back its enclosing transaction.
Successful POST replay creates no duplicate receipt, audit entry or job. Invalid
nonempty subject IDs and explicit JSON null fields are rejected before verifying.

Integrity of the currently recorded chain does not establish external publication
or detect truncation to a still-valid prefix without an independently trusted
checkpoint. The signed-checkpoint profiles are distinct assessments, and
transparency remains `not_evaluated` here. These limits and guarantees apply to
the focused PostgreSQL command; local-memory storage remains its explicit
compatibility path.

Source/test evidence: `internal/verification/app/audit_chain_hash.go`,
`internal/verification/app/audit_chain_verification.go`,
`internal/platform/wiring/audit_chain_verification_test.go` and
`internal/adapters/httpapi/audit_chain_verification_test.go`.

## Signed Merkle Audit-Chain Checkpoint Verification

`POST /v1/verify` with `subject_type: audit_chain_checkpoint` and a Merkle
batch ID uses `audit-chain-merkle-checkpoint.v1`, not `merkle-checkpoint.v1`.
In the PostgreSQL profile, this focused command first inspects the entire
current tenant chain using the canonical checks and bounds above. It then
requires `checkpoint_coverage`, `checkpoint_root` and `checkpoint_signature`.
The covered hashes must come from those same inspected pages and match the
batch's ordered leaves, entry count and root. The signature must bind to this
tenant's exact Merkle batch and satisfy historical signing-key validity.

An invalid or truncated sequence range returns failed `checkpoint_coverage`
after the full-chain checks, without root/signature checks, preserving the
existing receipt contract. Valid coverage does not excuse canonical tampering
elsewhere in the chain. The profile retains its empty payload digest and
explicit external-publication limitation; transparency is `not_evaluated`.

Tenant-wide `verify:read` authorization precedes content reads. Human actors
need a tenant grant, not a product/release grant. A transaction-scoped audit
writer fence and shared tenant, batch, audit and public signing-material locks
keep the checkpoint and full chain consistent until receipt, audit and outbox
effects commit. No private signing material or unrelated tenant payloads are
loaded. Full-chain input/check budgets and the separate 4096-leaf, 8 MiB
Merkle-material budget fail closed without a partial receipt. Failed generic
POST verification rolls back; successful idempotent replay adds no effects.

Existing response fields, profile, check names and persisted hashes remain
unchanged; no migration or historical rewrite is performed. Local-memory mode
retains its explicit compatibility implementation.

Source/test evidence: `internal/verification/app/merkle_checkpoint_verification.go`,
`internal/platform/wiring/merkle_checkpoint_verification_test.go` and
`internal/adapters/httpapi/merkle_checkpoint_verification_test.go`.

## Release-Manifest Audit-Chain Checkpoint Verification

`POST /v1/verify` with `subject_type: audit_chain_release_manifest` and a
release-bundle ID uses `audit-chain-release-manifest-checkpoint.v1`. The
PostgreSQL command checks the entire current tenant chain, then
`checkpoint_manifest_hash`, `checkpoint_signature` and `checkpoint_coverage`.
The normalized-JSON manifest hash and historically valid tenant signature must
bind to the selected release bundle. The signed manifest's `chain_checkpoint`
must contain an integer `sequence` and string `head_hash`; a positive sequence
must exist in the same inspected chain and match that entry's stored hash.
Missing, malformed, negative or truncated coverage fails. Sequence zero retains
its existing empty-range behavior. All three checkpoint checks remain in a
completed receipt even when coverage fails.

This is a tenant-wide assessment, including canonical entries beyond the
covered prefix. Human actors therefore require a tenant-wide `verify:read`
grant **before content reads** in the PostgreSQL profile. A release/product
grant alone no longer permits this assessment; ordinary release-bundle
signature verification remains resource-scoped. The explicit local-memory
compatibility path retains its legacy authorization behavior.

The audit writer fence and shared tenant, release/product, bundle, audit,
signature and public-key locks preserve one view through atomic receipt, audit
and outbox persistence. The full-chain limits above apply independently of the
8 MiB encoded bundle/signing projection limit and 4096-reference/signature/key
limits. Oversize data fails closed with no partial receipt. Private signing
material, unrelated products and other tenants' payloads are not loaded.
Successful idempotent replay adds no effects; failed generic POST verification
rolls back its enclosing transaction.

The existing profile, check names, manifest-hash payload digest, canonical hash
format and historical key policy are preserved; no schema or historical
record is rewritten. This detects a signed covered-head mismatch or deleted
tail, not external publication or third-party log inclusion. Transparency
remains `not_evaluated`; external review and trust-root selection remain
operator responsibilities.

Source/test evidence: `internal/verification/app/release_manifest_checkpoint.go`,
`internal/platform/wiring/release_manifest_checkpoint_test.go` and
`internal/adapters/httpapi/release_manifest_checkpoint_test.go`.

## Merkle Batch Verification

The `merkle-checkpoint.v1` profile requires all three checks:
`checkpoint_coverage`, `merkle_root` and `checkpoint_signature`. Covered hashes
must match the stored leaves in sequence order and count. The signed root must
match those leaves, and a referenced tenant signature must bind to this exact
batch with a signing key valid under its historical policy. This does not
rehash canonical audit contents; use the separate audit-chain integrity or
audit-chain checkpoint profiles for that assessment. External transparency-log
inclusion remains `not_evaluated`.

The PostgreSQL command authorizes tenant-wide `verify:read` before reading
batch data. Human actors need a tenant grant; unrelated product/release grants
are insufficient. Tenant, batch, covered audit rows and referenced signature/key
rows stay share-locked through atomic receipt, audit and outbox persistence.
It reads only covered sequence/hash pairs and public signing fields, not raw
audit metadata or private signing material.

Verification rejects rather than truncates batches/ranges above 4096 leaves,
reference/signature/key sets above 4096 records, or selected metadata above
8 MiB combined. IDs, leaf/root hashes and signing coordinates are limited to
1 KiB; signature/public-key text to 16 KiB. Oversized durable projections return
conflict without receipts. Invalid request IDs fail validation before subject
resolution. Existing profiles, check names, response fields and hash/signature
formats remain unchanged; no historical records or schemas are rewritten.

Direct and dedicated GET verification persist completed failed receipts and
return their checks. Failed generic idempotent POST verification rolls back its
enclosing transaction; successful POST replay returns the original result without
duplicate effects. The selected-range limit also applies to the shared inspector
used by explicit local-memory mode. Larger existing batches need a smaller
checkpoint for this profile; they are not silently assessed as partial ranges.

Source/test evidence: `internal/verification/app/merkle_verification.go`,
`internal/adapters/postgres/repositories/merkle_verification.go`,
`internal/platform/wiring/merkle_verification_test.go` and
`internal/adapters/httpapi/merkle_verification_test.go`.

## Artifact Signature Recording

`POST /v1/artifact-signatures` in the PostgreSQL profile uses a focused command,
not Ledger maps. `evidence:write` scope is checked before data access. A human
session additionally needs a tenant grant or a product/project/release grant
covering a current evidence or build association with the artifact. The grant
query uses the command transaction and returns only identity and visibility;
large artifact names and association lists are not copied into the command.
The current tenant and artifact digest remain share-locked through persistence.
Foreign and missing artifacts return not found before payload staging.

The record retains `artifact-signature.v1.0.0` and `recorded` status. Any
non-empty algorithm and detached signature text can be recorded; this is not
cryptographic verification or a trust-root decision. IDs are limited to 1024
bytes, algorithm/signature text to 64 KiB, and payload media type to 4096 bytes.
Invalid UTF-8, embedded NUL and blank required text are rejected. The HTTP
request keeps its existing 64 KiB JSON-envelope limit; optional `payload` must
be an object. Explicit nulls, duplicate fields and unknown envelope fields
are rejected. Direct application payloads have the existing 20 MiB evidence
document ceiling; this does not enlarge the HTTP envelope limit.

Optional payload bytes are hashed and staged through the shared object-ingestion
boundary, which checks tenant, digest, byte count, media type, canonical keys,
creation time and staged status returned by storage. No private signing key is
read or generated. Signature metadata, staged lifecycle metadata, a deduplicated
`finalize_payload` job and the artifact-digest audit append commit atomically
with HTTP replay state. Successful replay does not restage or append records.
Without a payload there is no lifecycle record or finalization job. The worker
performs verified, repeatable finalization separately.

A failed database transaction can leave staged bytes without metadata; the
existing payload reconciliation procedure handles these provider orphans.
Staging does not prove finalization, trusted signature validity, certificate
identity, transparency inclusion or successful release verification. Explicit
local-memory mode retains its compatibility path; historical records are not
rewritten.

Source/test evidence: `internal/verification/app/artifact_signature_commands.go`,
`internal/platform/wiring/artifact_signature_commands_test.go`,
`internal/app/object_staging_test.go` and
`internal/adapters/httpapi/artifact_signature_commands_test.go`.

## Artifact Signature Metadata Assessment

`POST /v1/verify` with `subject_type: artifact_signature` assesses recorded
digest binding and the presence of algorithm/signature metadata. It preserves
the five required checks of `artifact-signature-metadata.v1`; the cryptographic,
certificate-identity and transparency checks are not performed. Matching
metadata therefore returns `limited`, not `passed`. Missing signature/algorithm
metadata or mismatched digests produces `failed`. Non-empty arbitrary signature
text does not establish cryptographic validity. Use the separate full Cosign
route for an explicit offline configured-trust verification.

The PostgreSQL-profile command checks `verify:read` and a human actor's tenant
grant before reading assessment facts. An unrelated product/release grant is
insufficient because artifacts have no such authorization coordinate. Selected
tenant/artifact/signature rows stay share-locked until receipt, audit and outbox
effects commit together. The projection reads only digest labels and presence
flags, never raw signature bytes, algorithm text, payload references, provider
data or private keys. Selected IDs and digest labels above 1 KiB fail closed
with conflict rather than being truncated. Invalid/oversized request IDs fail
validation before resolving the stored subject.

Direct completed negative assessments persist their receipts and return the
verification failure. Failed idempotent HTTP commands roll back their enclosing
transaction; successful replay returns the original assessment without duplicate
effects. Local-memory inspection uses the same core policy through its explicit
compatibility path. Profiles, check names and response fields remain unchanged;
no schema migration or historical receipt rewrite is performed.

Source/test evidence: `internal/verification/app/artifact_signature_verification.go`,
`internal/adapters/postgres/repositories/artifact_signature_verification.go`,
`internal/platform/wiring/artifact_signature_verification.go`,
`TestPostgresArtifactSignatureVerificationIsDurableMetadataOnly` and
`TestArtifactSignatureVerificationHandlerUsesDurableMetadataAndReplay`.

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
