package domain

// Named verification profiles are stable identifiers for the exact assurance
// boundary a receipt represents. The definitions intentionally describe both
// implemented and limited assessments; a profile does not by itself turn a
// recorded value into cryptographic or identity trust.
const (
	VerificationProfileAuditChainIntegrity        = "audit-chain-integrity.v1"
	VerificationProfileAuditChainMerkleCheckpoint = "audit-chain-merkle-checkpoint.v1"
	VerificationProfileAuditChainReleaseManifest  = "audit-chain-release-manifest-checkpoint.v1"
	VerificationProfileEvidenceCanonicalHash      = "evidence-canonical-hash.v1"
	VerificationProfileReleaseBundleSignature     = "release-bundle-signature.v1"
	VerificationProfileArtifactSignatureMetadata  = "artifact-signature-metadata.v1"
	VerificationProfileCosignFull                 = "cosign-full-verification.v1"
	VerificationProfileDSSEAttestationSignature   = "dsse-attestation-signature.v1"
	VerificationProfileMerkleCheckpoint           = "merkle-checkpoint.v1"
	VerificationProfileTransparencyInclusion      = "transparency-inclusion-proof.v1"
	VerificationProfileObjectRetention            = "object-retention-provider-policy.v1"
	VerificationProfileBackupManifest             = "backup-manifest-consistency.v1"
	VerificationProfileCustomerPackageManifest    = "customer-package-manifest-integrity.v1"
	VerificationProfileReleaseArtifactManifest    = "release-artifact-manifest-signature.v1"
)

// VerificationProfileDefinition fixes the non-secret policy inputs needed to
// interpret a named verification receipt. It is domain policy, not a source of
// trust-root bytes, credentials, or raw payloads.
type VerificationProfileDefinition struct {
	ID                 string
	Version            string
	RequiredChecks     []string
	OptionalChecks     []string
	Canonicalization   string
	HashAlgorithm      string
	SignatureAlgorithm string
	TrustRootPolicy    string
	IdentityPolicy     string
	IssuerPolicy       string
	TransparencyPolicy string
	ClockPolicy        string
	RevocationPolicy   string
	OfflinePolicy      string
}

var verificationProfileDefinitions = []VerificationProfileDefinition{
	{ID: VerificationProfileAuditChainIntegrity, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"tenant_scope", "sequence_continuity", "previous_hash_link", "canonical_entry_hash"}, OptionalChecks: []string{"entry_signature"}, Canonicalization: "audit-chain-entry canonicalization version recorded on each entry", HashAlgorithm: "SHA-256", SignatureAlgorithm: "entry signature algorithm recorded by signing provider", TrustRootPolicy: "tenant signing key referenced by the entry when a signature exists", IdentityPolicy: "caller is authorized for the tenant audit chain", IssuerPolicy: "not applicable", TransparencyPolicy: "not evaluated", ClockPolicy: "entry timestamps are normalized to their recorded schema semantics", RevocationPolicy: "key status is evaluated only when an entry signature is checked", OfflinePolicy: "all required audit-chain data is local"},
	{ID: VerificationProfileAuditChainMerkleCheckpoint, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"checkpoint_range", "merkle_root", "checkpoint_signature"}, OptionalChecks: []string{"external_publication"}, Canonicalization: "ordered audit-chain entry hashes for the checkpoint sequence range", HashAlgorithm: "SHA-256 Merkle tree", SignatureAlgorithm: "tenant signing-provider algorithm on the root hash", TrustRootPolicy: "historically valid tenant signing key", IdentityPolicy: "caller is authorized for the tenant audit chain", IssuerPolicy: "tenant signing-provider configuration", TransparencyPolicy: "external publication is not evaluated", ClockPolicy: "checkpoint timestamp is informational; key validity is evaluated at signature time when available", RevocationPolicy: "revoked keys do not satisfy a current signature check unless historical validity is explicitly supported", OfflinePolicy: "local checkpoint and signing receipt are sufficient"},
	{ID: VerificationProfileAuditChainReleaseManifest, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"checkpoint_range", "release_manifest_hash", "checkpoint_signature"}, OptionalChecks: []string{"external_publication"}, Canonicalization: "canonical release-bundle manifest hash and covered audit-chain range", HashAlgorithm: "SHA-256", SignatureAlgorithm: "tenant signing-provider algorithm on the checkpoint payload", TrustRootPolicy: "historically valid tenant signing key", IdentityPolicy: "caller is authorized for the release scope", IssuerPolicy: "tenant signing-provider configuration", TransparencyPolicy: "external publication is not evaluated", ClockPolicy: "recorded checkpoint time is compared to available key validity evidence", RevocationPolicy: "historical key status must be retained for a historical-validity claim", OfflinePolicy: "local release bundle, checkpoint, and receipt are sufficient"},
	{ID: VerificationProfileEvidenceCanonicalHash, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"canonical_hash"}, OptionalChecks: []string{"payload_digest"}, Canonicalization: "evidence-item canonicalization profile recorded on the item", HashAlgorithm: "SHA-256", SignatureAlgorithm: "not evaluated", TrustRootPolicy: "not applicable", IdentityPolicy: "caller is authorized for the evidence scope", IssuerPolicy: "not applicable", TransparencyPolicy: "not evaluated", ClockPolicy: "not evaluated", RevocationPolicy: "not applicable", OfflinePolicy: "local evidence fields are sufficient"},
	{ID: VerificationProfileReleaseBundleSignature, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"manifest_hash", "bundle_signature"}, OptionalChecks: []string{"audit_chain_checkpoint", "external_publication"}, Canonicalization: "canonical JSON release-bundle manifest", HashAlgorithm: "SHA-256", SignatureAlgorithm: "tenant signing-provider algorithm over the manifest hash", TrustRootPolicy: "historically valid tenant signing key", IdentityPolicy: "caller is authorized for the release scope", IssuerPolicy: "tenant signing-provider configuration", TransparencyPolicy: "external publication is not evaluated", ClockPolicy: "signature time is compared with available key validity evidence", RevocationPolicy: "historical key status must be retained for a historical-validity claim", OfflinePolicy: "local manifest and signing receipt are sufficient"},
	{ID: VerificationProfileArtifactSignatureMetadata, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"digest_binding_assessed", "signature_material_present", "cryptographic_signature_verified", "certificate_identity_policy", "transparency_inclusion_proof"}, OptionalChecks: []string{"rekor_metadata_present"}, Canonicalization: "artifact subject digest and recorded detached signature metadata", HashAlgorithm: "SHA-256 subject digest format", SignatureAlgorithm: "recorded only; not cryptographically evaluated", TrustRootPolicy: "not evaluated", IdentityPolicy: "not evaluated", IssuerPolicy: "not evaluated", TransparencyPolicy: "not evaluated", ClockPolicy: "not evaluated", RevocationPolicy: "not evaluated", OfflinePolicy: "metadata may be inspected locally but cannot establish signature validity"},
	{ID: VerificationProfileCosignFull, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"sigstore_bundle", "subject_digest", "cryptographic_signature", "rekor_inclusion_proof", "fulcio_trust_root", "certificate_validity", "certificate_identity_policy"}, OptionalChecks: []string{"trusted_public_key", "trust_root_version", "sigstore_library"}, Canonicalization: "OCI artifact digest and exact Sigstore bundle", HashAlgorithm: "SHA-256 OCI subject digest", SignatureAlgorithm: "algorithm encoded by the verified Sigstore bundle", TrustRootPolicy: "operator or tenant configured Fulcio and public-key roots with recorded version", IdentityPolicy: "caller-supplied expected identity is matched against verified certificate identity for keyless verification", IssuerPolicy: "caller-supplied expected issuer is matched against verified certificate issuer for keyless verification", TransparencyPolicy: "the offline profile verifies embedded Rekor inclusion proof and observer timestamp; online-required requests are rejected rather than downgraded", ClockPolicy: "certificate and checkpoint times are evaluated at the signed observer timestamp", RevocationPolicy: "not established by the current offline bundle profile unless the configured trust material supplies explicit revocation semantics", OfflinePolicy: "only a complete offline bundle and configured roots may satisfy the implemented profile"},
	{ID: VerificationProfileDSSEAttestationSignature, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"dsse_signature"}, OptionalChecks: []string{"payload_digest", "predicate_type", "subject_digest", "builder_identity"}, Canonicalization: "decoded DSSE envelope payload in the current v1 implementation; DSSE PAE is not yet evaluated", HashAlgorithm: "SHA-256 payload digest when recorded", SignatureAlgorithm: "Ed25519 against an active tenant DSSE root in the current v1 implementation", TrustRootPolicy: "active tenant DSSE Ed25519 roots", IdentityPolicy: "DSSE key identifier matches a configured tenant root", IssuerPolicy: "not evaluated", TransparencyPolicy: "not evaluated", ClockPolicy: "not evaluated", RevocationPolicy: "only active roots are accepted; historical validity is not established", OfflinePolicy: "configured tenant root and stored envelope are required"},
	{ID: VerificationProfileMerkleCheckpoint, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"merkle_root", "checkpoint_signature"}, OptionalChecks: []string{"external_publication"}, Canonicalization: "ordered Merkle leaf hashes and root hash", HashAlgorithm: "SHA-256 Merkle tree", SignatureAlgorithm: "tenant signing-provider algorithm on the root hash", TrustRootPolicy: "historically valid tenant signing key", IdentityPolicy: "caller is authorized for the tenant scope", IssuerPolicy: "tenant signing-provider configuration", TransparencyPolicy: "external transparency-log inclusion is not evaluated", ClockPolicy: "signature time is compared with available key validity evidence", RevocationPolicy: "historical key status must be retained for a historical-validity claim", OfflinePolicy: "local batch and signing receipt are sufficient"},
	{ID: VerificationProfileTransparencyInclusion, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"leaf_hash", "inclusion_path", "root_hash", "tree_size", "checkpoint"}, OptionalChecks: []string{"log_key_signature", "network_fetch"}, Canonicalization: "RFC 6962-style leaf and proof hash inputs recorded by the log adapter", HashAlgorithm: "hash algorithm declared by the configured transparency log", SignatureAlgorithm: "configured public-log checkpoint signature algorithm", TrustRootPolicy: "operator-configured public-log key and endpoint identity", IdentityPolicy: "entry is bound to the requested tenant-scoped subject", IssuerPolicy: "configured public-log operator identity", TransparencyPolicy: "inclusion proof and checkpoint are required", ClockPolicy: "checkpoint time must be recorded and evaluated by the configured log policy", RevocationPolicy: "log-key rotation and revocation evidence must be retained by the operator", OfflinePolicy: "offline verification requires the leaf, inclusion path, checkpoint, and configured log key"},
	{ID: VerificationProfileObjectRetention, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"object_scope", "retention_mode", "retention_until", "legal_hold"}, OptionalChecks: []string{"provider_policy_identifier", "provider_observed_at"}, Canonicalization: "tenant-prefixed object key and persisted retention-policy fields", HashAlgorithm: "SHA-256 verification hash when a provider receipt supplies one", SignatureAlgorithm: "not evaluated unless provider receipt supplies one", TrustRootPolicy: "operator-configured object-storage provider credentials and endpoint", IdentityPolicy: "policy object and provider object must be tenant scoped", IssuerPolicy: "configured object-storage provider", TransparencyPolicy: "not applicable", ClockPolicy: "provider observation must be within the policy maximum verification age", RevocationPolicy: "not applicable", OfflinePolicy: "offline mode cannot establish live provider retention state"},
	{ID: VerificationProfileBackupManifest, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"manifest_hash", "state_hash", "resource_counts"}, OptionalChecks: []string{"restore_rehearsal", "object_store_generation_match"}, Canonicalization: "canonical backup manifest and persisted state hash", HashAlgorithm: "SHA-256", SignatureAlgorithm: "not evaluated unless a separate manifest signature exists", TrustRootPolicy: "not applicable", IdentityPolicy: "caller is authorized for the tenant backup scope", IssuerPolicy: "not applicable", TransparencyPolicy: "not evaluated", ClockPolicy: "manifest generation time and retention policy are recorded", RevocationPolicy: "not applicable", OfflinePolicy: "local manifest and state export are sufficient for consistency, not restore proof"},
	{ID: VerificationProfileCustomerPackageManifest, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"manifest_schema", "manifest_hash", "archive_metadata", "redaction", "evidence_bundle"}, OptionalChecks: []string{"artifact_digest", "decision_export"}, Canonicalization: "customer-security-package manifest JSON and archive member hashes", HashAlgorithm: "SHA-256", SignatureAlgorithm: "not evaluated by the current customer package verifier", TrustRootPolicy: "not applicable", IdentityPolicy: "package access token scope is enforced separately by the API", IssuerPolicy: "not applicable", TransparencyPolicy: "not evaluated", ClockPolicy: "package generation time is parsed as RFC 3339", RevocationPolicy: "package access record revocation is enforced separately from offline verification", OfflinePolicy: "manifest, archive, and optional evidence bundle can be verified locally"},
	{ID: VerificationProfileReleaseArtifactManifest, Version: VerificationProfileSchemaVersion, RequiredChecks: []string{"manifest_schema", "artifact_hashes", "manifest_signature"}, OptionalChecks: []string{"build_identity", "release_checkpoint"}, Canonicalization: "release artifact manifest canonical JSON", HashAlgorithm: "SHA-256", SignatureAlgorithm: "Ed25519 release-manifest signature format", TrustRootPolicy: "public key supplied to the offline verifier", IdentityPolicy: "not evaluated by the local release-manifest verifier", IssuerPolicy: "not evaluated by the local release-manifest verifier", TransparencyPolicy: "not evaluated", ClockPolicy: "manifest build time is informational", RevocationPolicy: "offline verifier has no revocation source", OfflinePolicy: "manifest, signature, and explicitly supplied public key are required"},
}

// VerificationProfileDefinitions returns a defensive copy so callers cannot
// alter the canonical policy registry.
func VerificationProfileDefinitions() []VerificationProfileDefinition {
	definitions := make([]VerificationProfileDefinition, 0, len(verificationProfileDefinitions))
	for _, definition := range verificationProfileDefinitions {
		definitions = append(definitions, cloneVerificationProfileDefinition(definition))
	}
	return definitions
}

// VerificationProfileDefinitionFor returns a defensive copy of one named
// profile definition.
func VerificationProfileDefinitionFor(id string) (VerificationProfileDefinition, bool) {
	for _, definition := range verificationProfileDefinitions {
		if definition.ID == id {
			return cloneVerificationProfileDefinition(definition), true
		}
	}
	return VerificationProfileDefinition{}, false
}

func cloneVerificationProfileDefinition(definition VerificationProfileDefinition) VerificationProfileDefinition {
	definition.RequiredChecks = append([]string(nil), definition.RequiredChecks...)
	definition.OptionalChecks = append([]string(nil), definition.OptionalChecks...)
	return definition
}
