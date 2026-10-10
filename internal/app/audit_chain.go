package app

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const auditChainEntryLegacySchemaVersion = verificationapp.AuditChainEntryLegacySchemaVersion

// Stateless canonicalization shared by repository-backed audit checks.
type auditCanonicalHasher struct{}

func (auditCanonicalHasher) Hash(value any) (string, error) { return canonicalAnyHash(value) }

func canonicalAuditChainEntryHash(entry domain.AuditChainEntry) (string, error) {
	return verificationapp.CanonicalAuditChainEntryHash(verificationdomain.AuditChainEntry(entry), auditCanonicalHasher{})
}

func verifiedAuditChainCanonicalHash(entry domain.AuditChainEntry) (string, bool, error) {
	return verificationapp.VerifiedAuditChainCanonicalHash(verificationdomain.AuditChainEntry(entry), auditCanonicalHasher{})
}

// VerifyAuditChainEntryHash validates one immutable fact, not chain coverage,
// signature trust or an external anchor. It retains the documented v1
// PostgreSQL timestamp reconstruction instead of rejecting valid old hashes.
func VerifyAuditChainEntryHash(entry domain.AuditChainEntry) bool {
	canonical, valid, err := verifiedAuditChainCanonicalHash(entry)
	return err == nil && valid && hashBytes([]byte(entry.PreviousEntryHash+"\n"+canonical)) == entry.EntryHash
}

// RehashAuditChainEntry recomputes both persisted hashes from the versioned
// canonical fields and the entry's previous hash.
func RehashAuditChainEntry(entry *domain.AuditChainEntry) error {
	canonical, err := canonicalAuditChainEntryHash(*entry)
	if err != nil {
		return err
	}
	entry.CanonicalEntryHash = canonical
	entry.EntryHash = hashBytes([]byte(entry.PreviousEntryHash + "\n" + canonical))
	return nil
}

func releaseManifestAuditChainCheckpoint(manifest map[string]any) (int64, string, bool) {
	return verificationapp.ReleaseManifestAuditChainCheckpoint(manifest)
}
