package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const AuditChainEntryLegacySchemaVersion = "audit-chain-entry.v1.0.0"

// CanonicalAuditChainEntryHash owns the existing versioned canonical field
// contract. Infrastructure supplies the established normalized-JSON hasher.
func CanonicalAuditChainEntryHash(e verificationdomain.AuditChainEntry, hasher CanonicalHasher) (string, error) {
	if hasher == nil {
		return "", ErrValidation
	}
	fields := map[string]any{"tenant_id": e.TenantID, "sequence": e.Sequence, "entry_type": e.EntryType, "subject_type": e.SubjectType, "subject_id": e.SubjectID, "actor_type": e.ActorType, "actor_id": e.ActorID, "payload_hash": e.PayloadHash, "previous_entry_hash": e.PreviousEntryHash, "signature_ref": e.SignatureRef, "schema_version": e.SchemaVersion}
	switch e.SchemaVersion {
	case AuditChainEntryLegacySchemaVersion:
		fields["occurred_at"] = e.OccurredAt.UTC().Format(time.RFC3339Nano)
	case verificationdomain.AuditChainEntrySchemaVersion:
		fields["occurred_at"] = e.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
		fields["id"], fields["request_id"], fields["idempotency_key"], fields["metadata"] = e.ID, e.RequestID, e.IdempotencyKey, e.Metadata
	default:
		return "", fmt.Errorf("unsupported audit-chain entry schema version %q", e.SchemaVersion)
	}
	return hasher.Hash(fields)
}

func VerifiedAuditChainCanonicalHash(e verificationdomain.AuditChainEntry, hasher CanonicalHasher) (string, bool, error) {
	canonical, err := CanonicalAuditChainEntryHash(e, hasher)
	if err != nil || canonical == e.CanonicalEntryHash || e.SchemaVersion != AuditChainEntryLegacySchemaVersion {
		return canonical, err == nil && canonical == e.CanonicalEntryHash, err
	}
	base := e.OccurredAt.UTC().Truncate(time.Microsecond)
	for nanos := 1; nanos < 1000; nanos++ {
		candidate := e
		candidate.OccurredAt = base.Add(time.Duration(nanos))
		canonical, err = CanonicalAuditChainEntryHash(candidate, hasher)
		if err != nil {
			return "", false, err
		}
		if canonical == e.CanonicalEntryHash {
			return canonical, true, nil
		}
	}
	return canonical, false, nil
}

func auditChainLinkHash(previous, canonical string) string {
	digest := sha256.Sum256([]byte(previous + "\n" + canonical))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func RehashAuditChainEntry(e *verificationdomain.AuditChainEntry, hasher CanonicalHasher) error {
	if e == nil {
		return ErrValidation
	}
	canonical, err := CanonicalAuditChainEntryHash(*e, hasher)
	if err != nil {
		return err
	}
	e.CanonicalEntryHash = canonical
	e.EntryHash = auditChainLinkHash(e.PreviousEntryHash, canonical)
	return nil
}
