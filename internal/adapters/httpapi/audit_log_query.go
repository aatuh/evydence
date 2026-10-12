package httpapi

import (
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func auditChainEntryFromQuery(entry verificationdomain.AuditChainEntry) domain.AuditChainEntry {
	return domain.AuditChainEntry{
		ID: entry.ID, TenantID: entry.TenantID, Sequence: entry.Sequence,
		EntryType: entry.EntryType, SubjectType: entry.SubjectType, SubjectID: entry.SubjectID,
		ActorType: entry.ActorType, ActorID: entry.ActorID, OccurredAt: entry.OccurredAt,
		RequestID: entry.RequestID, IdempotencyKey: entry.IdempotencyKey,
		PayloadHash: entry.PayloadHash, CanonicalEntryHash: entry.CanonicalEntryHash,
		PreviousEntryHash: entry.PreviousEntryHash, EntryHash: entry.EntryHash,
		SignatureRef: entry.SignatureRef, Metadata: entry.Metadata, SchemaVersion: entry.SchemaVersion,
	}
}
