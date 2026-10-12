package app

import (
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

func TestVerifyAuditChainEntryHashPreservesLegacyTimestampPrecision(t *testing.T) {
	entry := domain.AuditChainEntry{ID: "entry", TenantID: "tenant", Sequence: 1, EntryType: "created", ActorID: "actor", OccurredAt: time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC), SchemaVersion: auditChainEntryLegacySchemaVersion}
	if err := RehashAuditChainEntry(&entry); err != nil {
		t.Fatal(err)
	}
	entry.OccurredAt = entry.OccurredAt.Truncate(time.Microsecond)
	if !VerifyAuditChainEntryHash(entry) {
		t.Fatal("valid PostgreSQL legacy hash rejected")
	}
	tampered := entry
	tampered.ActorID = "tampered"
	if VerifyAuditChainEntryHash(tampered) {
		t.Fatal("tampered canonical fields accepted")
	}
	tampered = entry
	tampered.EntryHash = "tampered"
	if VerifyAuditChainEntryHash(tampered) {
		t.Fatal("tampered entry hash accepted")
	}
}
