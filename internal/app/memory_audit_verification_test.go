package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func memoryAuditVerificationFixture(t *testing.T) (*memoryUnitOfWork, verificationapp.AuditChainVerificationReader) {
	t.Helper()
	_, tx := memoryMembershipReadFixture(t)
	previous := ""
	for i := range 130 {
		e := domain.AuditChainEntry{ID: fmt.Sprintf("entry-%03d", i), TenantID: "tenant", Sequence: int64(i + 1), EntryType: "recorded", SubjectType: "merkle_batch", SubjectID: "batch", ActorType: "api_key", ActorID: "operator", OccurredAt: fixedNow(), PreviousEntryHash: previous, Metadata: map[string]any{"number": json.Number("9007199254740993")}, SchemaVersion: domain.AuditChainEntrySchemaVersion}
		if i == 0 {
			e.SignatureRef = "signature"
		}
		if err := RehashAuditChainEntry(&e); err != nil {
			t.Fatal(err)
		}
		previous = e.EntryHash
		tx.state.AuditEntries["tenant"] = append(tx.state.AuditEntries["tenant"], e)
	}
	tx.state.MerkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: "tenant", RootHash: "sha256:" + strings.Repeat("a", 64)}
	tx.state.Signatures["signature"] = domain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "batch", KeyID: "key", Algorithm: "Ed25519", Value: "recorded", CreatedAt: fixedNow()}
	tx.state.SigningKeys["key"] = domain.SigningKey{ID: "key", TenantID: "tenant", Algorithm: "Ed25519", Status: "active", PublicKey: "public", Private: []byte("private-key-marker"), CreatedAt: fixedNow(), ValidFrom: fixedNow()}
	r, ok := tx.Repositories().Verification.(verificationapp.AuditChainVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks bounded audit chain reader")
	}
	return tx, r
}

func TestMemoryAuditVerificationPagesPreserveExactCanonicalMetadataAndSelectedPublicBindings(t *testing.T) {
	tx, r := memoryAuditVerificationFixture(t)
	view, err := r.LockAuditChainVerification(t.Context(), "tenant")
	if err != nil || view.EntryCount != 130 || view.HeadSequence != 130 || view.HeadHash != tx.state.AuditEntries["tenant"][129].EntryHash {
		t.Fatal("current chain view lost head/count", view, err)
	}
	page, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, verificationapp.MaxAuditChainVerificationBytes)
	if err != nil || len(page.Entries) != 128 || page.Entries[0].Sequence != 1 || page.Entries[127].Sequence != 128 || len(page.Signatures) != 1 || len(page.Keys) != 1 || page.Bindings["entry-000"].Payload != tx.state.MerkleBatches["batch"].RootHash {
		t.Fatal("bounded audit page lost current bindings or ordering", err)
	}
	if page.Entries[0].Metadata["number"] != json.Number("9007199254740993") {
		t.Fatal("audit canonical number rounded")
	}
	if !reflect.DeepEqual(domain.AuditChainEntry(page.Entries[0]), tx.state.AuditEntries["tenant"][0]) {
		t.Fatal("audit JSON translation lost canonical fields")
	}
	raw, err := json.Marshal(page)
	if err != nil || strings.Contains(string(raw), "private-key-marker") || page.BytesRead != len(raw) {
		t.Fatal("audit page leaked private material or miscounted bytes", err)
	}
	if v, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, page.BytesRead); err != nil || !reflect.DeepEqual(v, page) {
		t.Fatal("exact audit page budget rejected", err)
	}
	if v, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, page.BytesRead-1); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.AuditChainVerificationPage{}) {
		t.Fatal("one-byte audit page overflow accepted", err)
	}
	page.Entries[0].Metadata["number"] = "caller"
	if tx.state.AuditEntries["tenant"][0].Metadata["number"] != json.Number("9007199254740993") {
		t.Fatal("audit page metadata aliases repository")
	}
	after := int64(128)
	last, err := r.ReadAuditChainVerificationPage(t.Context(), view, &after, verificationapp.MaxAuditChainVerificationBytes)
	if err != nil || len(last.Entries) != 2 || last.Entries[0].Sequence != 129 || len(last.Signatures) != 0 || len(last.Bindings) != 0 {
		t.Fatal("audit page repeated records or unselected signing material", err)
	}
	after = 130
	last, err = r.ReadAuditChainVerificationPage(t.Context(), view, &after, 0)
	if err != nil || len(last.Entries) != 0 || last.BytesRead != 0 {
		t.Fatal("empty audit page spent bytes or failed", err)
	}
}

func TestMemoryAuditVerificationDiscardsStaleOversizedForeignAndCancelledPages(t *testing.T) {
	tx, r := memoryAuditVerificationFixture(t)
	view, err := r.LockAuditChainVerification(t.Context(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	if v, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, 1); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.AuditChainVerificationPage{}) {
		t.Fatal("oversized page exposed partial audit facts", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.ReadAuditChainVerificationPage(ctx, view, nil, verificationapp.MaxAuditChainVerificationBytes); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationapp.AuditChainVerificationPage{}) {
		t.Fatal("cancelled page exposed audit facts", err)
	}
	view.HeadHash = "changed"
	if v, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, verificationapp.MaxAuditChainVerificationBytes); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.AuditChainVerificationPage{}) {
		t.Fatal("stale chain view accepted", err)
	}
	view, err = r.LockAuditChainVerification(t.Context(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	tx.state.AuditEntries["tenant"][0].Metadata["invalid"] = func() {}
	if _, err := r.LockAuditChainVerification(t.Context(), "tenant"); err != nil {
		t.Fatal("head lock inspected private canonical metadata", err)
	}
	if v, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, verificationapp.MaxAuditChainVerificationBytes); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.AuditChainVerificationPage{}) {
		t.Fatal("unreadable audit metadata escaped", err)
	}
	tx.state.AuditEntries["tenant"][0].TenantID = "foreign"
	if v, err := r.LockAuditChainVerification(t.Context(), "tenant"); !errors.Is(err, ErrConflict) || v != (verificationapp.AuditChainVerificationView{}) {
		t.Fatal("foreign row in current tenant chain exposed", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.LockAuditChainVerification(t.Context(), "tenant"); !errors.Is(err, ErrConflict) {
		t.Fatal("closed audit view accepted", err)
	}
}

func TestMemoryAuditCanonicalMetadataSurvivesAppendCommitSnapshotAndReopen(t *testing.T) {
	factory, tx := memoryMembershipReadFixture(t)
	e, err := tx.Repositories().Audit.Append(t.Context(), domain.AuditChainEntry{ID: "exact-entry", TenantID: "tenant", EntryType: "recorded", SubjectType: "product", SubjectID: "tenant-product", ActorType: "api_key", ActorID: "tenant-key", OccurredAt: fixedNow(), Metadata: map[string]any{"number": json.Number("9007199254740993")}, SchemaVersion: domain.AuditChainEntrySchemaVersion})
	if err != nil || e.Metadata["number"] != json.Number("9007199254740993") || !VerifyAuditChainEntryHash(e) {
		t.Fatal("audit append rounded canonical metadata", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := factory.Snapshot()
	if err != nil || snapshot.AuditEntries["tenant"][0].Metadata["number"] != json.Number("9007199254740993") || !VerifyAuditChainEntryHash(snapshot.AuditEntries["tenant"][0]) {
		t.Fatal("audit commit/snapshot changed canonical inputs", err)
	}
	unit, err := factory.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unit.Rollback(t.Context()) }()
	r := unit.Repositories().Verification.(verificationapp.AuditChainVerificationReader)
	view, err := r.LockAuditChainVerification(t.Context(), "tenant")
	if err != nil {
		t.Fatal(err)
	}
	p, err := r.ReadAuditChainVerificationPage(t.Context(), view, nil, verificationapp.MaxAuditChainVerificationBytes)
	if err != nil || len(p.Entries) != 1 || !VerifyAuditChainEntryHash(domain.AuditChainEntry(p.Entries[0])) {
		t.Fatal("reopened audit reader changed canonical inputs", err)
	}
}

func TestMemoryAuditCloneRetainsStoredRecordJSONValidation(t *testing.T) {
	e := domain.AuditChainEntry{OccurredAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Metadata: map[string]any{"number": json.Number("9007199254740993")}}
	if v, err := cloneMemoryAuditEntry(e); err == nil || !reflect.DeepEqual(v, domain.AuditChainEntry{}) {
		t.Fatal("audit cloning lost persisted record JSON validation")
	}
}
