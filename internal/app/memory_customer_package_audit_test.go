package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func memoryCustomerAuditFixture(t *testing.T) *memoryUnitOfWork {
	t.Helper()
	tx := memoryCustomerCatalogFixture(t)
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", ed25519.SeedSize)))
	tx.state.SigningKeys["key"] = domain.SigningKey{ID: "key", TenantID: "tenant", Algorithm: "Ed25519", Status: "active", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), Private: []byte("private-key-must-not-be-exported"), ValidFrom: fixedNow().Add(-time.Hour), CreatedAt: fixedNow().Add(-time.Hour)}
	tx.state.Signatures["signature"] = domain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "merkle_batch", SubjectID: "batch", KeyID: "key", Algorithm: "Ed25519", Value: base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, []byte("hash"))), CreatedAt: fixedNow()}
	tx.state.MerkleBatches["batch"] = domain.MerkleBatch{ID: "batch", TenantID: "tenant", RootHash: "hash"}
	for n := 1; n <= 130; n++ {
		e := domain.AuditChainEntry{ID: fmt.Sprintf("entry-%03d", n), TenantID: "tenant", EntryType: "fixture", SubjectType: "test", SubjectID: "private-subject-marker", ActorType: "api_key", ActorID: "private-actor-marker", OccurredAt: fixedNow(), Metadata: map[string]any{"private": "private-metadata-marker"}}
		if n == 130 {
			e.SubjectType, e.SubjectID, e.SignatureRef = "merkle_batch", "batch", "signature"
		}
		if _, err := tx.Repositories().Audit.Append(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	return tx
}

func TestMemoryCustomerPackageAuditInspectsEveryPageAndExportsOnlyAggregate(t *testing.T) {
	tx := memoryCustomerAuditFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	b := &memoryCustomerSnapshotBudget{remainingBytes: packageapp.MaxCustomerPackageManifestBytes}
	v, err := readMemoryCustomerPackageAudit(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{})
	if err != nil || v["result"] != "passed" || v["latest_sequence"] != int64(130) || v["head_hash"] != tx.state.AuditEntries["tenant"][129].EntryHash || !reflect.DeepEqual(v["checks"], []map[string]any{{"name": "audit_chain_integrity", "result": "passed"}}) {
		t.Fatal("real canonical audit summary changed", v, err)
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "entry-001") || strings.Contains(string(raw), "signature") || packageapp.MaxCustomerPackageManifestBytes-b.remainingBytes != len(raw) {
		t.Fatal("private audit/key material or source bytes entered manifest", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("audit inspection wrote state")
	}
	exact := &memoryCustomerSnapshotBudget{remainingBytes: len(raw)}
	if got, err := readMemoryCustomerPackageAudit(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), exact, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{}); err != nil || !reflect.DeepEqual(got, v) || exact.remainingBytes != 0 {
		t.Fatal("exact summary budget rejected", err)
	}
}

func TestMemoryCustomerPackageAuditFailsConservativelyOnTamperingAndSignatureBinding(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*MemoryUnitOfWorkSnapshot)
	}{
		{"metadata", func(s *MemoryUnitOfWorkSnapshot) {
			s.AuditEntries["tenant"][0].Metadata = map[string]any{"changed": true}
		}},
		{"predecessor", func(s *MemoryUnitOfWorkSnapshot) { s.AuditEntries["tenant"][1].PreviousEntryHash = "sha256:wrong" }},
		{"subject", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Signatures["signature"]
			v.SubjectID = "other"
			s.Signatures[v.ID] = v
		}},
		{"signature tenant", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.Signatures["signature"]
			v.TenantID = "foreign"
			s.Signatures[v.ID] = v
		}},
		{"key tenant", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.SigningKeys["key"]
			v.TenantID = "foreign"
			s.SigningKeys[v.ID] = v
		}},
		{"compromised key", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.SigningKeys["key"]
			v.RevocationSemantics, v.HistoricalValidityPolicy = "compromised", "invalidate_all"
			s.SigningKeys[v.ID] = v
		}},
		{"payload", func(s *MemoryUnitOfWorkSnapshot) {
			v := s.MerkleBatches["batch"]
			v.RootHash = "wrong"
			s.MerkleBatches[v.ID] = v
		}},
	} {
		t.Run(change.name, func(t *testing.T) {
			tx := memoryCustomerAuditFixture(t)
			change.edit(&tx.state)
			v, err := readMemoryCustomerPackageAudit(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: 1024}, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{})
			if err != nil || v["result"] != "failed" {
				t.Fatal("tampered audit was represented as passed", v, err)
			}
		})
	}
}

func TestMemoryCustomerPackageAuditRejectsOversizeCancelledAndForeignReadsWithoutPartialResults(t *testing.T) {
	tx := memoryCustomerAuditFixture(t)
	for _, scope := range [][3]string{{"tenant", "foreign-product", ""}, {"foreign", "tenant-product", "tenant-release"}, {"tenant", "tenant-product", "sibling-release"}} {
		if v, err := readMemoryCustomerPackageAudit(t.Context(), &tx.state, scope[0], scope[1], scope[2], fixedNow(), &memoryCustomerSnapshotBudget{remainingBytes: 1024}, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{}); !errors.Is(err, ErrNotFound) || v != nil {
			t.Fatal("foreign root returned audit summary", err)
		}
	}
	for _, remaining := range []int{0, 1} {
		b := &memoryCustomerSnapshotBudget{remainingBytes: remaining}
		if v, err := readMemoryCustomerPackageAudit(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{}); !errors.Is(err, ErrConflict) || v != nil || b.remainingBytes != remaining {
			t.Fatal("partial over-budget summary", err)
		}
	}
	tx.state.AuditEntries["tenant"][0].Metadata = map[string]any{"huge": strings.Repeat("x", 8<<20+1)}
	b := &memoryCustomerSnapshotBudget{remainingBytes: 1024}
	if v, err := readMemoryCustomerPackageAudit(t.Context(), &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{}); !errors.Is(err, ErrConflict) || v != nil || b.remainingBytes != 1024 {
		t.Fatal("oversized canonical source produced summary", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := readMemoryCustomerPackageAudit(ctx, &tx.state, "tenant", "tenant-product", "tenant-release", fixedNow(), b, memoryCustomerAuditHasher{}, memoryCustomerPayloadVerifier{}); !errors.Is(err, context.Canceled) || v != nil {
		t.Fatal("cancelled audit returned", err)
	}
}
