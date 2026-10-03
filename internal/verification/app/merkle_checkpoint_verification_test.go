package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type merkleCheckpointFake struct {
	auditVerificationFake
	point       MerkleVerificationSnapshot
	merkleReads int
}

func (f *merkleCheckpointFake) ExecuteMerkleCheckpointVerification(ctx context.Context, fn func(context.Context, MerkleCheckpointVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	copy.pageReads, copy.budgets = 0, nil
	err := fn(ctx, &copy)
	f.payloadReads, f.pageReads, f.merkleReads = copy.payloadReads, copy.pageReads, copy.merkleReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.jobs = copy.results, copy.audits, copy.jobs
	return nil
}
func (f *merkleCheckpointFake) ResolveMerkleVerificationSubject(context.Context, string, string) (SubjectReference, error) {
	return f.point.Subject, nil
}
func (f *merkleCheckpointFake) ReadMerkleVerification(context.Context, SubjectReference) (MerkleVerificationSnapshot, error) {
	f.merkleReads++
	return f.point, nil
}
func merkleCheckpointFixture(t *testing.T) (*MerkleCheckpointVerificationCommands, *merkleCheckpointFake) {
	t.Helper()
	c, a := auditVerificationFixture(t)
	_, m := merkleVerificationFixture(t)
	f := &merkleCheckpointFake{auditVerificationFake: *a, point: m.point}
	f.point.Batch.FromSequence, f.point.Batch.ToSequence = 1, 1
	hash := f.pages[0].Entries[0].EntryHash
	f.point.Batch.LeafHashes, f.point.Batch.RootHash = []string{hash}, hash
	f.point.Leaves = []AuditChainLeaf{{Sequence: 1, EntryHash: hash}}
	command, err := NewMerkleCheckpointVerificationCommands(MerkleCheckpointVerificationConfig{Transactions: f, Authorizer: f, Hasher: auditHashTestAdapter{}, Verifier: merkleVectorVerifier{hash}, Clock: c.config.Clock, IDs: c.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return command, f
}
func TestMerkleCheckpointVerificationPreservesDistinctProfileAndAtomicity(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := merkleCheckpointFixture(t)
	r, err := c.VerifyMerkleCheckpoint(t.Context(), actor, "batch")
	if err != nil || r.Result.String() != "passed" || r.SubjectType != "audit_chain_checkpoint" || r.SubjectID != "batch" || r.Profile.ID != verificationdomain.VerificationProfileAuditChainMerkleCheckpoint || r.Profile.PayloadDigest != "" || r.Profile.TransparencyProof != "not_evaluated" || len(r.Checks) != 11 || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || f.jobs[0].SubjectType != "audit_chain_checkpoint" {
		t.Fatal(r, err, f)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = merkleCheckpointFixture(t)
		f.fail = failure
		r, err = c.VerifyMerkleCheckpoint(t.Context(), actor, "batch")
		if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal(failure, r, err)
		}
	}
	c, f = merkleCheckpointFixture(t)
	f.fail = "auth"
	if _, err = c.VerifyMerkleCheckpoint(t.Context(), actor, "batch"); !errors.Is(err, application.ErrForbidden) || f.payloadReads+f.merkleReads+f.pageReads != 0 {
		t.Fatal("unauthorized content read", err)
	}
	c, f = merkleCheckpointFixture(t)
	f.point.Subject.TenantID = "foreign"
	if _, err = c.VerifyMerkleCheckpoint(t.Context(), actor, "batch"); !errors.Is(err, ErrNotFound) || f.merkleReads+f.pageReads != 0 {
		t.Fatal("foreign content read", err)
	}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{255}), strings.Repeat("x", 1025)} {
		c, f = merkleCheckpointFixture(t)
		if _, err = c.VerifyMerkleCheckpoint(t.Context(), actor, id); !errors.Is(err, ErrValidation) || f.payloadReads+f.pageReads+f.merkleReads != 0 {
			t.Fatal("invalid ID", err)
		}
	}
	c, f = merkleCheckpointFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = c.VerifyMerkleCheckpoint(ctx, actor, "batch"); !errors.Is(err, context.Canceled) || f.payloadReads != 0 {
		t.Fatal(err)
	}
}
func TestMerkleCheckpointVerificationChecksCanonicalChainAndSignedRange(t *testing.T) {
	t.Run("signed range must bind to the inspected canonical chain", func(t *testing.T) {
		c, f := merkleCheckpointFixture(t)
		f.point.Batch.LeafHashes, f.point.Batch.RootHash = []string{"forged"}, "forged"
		f.point.Leaves[0].EntryHash = "forged"
		c.config.Verifier = merkleVectorVerifier{"forged"}
		r, err := c.VerifyMerkleCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
		if !errors.Is(err, ErrVerificationFailed) || r.Checks[9].Result != "failed" {
			t.Fatal("independent forged range accepted", r, err)
		}
	})
	for name, mutate := range map[string]func(*merkleCheckpointFake){
		"canonical metadata": func(f *merkleCheckpointFake) { f.pages[0].Entries[0].Metadata["safe"] = "tampered" },
		"root":               func(f *merkleCheckpointFake) { f.point.Batch.RootHash = "other" },
		"stored leaves":      func(f *merkleCheckpointFake) { f.point.Batch.LeafHashes[0] = "other" },
		"selected leaf":      func(f *merkleCheckpointFake) { f.point.Leaves[0].EntryHash = "other" },
		"missing leaf":       func(f *merkleCheckpointFake) { f.point.Leaves = nil },
		"count":              func(f *merkleCheckpointFake) { f.point.Batch.EntryCount = 2 },
		"signature subject":  func(f *merkleCheckpointFake) { f.point.Signatures[0].SubjectID = "other" },
		"signature tenant":   func(f *merkleCheckpointFake) { f.point.Signatures[0].TenantID = "foreign" },
		"key tenant":         func(f *merkleCheckpointFake) { f.point.Keys[0].TenantID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			c, f := merkleCheckpointFixture(t)
			mutate(f)
			r, err := c.VerifyMerkleCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
			if !errors.Is(err, ErrVerificationFailed) || r.Result.String() != "failed" || len(f.results) != 1 {
				t.Fatal(r, err)
			}
		})
	}
	// A valid prefix alone cannot satisfy a checkpoint covering the deleted tail.
	c, f := merkleCheckpointFixture(t)
	f.point.Batch.ToSequence = 2
	r, err := c.VerifyMerkleCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
	if !errors.Is(err, ErrVerificationFailed) || len(r.Checks) != 9 || r.Checks[8].Name != "checkpoint_coverage" || r.Checks[8].Result != "failed" || len(r.Profile.RequiredChecks) != 9 {
		t.Fatal(r, err)
	}
	// Tampering beyond the checkpoint also fails because the whole chain is checked.
	c, f = merkleCheckpointFixture(t)
	second := f.pages[0].Entries[0]
	second.ID = "second"
	second.Sequence = 2
	second.PreviousEntryHash = f.view.HeadHash
	if err := RehashAuditChainEntry(&second, auditHashTestAdapter{}); err != nil {
		t.Fatal(err)
	}
	f.view.EntryCount, f.view.HeadSequence, f.view.HeadHash = 2, 2, second.EntryHash
	second.ActorID = "tampered"
	f.pages = append(f.pages, AuditChainVerificationPage{Entries: []verificationdomain.AuditChainEntry{second}, BytesRead: 1024})
	r, err = c.VerifyMerkleCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
	if !errors.Is(err, ErrVerificationFailed) || len(r.Checks) != 18 || r.Checks[15].Result != "passed" || f.pageReads != 3 {
		t.Fatal(r, err, f.pageReads)
	}
	for _, overflow := range []bool{false, true} {
		c, f = merkleCheckpointFixture(t)
		if overflow {
			f.point.Batch.ToSequence = MaxMerkleVerificationLeaves + 1
		} else {
			f.point.Batch.RootHash = strings.Repeat("x", 1025)
		}
		r, err = c.VerifyMerkleCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
		if !errors.Is(err, ErrConflict) || r.ID != "" || len(f.results) != 0 {
			t.Fatal(r, err)
		}
	}
}
