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

type merkleVerificationFake struct {
	bundleVerificationFake
	point MerkleVerificationSnapshot
}

type merkleVectorVerifier struct{ root string }

func (v merkleVectorVerifier) VerifyPayload(public, signature string, payload []byte) bool {
	return public == "public" && signature == "valid" && string(payload) == v.root
}

func TestMerkleVerificationPreservesOddLeafRootAndOrderedCoverage(t *testing.T) {
	const root = "sha256:6e444ebe3af93e744977821c234b40e5b33c1f358cddfbfb49f17fcca84300f0"
	c, f := merkleVerificationFixture(t)
	c.config.Verifier = merkleVectorVerifier{root}
	f.point.Batch.FromSequence, f.point.Batch.ToSequence, f.point.Batch.EntryCount = 5, 7, 3
	f.point.Batch.RootHash = root
	f.point.Batch.LeafHashes = []string{"one", "two", "three"}
	f.point.Leaves = []AuditChainLeaf{{Sequence: 5, EntryHash: "one"}, {Sequence: 6, EntryHash: "two"}, {Sequence: 7, EntryHash: "three"}}
	r, err := c.VerifyMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
	if err != nil || r.Result.String() != "passed" || r.Profile.PayloadDigest != root {
		t.Fatal(r, err)
	}
	f.point.Leaves[0], f.point.Leaves[1] = f.point.Leaves[1], f.point.Leaves[0]
	r, err = c.VerifyMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
	if !errors.Is(err, ErrVerificationFailed) || r.Checks[0].Name != "checkpoint_coverage" || r.Checks[0].Result != "failed" {
		t.Fatal(r, err)
	}
}

func (f *merkleVerificationFake) ExecuteMerkleVerification(ctx context.Context, fn func(context.Context, MerkleVerificationTransaction) error) error {
	copy := *f
	copy.results, copy.audits, copy.jobs = nil, nil, nil
	err := fn(ctx, &copy)
	f.payloadReads = copy.payloadReads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.results, f.audits, f.jobs = copy.results, copy.audits, copy.jobs
	return nil
}
func (f *merkleVerificationFake) ResolveMerkleVerificationSubject(context.Context, string, string) (SubjectReference, error) {
	return f.subject, nil
}
func (f *merkleVerificationFake) ReadMerkleVerification(context.Context, SubjectReference) (MerkleVerificationSnapshot, error) {
	f.payloadReads++
	if f.fail == "read" {
		return MerkleVerificationSnapshot{}, errVerificationTestFailure
	}
	return f.point, nil
}
func merkleVerificationFixture(t *testing.T) (*MerkleVerificationCommands, *merkleVerificationFake) {
	t.Helper()
	b, base := bundleVerificationFixture(t)
	base.subject = SubjectReference{TenantID: "tenant", Type: "merkle_batch", ID: "batch"}
	sig := base.snapshot.Signatures[0]
	sig.SubjectType, sig.SubjectID = "merkle_batch", "batch"
	f := &merkleVerificationFake{bundleVerificationFake: *base, point: MerkleVerificationSnapshot{Subject: base.subject, Batch: verificationdomain.MerkleBatch{ID: "batch", TenantID: "tenant", FromSequence: 2, ToSequence: 2, EntryCount: 1, LeafHashes: []string{"hash"}, RootHash: "hash", SignatureRefs: []string{"signature"}}, Leaves: []AuditChainLeaf{{Sequence: 2, EntryHash: "hash"}}, Signatures: []verificationdomain.Signature{sig}, Keys: base.snapshot.Keys}}
	c, err := NewMerkleVerificationCommands(MerkleVerificationConfig{Transactions: f, Authorizer: f, Verifier: bundleVerifierFake{}, Clock: b.config.Clock, IDs: b.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestMerkleVerificationIsAtomicAndRangeScoped(t *testing.T) {
	actor := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	c, f := merkleVerificationFixture(t)
	r, err := c.VerifyMerkleBatch(t.Context(), actor, "batch")
	if err != nil || r.Result.String() != "passed" || r.Profile.ID != verificationdomain.VerificationProfileMerkleCheckpoint || len(r.Checks) != 3 || len(r.Profile.RequiredChecks) != 3 || r.Profile.TransparencyProof != "not_evaluated" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 || f.jobs[0].Payload["result_id"] != r.ID {
		t.Fatal(r, err, f)
	}
	for _, failure := range []string{"read", "result", "audit", "outbox", "commit"} {
		c, f = merkleVerificationFixture(t)
		f.fail = failure
		r, err = c.VerifyMerkleBatch(t.Context(), actor, "batch")
		if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.results)+len(f.audits)+len(f.jobs) != 0 {
			t.Fatal("partial effects", failure, r, err)
		}
	}
	c, f = merkleVerificationFixture(t)
	f.fail = "auth"
	if _, err := c.VerifyMerkleBatch(t.Context(), actor, "batch"); !errors.Is(err, application.ErrForbidden) || f.payloadReads != 0 {
		t.Fatal("unauthorized read", err)
	}
	c, f = merkleVerificationFixture(t)
	f.subject.TenantID = "foreign"
	if _, err := c.VerifyMerkleBatch(t.Context(), actor, "batch"); !errors.Is(err, ErrNotFound) || f.payloadReads != 0 {
		t.Fatal("foreign read", err)
	}
	for _, id := range []string{"", " ", "bad\x00id", string([]byte{0xff}), strings.Repeat("x", 1025)} {
		c, f = merkleVerificationFixture(t)
		if _, err := c.VerifyMerkleBatch(t.Context(), actor, id); !errors.Is(err, ErrValidation) || f.payloadReads != 0 {
			t.Fatal("invalid ID reached reader", err)
		}
	}
	c, f = merkleVerificationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.VerifyMerkleBatch(ctx, actor, "batch"); !errors.Is(err, context.Canceled) || f.payloadReads != 0 {
		t.Fatal(err)
	}
}
func TestMerkleVerificationCommitsNegativeFactsWithoutOverclaiming(t *testing.T) {
	for name, mutate := range map[string]func(*MerkleVerificationSnapshot){
		"missing leaves":         func(s *MerkleVerificationSnapshot) { s.Leaves = nil },
		"sequence gap":           func(s *MerkleVerificationSnapshot) { s.Leaves[0].Sequence = 3 },
		"leaf mismatch":          func(s *MerkleVerificationSnapshot) { s.Leaves[0].EntryHash = "other" },
		"count":                  func(s *MerkleVerificationSnapshot) { s.Batch.EntryCount = 2 },
		"invalid range":          func(s *MerkleVerificationSnapshot) { s.Batch.FromSequence = 0 },
		"root":                   func(s *MerkleVerificationSnapshot) { s.Batch.RootHash = "other" },
		"signature":              func(s *MerkleVerificationSnapshot) { s.Signatures[0].Value = "invalid" },
		"signature subject":      func(s *MerkleVerificationSnapshot) { s.Signatures[0].SubjectID = "other" },
		"signature tenant":       func(s *MerkleVerificationSnapshot) { s.Signatures[0].TenantID = "foreign" },
		"key tenant":             func(s *MerkleVerificationSnapshot) { s.Keys[0].TenantID = "foreign" },
		"missing key":            func(s *MerkleVerificationSnapshot) { s.Keys = nil },
		"missing signatures":     func(s *MerkleVerificationSnapshot) { s.Signatures = nil },
		"unreferenced signature": func(s *MerkleVerificationSnapshot) { s.Batch.SignatureRefs = nil },
		"future signature":       func(s *MerkleVerificationSnapshot) { s.Signatures[0].CreatedAt = s.Keys[0].CreatedAt.AddDate(1, 0, 0) },
		"compromised key": func(s *MerkleVerificationSnapshot) {
			s.Keys[0].RevocationSemantics = "compromised"
			s.Keys[0].HistoricalValidityPolicy = "invalidate_all"
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, f := merkleVerificationFixture(t)
			mutate(&f.point)
			r, err := c.VerifyMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch")
			if !errors.Is(err, ErrVerificationFailed) || r.Result.String() != "failed" || len(f.results) != 1 || len(f.audits) != 1 || len(f.jobs) != 1 {
				t.Fatal(r, err)
			}
		})
	}
	for name, mutate := range map[string]func(*MerkleVerificationSnapshot){
		"snapshot subject": func(s *MerkleVerificationSnapshot) { s.Subject.ID = "other" },
		"batch tenant":     func(s *MerkleVerificationSnapshot) { s.Batch.TenantID = "foreign" },
		"too many leaves":  func(s *MerkleVerificationSnapshot) { s.Leaves = make([]AuditChainLeaf, MaxMerkleVerificationLeaves+1) },
		"too many stored leaves": func(s *MerkleVerificationSnapshot) {
			s.Batch.LeafHashes = make([]string, MaxMerkleVerificationLeaves+1)
		},
		"oversized range": func(s *MerkleVerificationSnapshot) { s.Batch.FromSequence = 1; s.Batch.ToSequence = 1 << 62 },
		"oversized root":  func(s *MerkleVerificationSnapshot) { s.Batch.RootHash = strings.Repeat("x", 1025) },
		"oversized hash":  func(s *MerkleVerificationSnapshot) { s.Leaves[0].EntryHash = strings.Repeat("x", 1025) },
		"aggregate material": func(s *MerkleVerificationSnapshot) {
			sig := s.Signatures[0]
			sig.Value = strings.Repeat("x", 16384)
			s.Signatures = make([]verificationdomain.Signature, 600)
			for i := range s.Signatures {
				s.Signatures[i] = sig
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, f := merkleVerificationFixture(t)
			mutate(&f.point)
			if r, err := c.VerifyMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "batch"); !errors.Is(err, ErrConflict) || r.ID != "" || len(f.results) != 0 {
				t.Fatal(r, err)
			}
		})
	}
}
