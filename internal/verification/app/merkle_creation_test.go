package app

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func TestMerkleCreationReplayGuardDoesNotReadChainOrSign(t *testing.T) {
	for _, failure := range []string{"", "scope", "auth", "commit"} {
		c, f := merkleCreationFixture(t)
		f.fail = failure
		c.config.Clock = application.ClockFunc(func() time.Time { panic("replay guard read clock") })
		c.config.IDs = application.IDGeneratorFunc(func(string) string { panic("replay guard generated ID") })
		err := c.AuthorizeMerkleCreation(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"})
		if failure == "" && err != nil || failure != "" && err == nil || f.reads+f.signs+len(f.keys)+len(f.sigs)+len(f.batches)+len(f.audits) != 0 {
			t.Fatal("guard generated or read Merkle state", failure, err)
		}
	}
	c, f := merkleCreationFixture(t)
	for _, tenant := range []string{" tenant ", "bad\x00", string([]byte{255}), strings.Repeat("t", 1025)} {
		if err := c.AuthorizeMerkleCreation(t.Context(), identitydomain.Actor{TenantID: tenant, KeyID: "caller"}); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal("bad tenant reached guard transaction", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := c.AuthorizeMerkleCreation(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal("cancelled guard reached transaction", err)
	}
}

type merkleCreationFake struct {
	recordedCheckpointFake
	view     MerkleCreationView
	leaves   []AuditChainLeaf
	keys     []PreparedSigningKey
	sigs     []verificationdomain.Signature
	batches  []verificationdomain.MerkleBatch
	prepared *PreparedSigningKey
	private  []byte
	signs    int
}

func (f *merkleCreationFake) ExecuteMerkleCreation(ctx context.Context, fn func(context.Context, MerkleCreationTransaction) error) error {
	f.transactions++
	copy := *f
	copy.inside = true
	copy.keys, copy.sigs, copy.batches, copy.audits = nil, nil, nil, nil
	err := fn(ctx, &copy)
	f.reads, f.signs = copy.reads, copy.signs
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.keys, f.sigs, f.batches, f.audits = copy.keys, copy.sigs, copy.batches, copy.audits
	return nil
}
func (f *merkleCreationFake) LockMerkleCreationView(context.Context, string) (MerkleCreationView, error) {
	f.reads++
	if f.fail == "view" {
		return MerkleCreationView{}, errVerificationTestFailure
	}
	return f.view, nil
}
func (f *merkleCreationFake) ReadMerkleCreationLeaves(_ context.Context, _ string, from, to int64) ([]AuditChainLeaf, error) {
	f.reads++
	if f.fail == "leaves" {
		return nil, errVerificationTestFailure
	}
	var leaves []AuditChainLeaf
	for _, l := range f.leaves {
		if l.Sequence >= from && l.Sequence <= to {
			leaves = append(leaves, l)
		}
	}
	return leaves, nil
}
func (f *merkleCreationFake) SignMerkleRoot(_ context.Context, r SigningRequest) (SigningResult, error) {
	f.signs++
	if f.fail == "sign" {
		return SigningResult{NewKey: f.prepared}, errVerificationTestFailure
	}
	s := verificationdomain.Signature{ID: "sig", TenantID: r.TenantID, SubjectType: r.SubjectType, SubjectID: r.SubjectID, KeyID: "key", Algorithm: "Ed25519", Value: "signature", CreatedAt: r.CreatedAt}
	if f.fail == "signature" {
		s.TenantID = "other"
	}
	return SigningResult{Signature: s, NewKey: f.prepared}, nil
}
func (f *merkleCreationFake) InsertSigningKey(_ context.Context, k PreparedSigningKey) error {
	if f.fail == "key" {
		return errVerificationTestFailure
	}
	k.PrivateMaterial = append([]byte(nil), k.PrivateMaterial...)
	f.keys = append(f.keys, k)
	return nil
}
func (f *merkleCreationFake) InsertSignature(_ context.Context, s verificationdomain.Signature) error {
	if f.fail == "signature insert" {
		return errVerificationTestFailure
	}
	f.sigs = append(f.sigs, s)
	return nil
}
func (f *merkleCreationFake) InsertMerkleBatch(_ context.Context, b verificationdomain.MerkleBatch) error {
	if f.fail == "batch" {
		return errVerificationTestFailure
	}
	f.batches = append(f.batches, cloneMerkleBatch(b))
	return nil
}
func merkleCreationFixture(t *testing.T) (*MerkleCreationCommands, *merkleCreationFake) {
	t.Helper()
	base, _, _ := recordedCheckpointFixture(t)
	f := &merkleCreationFake{view: MerkleCreationView{TenantID: "tenant", EntryCount: 3, FirstSequence: 1, LastSequence: 3}, leaves: []AuditChainLeaf{{1, "one"}, {2, "two"}, {3, "three"}}}
	c, err := NewMerkleCreationCommands(MerkleCreationConfig{Transactions: f, Authorizer: f, Clock: base.config.Clock, IDs: base.config.IDs})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}
func TestMerkleCreationSignsCompleteOwnedRangeAndCommitsOnlyAtomicEffects(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, in := range []CreateMerkleBatchInput{{}, {FromSequence: 2, ToSequence: 3}, {FromSequence: 3}, {ToSequence: 1}} {
		c, f := merkleCreationFixture(t)
		r, err := c.CreateMerkleBatch(t.Context(), a, in)
		from, to := in.FromSequence, in.ToSequence
		if from == 0 {
			from = 1
		}
		if to == 0 {
			to = 3
		}
		hashes := []string{"one", "two", "three"}[from-1 : to]
		if err != nil || r.ID != "mb_receipt" || r.TenantID != "tenant" || r.FromSequence != from || r.ToSequence != to || r.EntryCount != len(hashes) || r.RootHash != merkleRoot(hashes) || len(r.SignatureRefs) != 1 || r.SignatureRefs[0] != "sig" || r.SchemaVersion != verificationdomain.MerkleBatchSchemaVersion || len(f.batches) != 1 || len(f.sigs) != 1 || len(f.audits) != 1 || f.signs != 1 {
			t.Fatal(in, r, err, f)
		}
		if f.audits[0].PayloadHash != r.RootHash || f.audits[0].SignatureRef != "sig" || f.audits[0].EntryType != "merkle_batch.created" {
			t.Fatal(f.audits)
		}
		r.LeafHashes[0] = "changed"
		if f.batches[0].LeafHashes[0] == "changed" {
			t.Fatal("published mutable batch aliases")
		}
	}
	for _, failure := range []string{"scope", "auth", "view", "leaves", "sign", "signature", "signature insert", "batch", "audit", "commit"} {
		c, f := merkleCreationFixture(t)
		f.fail = failure
		r, err := c.CreateMerkleBatch(t.Context(), a, CreateMerkleBatchInput{})
		want := errVerificationTestFailure
		if failure == "scope" || failure == "auth" {
			want = ErrForbidden
		}
		if failure == "signature" {
			want = ErrValidation
		}
		if !errors.Is(err, want) || r.ID != "" || len(f.keys)+len(f.sigs)+len(f.batches)+len(f.audits) != 0 || (failure == "scope" || failure == "auth") && f.reads != 0 {
			t.Fatal(failure, r, err, f)
		}
	}
}
func TestMerkleCreationRejectsInvalidAndOversizedViewsWithoutSigning(t *testing.T) {
	for _, in := range []CreateMerkleBatchInput{{FromSequence: -1}, {ToSequence: -1}, {FromSequence: 3, ToSequence: 2}, {ToSequence: 4}, {FromSequence: math.MaxInt64, ToSequence: math.MaxInt64}} {
		c, f := merkleCreationFixture(t)
		if r, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, in); !errors.Is(err, ErrValidation) || r.ID != "" || f.signs != 0 {
			t.Fatal(in, r, err)
		}
	}
	for _, mutate := range []func(*merkleCreationFake){
		func(f *merkleCreationFake) { f.view.EntryCount = 0 }, func(f *merkleCreationFake) { f.view.FirstSequence = 2 }, func(f *merkleCreationFake) { f.view.LastSequence = 4 }, func(f *merkleCreationFake) { f.view.HasEmptyHash = true }, func(f *merkleCreationFake) { f.leaves = f.leaves[:2] }, func(f *merkleCreationFake) { f.leaves[1].EntryHash = " " }, func(f *merkleCreationFake) { f.leaves[1].Sequence = 3 },
	} {
		c, f := merkleCreationFixture(t)
		mutate(f)
		if r, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, ErrValidation) || r.ID != "" || f.signs != 0 {
			t.Fatal(r, err, f)
		}
	}
	c, f := merkleCreationFixture(t)
	f.view.TenantID = "other"
	if _, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, ErrNotFound) || f.signs != 0 {
		t.Fatal(err)
	}
	c, f = merkleCreationFixture(t)
	f.view.EntryCount, f.view.LastSequence = 4097, 4097
	if _, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, ErrConflict) || f.signs != 0 {
		t.Fatal(err)
	}
	c, f = merkleCreationFixture(t)
	f.leaves[0].EntryHash = strings.Repeat("x", 1025)
	if _, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, ErrConflict) || f.signs != 0 {
		t.Fatal(err)
	}
	c, f = merkleCreationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, err := c.CreateMerkleBatch(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, context.Canceled) || f.transactions != 0 {
			t.Fatal(err)
		}
	}
}
func TestMerkleCreationPersistsSignerCreatedKeyAtomicallyAndClearsTransientPrivateBytes(t *testing.T) {
	for _, failure := range []string{"", "sign", "key", "signature insert", "batch", "audit", "commit"} {
		c, f := merkleCreationFixture(t)
		f.fail = failure
		prepared := newVerificationTestService(t, newVerificationTestState())
		k, err := prepared.keyFactory.GenerateSigningKey(t.Context(), "tenant", verificationdomain.SigningKeyDefaultProvider, 1, c.config.Clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		k.Key.ID = "key"
		f.prepared = &k
		f.private = k.PrivateMaterial
		r, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{})
		if failure == "" {
			if err != nil || r.ID == "" || len(f.keys) != 1 || string(f.keys[0].PrivateMaterial) != "private-material" {
				t.Fatal(r, err, f)
			}
		} else if !errors.Is(err, errVerificationTestFailure) || r.ID != "" || len(f.keys)+len(f.sigs)+len(f.batches)+len(f.audits) != 0 {
			t.Fatal(failure, r, err, f)
		}
		for _, b := range f.private {
			if b != 0 {
				t.Fatal("transient key bytes retained")
			}
		}
	}
}

func TestMerkleCreationRejectsMissingDependenciesActorsAndEncodedBudget(t *testing.T) {
	c, f := merkleCreationFixture(t)
	for _, mutate := range []func(*MerkleCreationConfig){
		func(c *MerkleCreationConfig) { c.Transactions = nil },
		func(c *MerkleCreationConfig) { c.Authorizer = nil },
		func(c *MerkleCreationConfig) { c.Clock = nil },
		func(c *MerkleCreationConfig) { c.IDs = nil },
	} {
		config := c.config
		mutate(&config)
		if command, err := NewMerkleCreationCommands(config); !errors.Is(err, ErrValidation) || command != nil {
			t.Fatal(command, err)
		}
	}
	for _, actor := range []identitydomain.Actor{{}, {TenantID: "tenant"}, {KeyID: "caller"}} {
		if r, err := c.CreateMerkleBatch(t.Context(), actor, CreateMerkleBatchInput{}); !errors.Is(err, ErrForbidden) || r.ID != "" || f.transactions != 0 {
			t.Fatal(actor, r, err)
		}
	}
	f.view.EntryCount, f.view.LastSequence = MaxMerkleVerificationLeaves, MaxMerkleVerificationLeaves
	f.leaves = make([]AuditChainLeaf, MaxMerkleVerificationLeaves)
	for i := range f.leaves {
		f.leaves[i] = AuditChainLeaf{Sequence: int64(i + 1), EntryHash: strings.Repeat("\n", 1023) + "x"}
	}
	if r, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, ErrConflict) || r.ID != "" || f.signs != 0 {
		t.Fatal("encoded budget bypass", r, err)
	}
}

func TestMerkleCreationRejectsInvalidPreparedKeyAndClearsIt(t *testing.T) {
	for _, mutate := range []func(*PreparedSigningKey){
		func(k *PreparedSigningKey) { k.Key.TenantID = "other" },
		func(k *PreparedSigningKey) { k.Key.ID = "unbound" },
		func(k *PreparedSigningKey) {
			k.Key.Status, _ = verificationdomain.ParseSigningKeyStatus(verificationdomain.SigningKeyStatusRevoked)
		},
		func(k *PreparedSigningKey) { k.Key.Provider = "external" },
		func(k *PreparedSigningKey) { k.Key.Version = 0 },
	} {
		c, f := merkleCreationFixture(t)
		service := newVerificationTestService(t, newVerificationTestState())
		k, err := service.keyFactory.GenerateSigningKey(t.Context(), "tenant", verificationdomain.SigningKeyDefaultProvider, 1, c.config.Clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		k.Key.ID = "key"
		mutate(&k)
		f.prepared = &k
		raw := k.PrivateMaterial
		if r, err := c.CreateMerkleBatch(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateMerkleBatchInput{}); !errors.Is(err, ErrValidation) || r.ID != "" || len(f.keys)+len(f.sigs)+len(f.batches)+len(f.audits) != 0 {
			t.Fatal(r, err)
		}
		for _, b := range raw {
			if b != 0 {
				t.Fatal("invalid prepared private bytes retained")
			}
		}
	}
}
