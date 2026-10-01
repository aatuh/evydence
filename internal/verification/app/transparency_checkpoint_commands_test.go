package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type recordedCheckpointFake struct {
	point               TransparencyCheckpointSource
	checkpoints         []verificationdomain.TransparencyCheckpoint
	audits              []application.AuditEvent
	fail                string
	reads, transactions int
	inside              bool
}

func (f *recordedCheckpointFake) ExecuteTransparencyCheckpoint(ctx context.Context, fn func(context.Context, TransparencyCheckpointTransaction) error) error {
	f.transactions++
	copy := *f
	copy.inside = true
	copy.checkpoints, copy.audits = nil, nil
	err := fn(ctx, &copy)
	f.reads = copy.reads
	if err != nil {
		return err
	}
	if f.fail == "commit" {
		return errVerificationTestFailure
	}
	f.checkpoints, f.audits = copy.checkpoints, copy.audits
	return nil
}
func (f *recordedCheckpointFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeKeysAdmin || !r.TenantWide || r.ScopeOnly || !emptyResources(r.Resources) {
		return ErrForbidden
	}
	if f.fail == "scope" || f.fail == "auth" && f.inside {
		return ErrForbidden
	}
	return nil
}
func (f *recordedCheckpointFake) ReadTransparencyCheckpointSource(_ context.Context, tenant, id string) (TransparencyCheckpointSource, error) {
	f.reads++
	if tenant != "tenant" || id != "batch" {
		return TransparencyCheckpointSource{}, ErrNotFound
	}
	if f.fail == "read" {
		return TransparencyCheckpointSource{}, errVerificationTestFailure
	}
	return f.point, nil
}
func (f *recordedCheckpointFake) InsertTransparencyCheckpoint(_ context.Context, c verificationdomain.TransparencyCheckpoint) error {
	if f.fail == "insert" {
		return errVerificationTestFailure
	}
	f.checkpoints = append(f.checkpoints, c)
	return nil
}
func (f *recordedCheckpointFake) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, errVerificationTestFailure
	}
	f.audits = append(f.audits, a)
	return application.AuditReceipt{ID: a.ID}, nil
}

type recordedCheckpointHasher struct {
	input any
	fail  string
}

func (h *recordedCheckpointHasher) Hash(v any) (string, error) {
	h.input = v
	if h.fail == "hash" {
		return "", errVerificationTestFailure
	}
	if h.fail == "empty hash" {
		return "", nil
	}
	if h.fail == "malformed hash" {
		return "hash\x00value", nil
	}
	if h.fail == "oversized hash" {
		return strings.Repeat("h", 1025), nil
	}
	return application.NormalizedJSONHash(v)
}
func recordedCheckpointFixture(t *testing.T) (*TransparencyCheckpointCommands, *recordedCheckpointFake, *recordedCheckpointHasher) {
	t.Helper()
	f := &recordedCheckpointFake{point: TransparencyCheckpointSource{TenantID: "tenant", ID: "batch", RootHash: "sha256:root"}}
	h := &recordedCheckpointHasher{}
	c, err := NewTransparencyCheckpointCommands(TransparencyCheckpointConfig{Transactions: f, Authorizer: f, Hasher: h, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_receipt" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, h
}
func TestRecordedTransparencyCheckpointPreservesCanonicalAssertionAndAtomicAudit(t *testing.T) {
	c, f, h := recordedCheckpointFixture(t)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	r, err := c.CreateTransparencyCheckpoint(t.Context(), a, CreateTransparencyCheckpointInput{BatchID: " batch ", Provider: " rfc3161 ", ExternalID: " checkpoint ", ExternalURL: " https://example.test/record "})
	wantInput := map[string]any{"batch_id": "batch", "root_hash": "sha256:root", "provider": "rfc3161", "external_url": "https://example.test/record", "external_id": "checkpoint"}
	wantHash, _ := application.NormalizedJSONHash(wantInput)
	if err != nil || r.ID != "tcp_receipt" || r.TenantID != "tenant" || r.BatchID != "batch" || r.Provider != "rfc3161" || r.ExternalID != "checkpoint" || r.ExternalURL != "https://example.test/record" || r.TimestampHash != wantHash || r.State != "recorded" || r.SchemaVersion != verificationdomain.TransparencyCheckpointVersion || !r.CreatedAt.Equal(c.config.Clock.Now()) || !reflect.DeepEqual(h.input, wantInput) || f.transactions != 1 || f.reads != 1 || len(f.checkpoints) != 1 || len(f.audits) != 1 {
		t.Fatal(r, err, f, h)
	}
	au := f.audits[0]
	if au.TenantID != a.TenantID || au.EntryType != "transparency_checkpoint.recorded" || au.SubjectType != "transparency_checkpoint" || au.SubjectID != r.ID || au.PayloadHash != r.TimestampHash || au.ActorID != a.KeyID || au.SignatureRef != "" {
		t.Fatal(au)
	}
	for _, failure := range []string{"scope", "auth", "read", "insert", "audit", "commit", "hash", "empty hash", "malformed hash", "oversized hash"} {
		c, f, h = recordedCheckpointFixture(t)
		f.fail, h.fail = failure, failure
		r, err = c.CreateTransparencyCheckpoint(t.Context(), a, CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"})
		want := errVerificationTestFailure
		if failure == "scope" || failure == "auth" {
			want = ErrForbidden
		}
		if failure == "empty hash" || failure == "malformed hash" || failure == "oversized hash" {
			want = ErrValidation
		}
		if !errors.Is(err, want) || r.ID != "" || len(f.checkpoints)+len(f.audits) != 0 || (failure == "scope" || failure == "auth") && f.reads != 0 {
			t.Fatal(failure, r, err, f)
		}
	}
}
func TestRecordedTransparencyCheckpointRejectsInvalidInputsBeforeReads(t *testing.T) {
	for _, input := range []CreateTransparencyCheckpointInput{
		{}, {BatchID: "batch", Provider: "provider"}, {BatchID: " ", Provider: "provider", ExternalID: "record"}, {BatchID: "batch", Provider: " ", ExternalID: "record"},
		{BatchID: "bad\x00id", Provider: "provider", ExternalID: "record"}, {BatchID: "batch", Provider: string([]byte{255}), ExternalID: "record"}, {BatchID: "batch", Provider: "provider", ExternalID: "bad\x00id"}, {BatchID: "batch", Provider: "provider", ExternalURL: "bad\x00url"},
		{BatchID: strings.Repeat("b", 1025), Provider: "provider", ExternalID: "record"}, {BatchID: "batch", Provider: "provider", ExternalURL: strings.Repeat("x", MaxRecordedCheckpointTextBytes+1)},
	} {
		c, f, _ := recordedCheckpointFixture(t)
		if r, err := c.CreateTransparencyCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, input); !errors.Is(err, ErrValidation) || r.ID != "" || f.reads != 0 || f.transactions != 0 {
			t.Fatal(input.BatchID, r, err, f)
		}
	}
	for _, mutate := range []func(*TransparencyCheckpointSource){
		func(s *TransparencyCheckpointSource) { s.TenantID = "other" }, func(s *TransparencyCheckpointSource) { s.ID = "other" }, func(s *TransparencyCheckpointSource) { s.RootHash = "" },
		func(s *TransparencyCheckpointSource) { s.RootHash = strings.Repeat("x", 1025) }, func(s *TransparencyCheckpointSource) { s.RootHash = "bad\x00hash" },
	} {
		c, f, _ := recordedCheckpointFixture(t)
		mutate(&f.point)
		want := ErrNotFound
		if len(f.point.RootHash) > 1024 || strings.ContainsRune(f.point.RootHash, '\x00') {
			want = ErrConflict
		}
		if r, err := c.CreateTransparencyCheckpoint(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"}); !errors.Is(err, want) || r.ID != "" || len(f.checkpoints)+len(f.audits) != 0 {
			t.Fatal(r, err, f)
		}
	}
	c, f, _ := recordedCheckpointFixture(t)
	input := CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"}
	if _, err := c.CreateTransparencyCheckpoint(t.Context(), identitydomain.Actor{}, input); !errors.Is(err, ErrForbidden) || f.transactions != 0 {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{ctx, nil} {
		if _, err := c.CreateTransparencyCheckpoint(ctx, identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, input); !errors.Is(err, context.Canceled) || f.transactions != 0 {
			t.Fatal(err)
		}
	}
}
func TestRecordedTransparencyCheckpointRequiresFocusedDependencies(t *testing.T) {
	c, _, _ := recordedCheckpointFixture(t)
	for _, omit := range []func(*TransparencyCheckpointConfig){func(c *TransparencyCheckpointConfig) { c.Transactions = nil }, func(c *TransparencyCheckpointConfig) { c.Authorizer = nil }, func(c *TransparencyCheckpointConfig) { c.Hasher = nil }, func(c *TransparencyCheckpointConfig) { c.Clock = nil }, func(c *TransparencyCheckpointConfig) { c.IDs = nil }} {
		config := c.config
		omit(&config)
		if c, err := NewTransparencyCheckpointCommands(config); !errors.Is(err, ErrValidation) || c != nil {
			t.Fatal(c, err)
		}
	}
}

func TestRecordedTransparencyCheckpointInputBudgetAndLocalMemoryHashCompatibility(t *testing.T) {
	input := CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"}
	input.ExternalURL = strings.Repeat("u", MaxRecordedCheckpointTextBytes-len(input.BatchID)-len(input.Provider)-len(input.ExternalID))
	if _, err := normalizeTransparencyCheckpointInput(input); err != nil {
		t.Fatal("exact combined budget rejected", err)
	}
	input.ExternalURL += "u"
	if _, err := normalizeTransparencyCheckpointInput(input); !errors.Is(err, ErrValidation) {
		t.Fatal("combined budget overflow accepted", err)
	}
	input = CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "provider", ExternalID: "record"}
	c, f, _ := recordedCheckpointFixture(t)
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{ScopeKeysAdmin}}
	state := newVerificationTestState()
	state.merkleBatches["batch"] = verificationdomain.MerkleBatch{ID: "batch", TenantID: "tenant", RootHash: f.point.RootHash}
	legacy := newVerificationTestService(t, state)
	legacy.canonicalHasher = &recordedCheckpointHasher{}
	local, err := legacy.CreateTransparencyCheckpoint(t.Context(), a, input)
	if err != nil {
		t.Fatal(err)
	}
	durable, err := c.CreateTransparencyCheckpoint(t.Context(), a, input)
	if err != nil || local.TimestampHash != durable.TimestampHash || local.State != durable.State || local.SchemaVersion != durable.SchemaVersion || local.Provider != durable.Provider || local.ExternalID != durable.ExternalID || local.ExternalURL != durable.ExternalURL {
		t.Fatal("local and focused checkpoint policies diverged", local, durable, err)
	}
}
