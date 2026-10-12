package app

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type failingCreationTransactions struct {
	base  EvidenceCreationTransactionRunner
	point string
}

func (r failingCreationTransactions) ExecuteEvidenceCreation(ctx context.Context, fn func(context.Context, EvidenceCreationTransaction) error) error {
	return r.base.ExecuteEvidenceCreation(ctx, func(ctx context.Context, tx EvidenceCreationTransaction) error {
		return fn(ctx, failingCreationTransaction{tx, r.point})
	})
}

type failingCreationTransaction struct {
	EvidenceCreationTransaction
	point string
}

func (t failingCreationTransaction) ValidateScope(ctx context.Context, tenant string, s EvidenceScope) error {
	if t.point == "scope" {
		return ErrConflict
	}
	return t.EvidenceCreationTransaction.ValidateScope(ctx, tenant, s)
}
func (t failingCreationTransaction) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	if t.point == "artifact" {
		return ErrConflict
	}
	return t.EvidenceCreationTransaction.ValidateArtifactReference(ctx, tenant, id, digest)
}
func (t failingCreationTransaction) RecordStagedPayload(ctx context.Context, p StagedPayload) error {
	if t.point == "payload" {
		return ErrConflict
	}
	return t.EvidenceCreationTransaction.RecordStagedPayload(ctx, p)
}
func (t failingCreationTransaction) EnqueueOutbox(ctx context.Context, e application.OutboxEvent) error {
	if t.point == "outbox" {
		return ErrConflict
	}
	return t.EvidenceCreationTransaction.EnqueueOutbox(ctx, e)
}
func (t failingCreationTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if t.point == "audit" {
		return application.AuditReceipt{}, ErrConflict
	}
	return t.EvidenceCreationTransaction.AppendAudit(ctx, e)
}
func (t failingCreationTransaction) InsertEvidence(ctx context.Context, v evidencedomain.EvidenceItem) error {
	if t.point == "insert" {
		return ErrConflict
	}
	return t.EvidenceCreationTransaction.InsertEvidence(ctx, v)
}

func TestEvidenceCreationCommandsRollbackAtEveryTransactionBoundary(t *testing.T) {
	for _, point := range []string{"scope", "artifact", "payload", "outbox", "audit", "insert", "commit"} {
		t.Run(point, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			f.reader.artifacts["artifact"] = f.actor.TenantID
			f.reader.artifactDigests["artifact"] = testDigest('b')
			f.transactions.state.artifactTenants["artifact"] = f.actor.TenantID
			f.transactions.state.artifactDigests["artifact"] = testDigest('b')
			config := creationConfig(f)
			config.Transactions = failingCreationTransactions{config.Transactions, point}
			if point == "commit" {
				f.transactions.commitErr = ErrConflict
			}
			c, err := NewEvidenceCreationCommands(config)
			if err != nil {
				t.Fatal(err)
			}
			p := StagedPayload{TenantID: f.actor.TenantID, Digest: testDigest('a'), Size: 12, MediaType: "application/json", Status: PayloadStatusStaged, StagingKey: "staging", FinalKey: "final", CreatedAt: f.now, UpdatedAt: f.now}
			v, err := c.CreateEvidence(t.Context(), f.actor, CreateEvidenceInput{Type: "note", Title: "Note", PayloadHash: p.Digest, PayloadRef: p.Reference(), PayloadSize: p.Size, PayloadMediaType: p.MediaType, StagedPayload: p, SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: testDigest('b')}}})
			state := f.transactions.state
			if v.ID != "" || !errors.Is(err, ErrConflict) || f.transactions.commits != 0 || f.transactions.rollbacks != 1 || len(state.evidence) != 0 || len(state.payloads) != 0 || len(state.outbox) != 0 || len(state.audit) != 0 {
				t.Fatal("partial creation", v, err, f.transactions)
			}
		})
	}
}

func creationConfig(f *evidenceServiceFixture) EvidenceCreationCommandConfig {
	return EvidenceCreationCommandConfig{
		Reader: f.reader, Transactions: evidenceCreationTransactions{f.transactions},
		Authorizer: f.authorizer, Payloads: f.objects, Canonicalizer: f.canonicalizer,
		CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion,
		Clock:                   f.service.clock, IDs: f.service.ids,
	}
}

func TestEvidenceCreationCommandsRequireOnlyFocusedDependencies(t *testing.T) {
	f := newEvidenceServiceFixture(t)
	config := creationConfig(f)
	if _, err := NewEvidenceCreationCommands(config); err != nil {
		t.Fatal(err)
	}
	for _, clear := range []func(*EvidenceCreationCommandConfig){
		func(c *EvidenceCreationCommandConfig) { c.Reader = nil },
		func(c *EvidenceCreationCommandConfig) { c.Transactions = nil },
		func(c *EvidenceCreationCommandConfig) { c.Authorizer = nil },
		func(c *EvidenceCreationCommandConfig) { c.Payloads = nil },
		func(c *EvidenceCreationCommandConfig) { c.Canonicalizer = nil },
		func(c *EvidenceCreationCommandConfig) { c.Clock = nil },
		func(c *EvidenceCreationCommandConfig) { c.IDs = nil },
		func(c *EvidenceCreationCommandConfig) { c.CanonicalizationProfile = " " },
	} {
		bad := config
		clear(&bad)
		if c, err := NewEvidenceCreationCommands(bad); c != nil || !errors.Is(err, ErrValidation) {
			t.Fatal(c, err)
		}
	}
}

type creationCanonicalizerFunc func(context.Context, evidencedomain.EvidenceItem) (string, error)

func (f creationCanonicalizerFunc) HashEvidence(ctx context.Context, v evidencedomain.EvidenceItem) (string, error) {
	return f(ctx, v)
}

func TestEvidenceCreationCommandsCommitPrecisionAndDefensiveCopies(t *testing.T) {
	f := newEvidenceServiceFixture(t)
	config := creationConfig(f)
	now := time.Date(2026, 10, 2, 12, 0, 0, 123456789, time.FixedZone("offset", 3*3600))
	config.Clock = application.ClockFunc(func() time.Time { return now })
	var hashed evidencedomain.EvidenceItem
	config.Canonicalizer = creationCanonicalizerFunc(func(_ context.Context, v evidencedomain.EvidenceItem) (string, error) {
		hashed = cloneEvidence(v)
		return testDigest('c'), nil
	})
	c, err := NewEvidenceCreationCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	in := CreateEvidenceInput{Type: "note", Title: " Note ", PayloadHash: testDigest('a'), ObservedAt: now, SourceIdentity: map[string]any{"nested": map[string]any{"source": "api"}}, Metadata: map[string]any{"note": "original"}, Tags: []string{"b", "a"}, SubjectRefs: []evidencedomain.SubjectRef{{Type: "opaque", ID: "unresolved-label"}}, Limitations: []string{"recorded only"}}
	v, err := c.CreateEvidence(t.Context(), f.actor, in)
	if err != nil || v.ID == "" || v.ChainEntryID == "" || f.transactions.commits != 1 || len(f.transactions.state.evidence) != 1 || len(f.transactions.state.audit) != 1 {
		t.Fatal(v, err, f.transactions)
	}
	if v.CreatedAt != now.UTC().Truncate(time.Microsecond) || v.ObservedAt != v.CreatedAt || hashed.CreatedAt != v.CreatedAt || hashed.ObservedAt != v.ObservedAt || hashed.ChainEntryID != "" || hashed.CanonicalHash != "" {
		t.Fatal("hash precision or ordering", v, hashed)
	}
	if v.TrustLevel != "L2" || v.VerificationStatus != "pending" || v.Title != "Note" || !reflect.DeepEqual(v.Tags, []string{"a", "b"}) {
		t.Fatal(v)
	}
	in.SourceIdentity["nested"].(map[string]any)["source"] = "changed"
	in.Metadata["note"] = "changed"
	in.Tags[0] = "changed"
	in.Limitations[0] = "changed"
	in.SubjectRefs[0].ID = "changed"
	stored := f.transactions.state.evidence[v.ID]
	if stored.SourceIdentity["nested"].(map[string]any)["source"] != "api" || stored.Metadata["note"] != "original" || stored.Limitations[0] != "recorded only" || stored.SubjectRefs[0].ID != "unresolved-label" {
		t.Fatal("caller mutation changed stored evidence", stored)
	}
	if v.SourceIdentity["nested"].(map[string]any)["source"] != "api" {
		t.Fatal("caller mutation changed response", v)
	}
	v.SourceIdentity["nested"].(map[string]any)["source"] = "response-changed"
	if f.transactions.state.evidence[v.ID].SourceIdentity["nested"].(map[string]any)["source"] != "api" {
		t.Fatal("response mutation changed stored evidence")
	}
	var nilContext context.Context
	if v, err := c.CreateEvidence(nilContext, f.actor, in); v.ID != "" || err == nil {
		t.Fatal(v, err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := c.CreateEvidence(canceled, f.actor, in); v.ID != "" || !errors.Is(err, context.Canceled) {
		t.Fatal(v, err)
	}
}

func TestEvidenceCreationCommandsReauthorizeBeforeTransactionalEffects(t *testing.T) {
	for _, target := range []string{"parent", "artifact"} {
		t.Run(target, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			f.reader.artifacts["artifact"] = f.actor.TenantID
			f.reader.artifactDigests["artifact"] = testDigest('a')
			f.transactions.state.artifactTenants["artifact"] = f.actor.TenantID
			f.transactions.state.artifactDigests["artifact"] = testDigest('a')
			transactionStarted := false
			f.transactions.beforeExecute = func() { transactionStarted = true }
			f.authorizer.authorize = func(r application.AuthorizationRequest) error {
				if transactionStarted && (target == "parent" && r.Resources.ProductID != "" || target == "artifact" && r.Resources.ArtifactID != "") {
					return application.ErrForbidden
				}
				return nil
			}
			c, err := NewEvidenceCreationCommands(creationConfig(f))
			if err != nil {
				t.Fatal(err)
			}
			v, err := c.CreateEvidence(t.Context(), f.actor, CreateEvidenceInput{ProductID: "product", Type: "note", Title: "Note", PayloadHash: testDigest('b'), SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: testDigest('a')}}})
			if v.ID != "" || !errors.Is(err, application.ErrForbidden) || len(f.transactions.state.evidence) != 0 || len(f.transactions.state.audit) != 0 || f.transactions.rollbacks != 1 {
				t.Fatal("authority drift committed evidence", v, err, f.transactions)
			}
		})
	}
}

func TestEvidenceCreationCommandsFailClosedOnEmptyAuditReceipt(t *testing.T) {
	f := newEvidenceServiceFixture(t)
	f.transactions.emptyAuditReceipt = true
	c, err := NewEvidenceCreationCommands(creationConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.CreateEvidence(t.Context(), f.actor, CreateEvidenceInput{Type: "note", Title: "Note", PayloadHash: testDigest('a')})
	if v.ID != "" || !errors.Is(err, ErrConflict) || len(f.transactions.state.evidence) != 0 || len(f.transactions.state.audit) != 0 || f.transactions.rollbacks != 1 {
		t.Fatal(v, err, f.transactions)
	}
}

func TestEvidenceCreationCommandsRejectNonJSONMetadataBeforeEffects(t *testing.T) {
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	for _, value := range []map[string]any{cycle, {"bad": math.NaN()}, {"bad": make(chan int)}} {
		for _, sourceIdentity := range []bool{true, false} {
			f := newEvidenceServiceFixture(t)
			c, err := NewEvidenceCreationCommands(creationConfig(f))
			if err != nil {
				t.Fatal(err)
			}
			in := CreateEvidenceInput{Type: "note", Title: "Note", PayloadHash: testDigest('a')}
			if sourceIdentity {
				in.SourceIdentity = value
			} else {
				in.Metadata = value
			}
			v, err := c.CreateEvidence(t.Context(), f.actor, in)
			if v.ID != "" || !errors.Is(err, ErrValidation) || f.canonicalizer.calls != 0 || f.transactions.commits != 0 || f.transactions.rollbacks != 0 {
				t.Fatal(v, err, f.transactions)
			}
		}
	}
}

func TestEvidenceCreationJSONCopyPreservesWireAndNativeTypes(t *testing.T) {
	input := map[string]any{
		"number": 17, "large": uint64(18446744073709551615),
		"json_number":  json.Number("12345678901234567890"),
		"array":        []any{map[string]any{"value": "original"}},
		"maps":         []map[string]any{{"value": "original"}},
		"strings":      []string{"original"},
		"empty_object": map[string]any{}, "empty_array": []any{},
		"nil_object": map[string]any(nil), "nil_array": []any(nil),
	}
	copy := cloneMap(input)
	before, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(copy)
	if err != nil || string(before) != string(after) || copy["number"] != 17 || copy["large"] != uint64(18446744073709551615) || copy["json_number"] != json.Number("12345678901234567890") {
		t.Fatal(string(before), string(after), copy, err)
	}
	input["array"].([]any)[0].(map[string]any)["value"] = "changed"
	input["maps"].([]map[string]any)[0]["value"] = "changed"
	input["strings"].([]string)[0] = "changed"
	if copy["array"].([]any)[0].(map[string]any)["value"] != "original" || copy["maps"].([]map[string]any)[0]["value"] != "original" || copy["strings"].([]string)[0] != "original" {
		t.Fatal("copy retained mutable input", copy)
	}
}
