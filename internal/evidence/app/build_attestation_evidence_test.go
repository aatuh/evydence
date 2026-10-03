package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestBuildAttestationEvidenceWriterFixedShapeAndPayloadEffects(t *testing.T) {
	f := &attestationEvidenceFake{}
	w, err := NewBuildAttestationEvidenceWriter(attestationEvidenceConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", CollectorID: "collector", Scopes: []string{"build:write"}}
	at := time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	in := BuildAttestationEvidenceInput{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", SourceSystem: "generic_ci", SourceIdentity: map[string]any{"oidc_verified": false}, ObservedAt: at, CreatedAt: at, PayloadHash: digest, PayloadSize: 10, ParserVersion: "dsse-in-toto-json.v1.0.0", PayloadType: "application/vnd.in-toto+json", PredicateType: "https://slsa.dev/provenance/v1", SignatureCount: 1, Subjects: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact", Digest: digest}}}
	id, err := w.WriteBuildAttestationEvidence(t.Context(), a, in)
	item := f.item
	if err != nil || id != "ev_id" || item.Type != "build_attestation" || item.Subtype != "dsse_in_toto" || item.Title != "DSSE in-toto build attestation" || item.TrustLevel != "L2" || item.VerificationStatus != "pending" || item.UploadedBy != "key" || item.CollectorID != "collector" || item.Canonicalization != evidencedomain.EvidenceCanonicalizationProfileVersion || item.ChainEntryID != "ace_id" || item.CreatedAt != at.Truncate(time.Microsecond) || item.ObservedAt != item.CreatedAt || item.Metadata["signature_count"] != 1 {
		t.Fatal(id, item, err)
	}
	wantRefs := append(append([]evidencedomain.SubjectRef(nil), in.Subjects...), evidencedomain.SubjectRef{Type: "product", ID: "product"}, evidencedomain.SubjectRef{Type: "project", ID: "project"}, evidencedomain.SubjectRef{Type: "release", ID: "release"}, evidencedomain.SubjectRef{Type: "build", ID: "build"})
	if !reflect.DeepEqual(item.SubjectRefs, wantRefs) || !reflect.DeepEqual(f.effects, []string{"audit", "evidence"}) || f.audit.PayloadHash != digest || f.audit.ActorType != "collector" || f.audit.ActorID != "collector" {
		t.Fatal(item, f)
	}
	if f.hashInput.CreatedAt != item.CreatedAt || f.hashInput.ObservedAt != item.ObservedAt || f.hashInput.CanonicalHash != "" || f.hashInput.ChainEntryID != "" || !reflect.DeepEqual(f.hashInput.SubjectRefs, item.SubjectRefs) {
		t.Fatal("hash did not receive the committed immutable fields", f.hashInput, item)
	}
	parser := item.Metadata["parser"].(map[string]any)
	if parser["name"] != "dsse-in-toto" || parser["version"] != in.ParserVersion || parser["source_schema"] != "in-toto-statement.v1" || parser["normalized_schema"] != "evydence-build-attestation.v1" || parser["replay_status"] != "original" || len(item.Limitations) != 1 {
		t.Fatal(item.Metadata, item.Limitations)
	}
	f.effects = nil
	in.StagedPayload = StagedPayload{TenantID: "tenant", Digest: digest, Size: 10, MediaType: "application/vnd.dsse.envelope+json", StagingKey: "tenants/tenant/staging/sha256/" + strings.Repeat("a", 64), FinalKey: "tenants/tenant/payloads/sha256/" + strings.Repeat("a", 64), Status: PayloadStatusStaged, CreatedAt: at, UpdatedAt: at}
	in.PayloadRef = in.StagedPayload.Reference()
	if _, err := w.WriteBuildAttestationEvidence(t.Context(), a, in); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.effects, []string{"payload", "outbox", "audit", "evidence"}) || f.job.Kind != "finalize_payload" || f.job.SubjectID != digest || f.job.Payload["payload_lifecycle"] != PayloadLifecycleVersion {
		t.Fatal(f.effects, f.job)
	}
	for _, failure := range []string{"grant", "artifact grant", "payload validation", "scope", "artifact", "hash", "invalid hash", "payload", "outbox", "audit", "empty audit", "insert"} {
		f.failure = failure
		f.effects = nil
		if id, err := w.WriteBuildAttestationEvidence(t.Context(), a, in); err == nil || id != "" {
			t.Fatal("failure published receipt", failure, id, err)
		}
		if (failure == "grant" || failure == "artifact grant" || failure == "scope" || failure == "artifact" || failure == "payload validation" || failure == "hash" || failure == "invalid hash") && len(f.effects) != 0 {
			t.Fatal("denied or invalid input reached mutation ports", failure, f.effects)
		}
	}
}

func TestBuildAttestationEvidenceWriterRequiresDependenciesAndContext(t *testing.T) {
	f := &attestationEvidenceFake{}
	config := attestationEvidenceConfig(f)
	for _, mutate := range []func(*BuildAttestationEvidenceConfig){func(c *BuildAttestationEvidenceConfig) { c.Repository = nil }, func(c *BuildAttestationEvidenceConfig) { c.Audit = nil }, func(c *BuildAttestationEvidenceConfig) { c.Payloads = nil }, func(c *BuildAttestationEvidenceConfig) { c.Outbox = nil }, func(c *BuildAttestationEvidenceConfig) { c.Canonicalizer = nil }, func(c *BuildAttestationEvidenceConfig) { c.Authorizer = nil }, func(c *BuildAttestationEvidenceConfig) { c.IDs = nil }} {
		c := config
		mutate(&c)
		if w, err := NewBuildAttestationEvidenceWriter(c); w != nil || !errors.Is(err, ErrValidation) {
			t.Fatal(w, err)
		}
	}
	w, err := NewBuildAttestationEvidenceWriter(config)
	if err != nil {
		t.Fatal(err)
	}
	var missingContext context.Context
	if id, err := w.WriteBuildAttestationEvidence(missingContext, identitydomain.Actor{}, BuildAttestationEvidenceInput{}); id != "" || !errors.Is(err, ErrValidation) {
		t.Fatal(id, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if id, err := w.WriteBuildAttestationEvidence(ctx, identitydomain.Actor{}, BuildAttestationEvidenceInput{}); id != "" || !errors.Is(err, context.Canceled) || len(f.effects) != 0 {
		t.Fatal(id, err, f.effects)
	}
}

func TestBuildAttestationEvidenceWriterRejectsMalformedBindings(t *testing.T) {
	f := &attestationEvidenceFake{}
	w, err := NewBuildAttestationEvidenceWriter(attestationEvidenceConfig(f))
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key"}
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	in := BuildAttestationEvidenceInput{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build", ObservedAt: at, CreatedAt: at, PayloadHash: digest, PayloadSize: 10, ParserVersion: "dsse-in-toto-json.v1.0.0", PayloadType: "type", PredicateType: "predicate", Subjects: []evidencedomain.SubjectRef{{Type: "artifact", Digest: digest}}}
	for _, mutate := range []func(*BuildAttestationEvidenceInput){func(v *BuildAttestationEvidenceInput) { v.BuildID = "" }, func(v *BuildAttestationEvidenceInput) { v.ProjectID = "bad\x00" }, func(v *BuildAttestationEvidenceInput) { v.PayloadHash = "bad" }, func(v *BuildAttestationEvidenceInput) { v.PayloadSize = 21 << 20 }, func(v *BuildAttestationEvidenceInput) { v.ParserVersion = "unknown" }, func(v *BuildAttestationEvidenceInput) { v.SignatureCount = -1 }, func(v *BuildAttestationEvidenceInput) { v.ObservedAt = time.Time{} }, func(v *BuildAttestationEvidenceInput) { v.PayloadRef = "object://unbound" }, func(v *BuildAttestationEvidenceInput) {
		v.Subjects = []evidencedomain.SubjectRef{{Type: "release", ID: "release"}}
	}, func(v *BuildAttestationEvidenceInput) {
		v.StagedPayload = StagedPayload{TenantID: "other", Status: PayloadStatusStaged}
	}} {
		v := in
		mutate(&v)
		if id, err := w.WriteBuildAttestationEvidence(t.Context(), a, v); !errors.Is(err, ErrValidation) || id != "" || len(f.effects) != 0 {
			t.Fatal("malformed input wrote effects", id, err, f.effects)
		}
	}
	for _, foreign := range []string{"tenant", "project", "artifact"} {
		actor, v := a, in
		switch foreign {
		case "tenant":
			actor.TenantID = "other"
		case "project":
			v.ProjectID = "other"
		case "artifact":
			v.Subjects = []evidencedomain.SubjectRef{{Type: "artifact", ID: "foreign", Digest: digest}}
		}
		if id, err := w.WriteBuildAttestationEvidence(t.Context(), actor, v); id != "" || !errors.Is(err, ErrNotFound) || len(f.effects) != 0 {
			t.Fatal("foreign scope wrote evidence", foreign, id, err, f.effects)
		}
	}
}

func attestationEvidenceConfig(f *attestationEvidenceFake) BuildAttestationEvidenceConfig {
	return BuildAttestationEvidenceConfig{Repository: f, Audit: f, Payloads: f, Outbox: f, Canonicalizer: f, Authorizer: f, IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_id" })}
}

type attestationEvidenceFake struct {
	item      evidencedomain.EvidenceItem
	hashInput evidencedomain.EvidenceItem
	audit     application.AuditEvent
	job       application.OutboxEvent
	effects   []string
	failure   string
}

func (f *attestationEvidenceFake) ValidateScope(_ context.Context, tenant string, scope EvidenceScope) error {
	if f.failure == "scope" || tenant != "tenant" || scope != (EvidenceScope{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}) {
		return ErrNotFound
	}
	return nil
}
func (f *attestationEvidenceFake) ValidateArtifactReference(_ context.Context, tenant, id, digest string) error {
	if f.failure == "artifact" || tenant != "tenant" || id != "artifact" || digest != "sha256:"+strings.Repeat("a", 64) {
		return ErrNotFound
	}
	return nil
}
func (f *attestationEvidenceFake) InsertEvidence(_ context.Context, v evidencedomain.EvidenceItem) error {
	if f.failure == "insert" {
		return ErrConflict
	}
	f.item = v
	f.effects = append(f.effects, "evidence")
	return nil
}
func (f *attestationEvidenceFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, ErrConflict
	}
	if f.failure == "empty audit" {
		return application.AuditReceipt{}, nil
	}
	f.audit = v
	f.effects = append(f.effects, "audit")
	return application.AuditReceipt{ID: v.ID}, nil
}
func (f *attestationEvidenceFake) HashEvidence(_ context.Context, v evidencedomain.EvidenceItem) (string, error) {
	if f.failure == "hash" {
		return "", ErrConflict
	}
	if f.failure == "invalid hash" {
		return "malformed", nil
	}
	f.hashInput = v
	return "sha256:" + strings.Repeat("b", 64), nil
}
func (f *attestationEvidenceFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != "build:write" || f.failure == "grant" || f.failure == "artifact grant" && r.Resources.ArtifactID != "" {
		return application.ErrForbidden
	}
	return nil
}
func (f *attestationEvidenceFake) RecordStagedPayload(context.Context, StagedPayload) error {
	if f.failure == "payload" {
		return ErrConflict
	}
	f.effects = append(f.effects, "payload")
	return nil
}
func (f *attestationEvidenceFake) ValidateStagedPayload(_ context.Context, p StagedPayload) error {
	if f.failure == "payload validation" || p.StagingKey != "tenants/tenant/staging/sha256/"+strings.Repeat("a", 64) || p.FinalKey != "tenants/tenant/payloads/sha256/"+strings.Repeat("a", 64) {
		return ErrValidation
	}
	return nil
}
func (f *attestationEvidenceFake) EnqueueOutbox(_ context.Context, v application.OutboxEvent) error {
	if f.failure == "outbox" {
		return ErrConflict
	}
	f.job = v
	f.effects = append(f.effects, "outbox")
	return nil
}
