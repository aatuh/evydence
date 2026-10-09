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

type fixedDeploymentEvidenceFake struct {
	item    evidencedomain.EvidenceItem
	audit   application.AuditEvent
	failure string
	effects []string
}

func (f *fixedDeploymentEvidenceFake) InsertEvidence(_ context.Context, v evidencedomain.EvidenceItem) error {
	if f.failure == "insert" {
		return errors.New("insert failed")
	}
	f.item = v
	f.effects = append(f.effects, "evidence")
	return nil
}
func (f *fixedDeploymentEvidenceFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, errors.New("audit failed")
	}
	f.audit = v
	f.effects = append(f.effects, "audit")
	return application.AuditReceipt{ID: v.ID}, nil
}
func (f *fixedDeploymentEvidenceFake) HashEvidence(_ context.Context, v evidencedomain.EvidenceItem) (string, error) {
	if f.failure == "hash" {
		return "", errors.New("hash failed")
	}
	f.item = v
	return "sha256:canonical", nil
}
func (f *fixedDeploymentEvidenceFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.failure == "grant" {
		return application.ErrForbidden
	}
	if r.Scope != "deployment:write" || r.Resources.EnvironmentID != "env" {
		return errors.New("wrong authorization")
	}
	return nil
}
func TestDeploymentEventEvidenceIsFixedCanonicalAndAuditBound(t *testing.T) {
	f := &fixedDeploymentEvidenceFake{}
	w, err := NewDeploymentEventEvidenceWriter(DeploymentEventEvidenceConfig{Repository: f, Audit: f, Canonicalizer: f, Authorizer: f, IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_id" })})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	in := DeploymentEventEvidenceInput{ProductID: "product", ReleaseID: "release", EnvironmentID: "env", DeploymentID: "dep", Status: "succeeded", ArtifactIDs: []string{"a", "b"}, ObservedAt: at, CreatedAt: at}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}
	id, err := w.WriteDeploymentEventEvidence(t.Context(), a, in)
	item := f.item
	if err != nil || id != "ev_id" || item.Type != "deployment" || item.Subtype != "event" || item.Title != "Deployment event" || item.SourceSystem != "api" || item.UploadedBy != "key" || item.TrustLevel != "L2" || item.VerificationStatus != "pending" || item.EvidenceVersion != 1 || item.SchemaVersion != evidencedomain.EvidenceItemSchemaVersion || item.Canonicalization != evidencedomain.EvidenceCanonicalizationProfileVersion || item.ChainEntryID != "ace_id" || item.CanonicalHash != "sha256:canonical" || item.PayloadHash != "sha256:84e2f5eafafb3291d70ac14fc7e4f30e25884db6e7c1658c16a75b2f1261d180" {
		t.Fatal(id, item, err)
	}
	want := []evidencedomain.SubjectRef{{Type: "release", ID: "release"}, {Type: "artifact", ID: "a"}, {Type: "artifact", ID: "b"}, {Type: "product", ID: "product"}, {Type: "deployment", ID: "dep"}}
	if !reflect.DeepEqual(item.SubjectRefs, want) || !reflect.DeepEqual(f.effects, []string{"audit", "evidence"}) || f.audit.PayloadHash != item.PayloadHash || f.audit.EntryType != "evidence.created" || len(item.Limitations) != 1 || item.Metadata["status"] != "succeeded" || item.Metadata["environment_id"] != "env" {
		t.Fatal(item, f)
	}
	in.ArtifactIDs[0] = "changed"
	if item.SubjectRefs[1].ID != "a" {
		t.Fatal("origin aliased caller")
	}
	in.ArtifactIDs[0] = "a"
	for _, failure := range []string{"grant", "hash", "audit", "insert"} {
		f.failure = failure
		id, err := w.WriteDeploymentEventEvidence(t.Context(), a, in)
		if err == nil || id != "" || failure == "grant" && !errors.Is(err, application.ErrForbidden) || failure != "grant" && !strings.Contains(err.Error(), failure+" failed") {
			t.Fatal(failure, id, err)
		}
	}
}

func TestDeploymentEventEvidenceRejectsMalformedOriginAndMissingDependencies(t *testing.T) {
	f := &fixedDeploymentEvidenceFake{}
	config := DeploymentEventEvidenceConfig{Repository: f, Audit: f, Canonicalizer: f, Authorizer: f, IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_id" })}
	for _, mutate := range []func(*DeploymentEventEvidenceConfig){func(c *DeploymentEventEvidenceConfig) { c.Repository = nil }, func(c *DeploymentEventEvidenceConfig) { c.Audit = nil }, func(c *DeploymentEventEvidenceConfig) { c.Canonicalizer = nil }, func(c *DeploymentEventEvidenceConfig) { c.Authorizer = nil }, func(c *DeploymentEventEvidenceConfig) { c.IDs = nil }} {
		c := config
		mutate(&c)
		if _, err := NewDeploymentEventEvidenceWriter(c); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	w, err := NewDeploymentEventEvidenceWriter(config)
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"deployment:write"}}
	at := time.Date(2026, 10, 2, 0, 0, 0, 123456789, time.UTC)
	in := DeploymentEventEvidenceInput{ProductID: "product", ReleaseID: "release", EnvironmentID: "env", DeploymentID: "dep", Status: "succeeded", ArtifactIDs: []string{"a", "b"}, ObservedAt: at, CreatedAt: at}
	for _, mutate := range []func(*DeploymentEventEvidenceInput){func(in *DeploymentEventEvidenceInput) { in.DeploymentID = "" }, func(in *DeploymentEventEvidenceInput) { in.ReleaseID = "bad\x00" }, func(in *DeploymentEventEvidenceInput) { in.Status = "unknown" }, func(in *DeploymentEventEvidenceInput) { in.ObservedAt = time.Time{} }, func(in *DeploymentEventEvidenceInput) { in.ArtifactIDs = []string{"b", "a"} }, func(in *DeploymentEventEvidenceInput) { in.ArtifactIDs = make([]string, 1025) }} {
		v := in
		mutate(&v)
		if id, err := w.WriteDeploymentEventEvidence(t.Context(), a, v); !errors.Is(err, ErrValidation) || id != "" || len(f.effects) != 0 {
			t.Fatal("malformed origin reached evidence writes", id, err)
		}
	}
	if _, err := w.WriteDeploymentEventEvidence(t.Context(), a, in); err != nil || f.item.CreatedAt != at.Truncate(time.Microsecond) || f.item.ObservedAt != at.Truncate(time.Microsecond) {
		t.Fatal("evidence writer did not normalize commitment timestamps", f.item, err)
	}
}
