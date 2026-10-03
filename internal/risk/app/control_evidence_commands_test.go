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
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlEvidenceFixture struct {
	controlExists                                                                 bool
	subject                                                                       ControlEvidenceSubjectCoordinates
	existing                                                                      riskdomain.ControlEvidence
	readError, subjectError, duplicateError, insertError, auditError, commitError error
	authFailAt, authorizations, transactions, reads, duplicateReads               int
	requests                                                                      []application.AuthorizationRequest
	keys                                                                          []ControlEvidenceLinkKey
	links                                                                         []riskdomain.ControlEvidence
	audits                                                                        []application.AuditEvent
}

func (f *controlEvidenceFixture) ExecuteControlEvidence(ctx context.Context, fn func(context.Context, ControlEvidenceTransaction) error) error {
	f.transactions++
	links, audits := len(f.links), len(f.audits)
	err := fn(ctx, f)
	if err == nil {
		err = f.commitError
	}
	if err != nil {
		f.links, f.audits = f.links[:links], f.audits[:audits]
	}
	return err
}
func (f *controlEvidenceFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	f.authorizations++
	f.requests = append(f.requests, r)
	if f.authorizations == f.authFailAt {
		return application.ErrForbidden
	}
	if r.Scope != ScopeControlsWrite {
		return application.ErrForbidden
	}
	return nil
}
func (f *controlEvidenceFixture) ControlEvidenceControlExists(_ context.Context, tenant, id string) (bool, error) {
	f.reads++
	if tenant != "tenant" || id != "control" {
		return false, nil
	}
	return f.controlExists, f.readError
}
func (f *controlEvidenceFixture) ReadControlEvidenceSubject(_ context.Context, tenant string, key ControlEvidenceSubjectKey) (ControlEvidenceSubjectCoordinates, error) {
	f.reads++
	if tenant != "tenant" || key.SubjectID != "subject" {
		return ControlEvidenceSubjectCoordinates{}, ErrNotFound
	}
	return f.subject, f.subjectError
}
func (f *controlEvidenceFixture) ReadControlEvidenceLink(_ context.Context, tenant string, key ControlEvidenceLinkKey) (riskdomain.ControlEvidence, bool, error) {
	f.duplicateReads++
	f.keys = append(f.keys, key)
	if tenant != "tenant" {
		return riskdomain.ControlEvidence{}, false, ErrNotFound
	}
	return f.existing, f.existing.ID != "", f.duplicateError
}
func (f *controlEvidenceFixture) InsertControlEvidence(_ context.Context, v riskdomain.ControlEvidence) error {
	f.links = append(f.links, v)
	return f.insertError
}
func (f *controlEvidenceFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, f.auditError
}
func newControlEvidenceFixture(t *testing.T) (*ControlEvidenceCommands, *controlEvidenceFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	f := &controlEvidenceFixture{controlExists: true, subject: ControlEvidenceSubjectCoordinates{TenantID: "tenant", SubjectType: "evidence", SubjectID: "subject", ProductID: "product", ProjectID: "project", ReleaseID: "release"}}
	now := time.Date(2026, 10, 2, 10, 0, 0, 0, time.FixedZone("test", 3600))
	s, err := NewControlEvidenceCommands(ControlEvidenceCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopeControlsWrite}}, now.UTC()
}
func controlEvidenceInput() LinkControlEvidenceInput {
	return LinkControlEvidenceInput{EvidenceType: "sbom", SubjectType: "evidence", SubjectID: "subject", Confidence: "high", Notes: "reviewed"}
}

func TestControlEvidenceCommandsPreserveLinkAndUseSubjectCoordinates(t *testing.T) {
	s, f, actor, now := newControlEvidenceFixture(t)
	in := LinkControlEvidenceInput{EvidenceType: " sbom ", SubjectType: " evidence ", SubjectID: " subject ", Confidence: " high ", Notes: " reviewed "}
	v, err := s.LinkControlEvidence(t.Context(), actor, " control ", in)
	want := riskdomain.ControlEvidence{ID: "ce-id", TenantID: "tenant", ControlID: "control", EvidenceType: "sbom", SubjectType: "evidence", SubjectID: "subject", Confidence: "high", Notes: "reviewed", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: now}
	if err != nil || v != want || !reflect.DeepEqual(f.links, []riskdomain.ControlEvidence{want}) {
		t.Fatal("link shape or atomic insert changed", v, err, f.links)
	}
	if f.transactions != 1 || f.reads != 2 || f.duplicateReads != 1 || len(f.audits) != 1 {
		t.Fatal("unexpected transaction effects", f)
	}
	wantRequests := []application.AuthorizationRequest{{Scope: ScopeControlsWrite, ScopeOnly: true}, {Scope: ScopeControlsWrite, ScopeOnly: true}, {Scope: ScopeControlsWrite, Resources: application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}}}
	if !reflect.DeepEqual(f.requests, wantRequests) {
		t.Fatal("authorization did not use current coordinates", f.requests)
	}
	a := f.audits[0]
	if a != (application.AuditEvent{ID: "ace-id", TenantID: "tenant", EntryType: "control_evidence.linked", SubjectType: "control_evidence", SubjectID: v.ID, ActorType: "api_key", ActorID: "key", OccurredAt: now}) {
		t.Fatal("audit contract changed", a)
	}
	if in.SubjectID != " subject " || in.Notes != " reviewed " {
		t.Fatal("input mutated", in)
	}
}

func TestControlEvidenceCommandsDuplicatePreservesOriginalWithoutAudit(t *testing.T) {
	s, f, actor, now := newControlEvidenceFixture(t)
	f.existing = riskdomain.ControlEvidence{ID: "original", TenantID: "tenant", ControlID: "control", EvidenceType: "sbom", SubjectType: "evidence", SubjectID: "subject", Confidence: "low", Notes: "original notes", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: now.Add(-time.Hour)}
	v, err := s.LinkControlEvidence(t.Context(), actor, "control", controlEvidenceInput())
	if err != nil || v != f.existing || len(f.links)+len(f.audits) != 0 || f.authorizations != 3 {
		t.Fatal("duplicate was changed or skipped current authorization", v, err, f)
	}
	f.authFailAt = f.authorizations + 3
	v, err = s.LinkControlEvidence(t.Context(), actor, "control", controlEvidenceInput())
	if !errors.Is(err, application.ErrForbidden) || v != (riskdomain.ControlEvidence{}) || f.duplicateReads != 1 {
		t.Fatal("duplicate disclosed before current grant", v, err, f)
	}
}

func TestControlEvidenceCommandsRejectForeignMismatchedOrMalformedSubjects(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*controlEvidenceFixture, *LinkControlEvidenceInput)
		want   error
	}{
		{"foreign control", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) { f.controlExists = false }, ErrNotFound},
		{"foreign subject", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) { f.subject.TenantID = "other" }, ErrNotFound},
		{"wrong subject identity", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) { f.subject.SubjectID = "other" }, ErrNotFound},
		{"wrong subject type", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) { f.subject.SubjectType = "release" }, ErrNotFound},
		{"orphan parent coordinates", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) { f.subject.ProductID = "" }, ErrNotFound},
		{"claimed product", func(_ *controlEvidenceFixture, in *LinkControlEvidenceInput) { in.ProductID = "other" }, ErrNotFound},
		{"claimed release", func(_ *controlEvidenceFixture, in *LinkControlEvidenceInput) { in.ReleaseID = "other" }, ErrNotFound},
		{"claimed product on detached subject", func(f *controlEvidenceFixture, in *LinkControlEvidenceInput) {
			f.subject.ProductID = ""
			in.ProductID = "product"
		}, ErrNotFound},
		{"oversized coordinates", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) {
			f.subject.ProjectID = strings.Repeat("x", 1025)
		}, ErrValidation},
		{"NUL coordinates", func(f *controlEvidenceFixture, _ *LinkControlEvidenceInput) { f.subject.ProjectID = "bad\x00id" }, ErrValidation},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, a, _ := newControlEvidenceFixture(t)
			in := controlEvidenceInput()
			test.change(f, &in)
			v, err := s.LinkControlEvidence(t.Context(), a, "control", in)
			if !errors.Is(err, test.want) || v != (riskdomain.ControlEvidence{}) || len(f.links)+len(f.audits)+f.duplicateReads != 0 {
				t.Fatal("invalid ownership produced effects", v, err, f)
			}
		})
	}
}

func TestControlEvidenceCommandsRollbackAndReauthorizeBeforeReads(t *testing.T) {
	failure := errors.New("private storage failure")
	for _, test := range []struct {
		name   string
		change func(*controlEvidenceFixture)
		want   error
		reads  int
	}{
		{"preflight denial", func(f *controlEvidenceFixture) { f.authFailAt = 1 }, application.ErrForbidden, 0},
		{"transaction credential denial", func(f *controlEvidenceFixture) { f.authFailAt = 2 }, application.ErrForbidden, 0},
		{"resource denial", func(f *controlEvidenceFixture) { f.authFailAt = 3 }, application.ErrForbidden, 2},
		{"read failure", func(f *controlEvidenceFixture) { f.readError = failure }, failure, 1},
		{"subject read failure", func(f *controlEvidenceFixture) { f.subjectError = failure }, failure, 2},
		{"duplicate read failure", func(f *controlEvidenceFixture) { f.duplicateError = failure }, failure, 2},
		{"insert failure", func(f *controlEvidenceFixture) { f.insertError = failure }, failure, 2},
		{"audit failure", func(f *controlEvidenceFixture) { f.auditError = failure }, failure, 2},
		{"commit failure", func(f *controlEvidenceFixture) { f.commitError = failure }, failure, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, a, _ := newControlEvidenceFixture(t)
			test.change(f)
			v, err := s.LinkControlEvidence(t.Context(), a, "control", controlEvidenceInput())
			if !errors.Is(err, test.want) || v != (riskdomain.ControlEvidence{}) || len(f.links)+len(f.audits) != 0 || f.reads != test.reads {
				t.Fatal("failed command published or read before auth", v, err, f)
			}
		})
	}
}

func TestControlEvidenceCommandsSupportEverySubjectAndConfidence(t *testing.T) {
	for _, typ := range []string{"evidence", "evidence_item", "product", "release", "artifact", "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "finding", "vulnerability_finding", "exception", "build", "build_attestation", "openapi_contract", "release_bundle"} {
		for _, confidence := range []string{"high", "medium", "low", "unsupported"} {
			t.Run(typ+"/"+confidence, func(t *testing.T) {
				s, f, a, _ := newControlEvidenceFixture(t)
				f.subject.SubjectType = typ
				in := controlEvidenceInput()
				in.SubjectType = typ
				in.Confidence = confidence
				v, err := s.LinkControlEvidence(t.Context(), a, "control", in)
				if err != nil || v.SubjectType != typ || v.Confidence != confidence || len(f.links) != 1 || len(f.audits) != 1 {
					t.Fatal("supported subject rejected", v, err)
				}
			})
		}
	}
}

func TestControlEvidenceCommandsArtifactAuthorizationDoesNotTrustClaimedScope(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		t.Run(map[bool]string{false: "unscoped", true: "scoped"}[scoped], func(t *testing.T) {
			s, f, a, _ := newControlEvidenceFixture(t)
			in := controlEvidenceInput()
			in.SubjectType = "artifact"
			f.subject.SubjectType = "artifact"
			f.subject.ProjectID = ""
			f.subject.ReleaseID = ""
			want := application.ResourceReferences{ArtifactID: "subject"}
			if scoped {
				in.ProductID = "product"
				want = application.ResourceReferences{ArtifactID: "subject", ProductID: "product"}
			} else {
				f.subject.ProductID = ""
			}
			_, err := s.LinkControlEvidence(t.Context(), a, "control", in)
			if err != nil || f.requests[2].Resources != want || f.requests[2].ScopeOnly {
				t.Fatal("artifact grant path changed", f.requests, err)
			}
		})
	}
}

func TestControlEvidenceCommandsValidateInputBeforeTransaction(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*LinkControlEvidenceInput)
		want   error
	}{
		{"missing subject", func(in *LinkControlEvidenceInput) { in.SubjectID = " " }, ErrValidation},
		{"invalid evidence type", func(in *LinkControlEvidenceInput) { in.EvidenceType = "unknown" }, ErrValidation},
		{"invalid confidence", func(in *LinkControlEvidenceInput) { in.Confidence = "certain" }, ErrValidation},
		{"unknown subject", func(in *LinkControlEvidenceInput) { in.SubjectType = "unknown" }, ErrNotFound},
		{"oversized subject", func(in *LinkControlEvidenceInput) { in.SubjectID = strings.Repeat("x", 1025) }, ErrValidation},
		{"oversized notes", func(in *LinkControlEvidenceInput) { in.Notes = strings.Repeat("x", 65537) }, ErrValidation},
		{"NUL notes", func(in *LinkControlEvidenceInput) { in.Notes = "private\x00notes" }, ErrValidation},
		{"invalid UTF8", func(in *LinkControlEvidenceInput) { in.Notes = string([]byte{0xff}) }, ErrValidation},
		{"oversized natural key", func(in *LinkControlEvidenceInput) {
			in.SubjectID = strings.Repeat("x", 1024)
			in.ProductID = strings.Repeat("p", 1024)
		}, ErrValidation},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, a, _ := newControlEvidenceFixture(t)
			in := controlEvidenceInput()
			test.change(&in)
			v, err := s.LinkControlEvidence(t.Context(), a, "control", in)
			if !errors.Is(err, test.want) || v != (riskdomain.ControlEvidence{}) || f.transactions != 0 {
				t.Fatal("invalid input reached transaction", v, err, f)
			}
		})
	}
	s, f, a, _ := newControlEvidenceFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := s.LinkControlEvidence(ctx, a, "control", controlEvidenceInput())
	if !errors.Is(err, context.Canceled) || f.transactions != 0 || f.authorizations != 0 {
		t.Fatal("cancellation ignored", err, f)
	}
}

func TestControlEvidenceCommandsRejectMalformedDuplicateWithoutPublishing(t *testing.T) {
	for _, change := range []func(*riskdomain.ControlEvidence){func(v *riskdomain.ControlEvidence) { v.TenantID = "other" }, func(v *riskdomain.ControlEvidence) { v.SubjectID = "wrong" }, func(v *riskdomain.ControlEvidence) { v.ProductID = "wrong" }, func(v *riskdomain.ControlEvidence) { v.Confidence = "unknown" }, func(v *riskdomain.ControlEvidence) { v.Notes = strings.Repeat("x", 65537) }, func(v *riskdomain.ControlEvidence) { v.SchemaVersion = "future" }, func(v *riskdomain.ControlEvidence) { v.CreatedAt = time.Time{} }} {
		s, f, a, now := newControlEvidenceFixture(t)
		f.existing = riskdomain.ControlEvidence{ID: "old", TenantID: "tenant", ControlID: "control", EvidenceType: "sbom", SubjectType: "evidence", SubjectID: "subject", Confidence: "low", SchemaVersion: riskdomain.ControlEvidenceSchemaVersion, CreatedAt: now}
		change(&f.existing)
		v, err := s.LinkControlEvidence(t.Context(), a, "control", controlEvidenceInput())
		if !errors.Is(err, ErrValidation) || v != (riskdomain.ControlEvidence{}) || len(f.links)+len(f.audits) != 0 {
			t.Fatal("malformed duplicate returned", v, err)
		}
	}
}

func TestControlEvidenceCommandsAcceptExactBudgetsAndPreserveSuppliedScopes(t *testing.T) {
	s, f, a, _ := newControlEvidenceFixture(t)
	in := controlEvidenceInput()
	in.ProductID = strings.Repeat("p", 1024)
	used := len(a.TenantID) + len("control") + len(in.EvidenceType) + len(in.SubjectType) + len(in.SubjectID) + len(in.ProductID)
	in.ReleaseID = strings.Repeat("r", 2048-used)
	in.Notes = strings.Repeat("n", 65536)
	f.subject.ProductID, f.subject.ReleaseID = in.ProductID, in.ReleaseID
	v, err := s.LinkControlEvidence(t.Context(), a, "control", in)
	if err != nil || v.ProductID != in.ProductID || v.ReleaseID != in.ReleaseID || v.Notes != in.Notes || len(f.links) != 1 || f.links[0] != v {
		t.Fatal("exact budgets rejected or supplied scopes replaced", v.ID, err)
	}
	key := ControlEvidenceLinkKey{ControlID: "control", EvidenceType: in.EvidenceType, SubjectType: in.SubjectType, SubjectID: in.SubjectID, ProductID: in.ProductID, ReleaseID: in.ReleaseID}
	if !reflect.DeepEqual(f.keys, []ControlEvidenceLinkKey{key}) {
		t.Fatal("duplicate key lost scope", f.keys)
	}
	key.ReleaseID += "r"
	if ValidControlEvidenceLinkKey(a.TenantID, key) {
		t.Fatal("indexed tuple overflow accepted")
	}
}

func TestControlEvidenceCommandsAuditAuthenticatedPrincipal(t *testing.T) {
	for _, test := range []struct{ name, key, user, collector, actorType, actorID string }{
		{"key", "key", "", "", "api_key", "key"},
		{"human", "", "user", "", "human_user", "user"},
		{"collector", "", "", "collector", "collector", "collector"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, a, _ := newControlEvidenceFixture(t)
			a.KeyID, a.UserID, a.CollectorID = test.key, test.user, test.collector
			_, err := s.LinkControlEvidence(t.Context(), a, "control", controlEvidenceInput())
			if err != nil || len(f.audits) != 1 || f.audits[0].ActorType != test.actorType || f.audits[0].ActorID != test.actorID {
				t.Fatal("audit principal changed", f.audits, err)
			}
		})
	}
}

func TestControlEvidenceCommandsRejectInvalidGeneratedRecords(t *testing.T) {
	for _, test := range []struct {
		name  string
		ids   application.IDGenerator
		clock application.Clock
	}{
		{name: "blank ID", ids: application.IDGeneratorFunc(func(string) string { return "" })},
		{name: "oversized ID", ids: application.IDGeneratorFunc(func(string) string { return strings.Repeat("x", 1025) })},
		{name: "invalid audit ID", ids: application.IDGeneratorFunc(func(prefix string) string {
			if prefix == "ace" {
				return "bad\x00id"
			}
			return "ce-id"
		})},
		{name: "zero timestamp", clock: application.ClockFunc(func() time.Time { return time.Time{} })},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, a, _ := newControlEvidenceFixture(t)
			if test.ids != nil {
				s.config.IDs = test.ids
			}
			if test.clock != nil {
				s.config.Clock = test.clock
			}
			v, err := s.LinkControlEvidence(t.Context(), a, "control", controlEvidenceInput())
			if !errors.Is(err, ErrValidation) || v != (riskdomain.ControlEvidence{}) || len(f.links)+len(f.audits) != 0 {
				t.Fatal("invalid generated record persisted", v, err, f)
			}
		})
	}
}

func TestControlEvidenceCommandsRequireExplicitPorts(t *testing.T) {
	s, _, a, _ := newControlEvidenceFixture(t)
	for _, change := range []func(*ControlEvidenceCommandConfig){func(c *ControlEvidenceCommandConfig) { c.Authorizer = nil }, func(c *ControlEvidenceCommandConfig) { c.Transactions = nil }, func(c *ControlEvidenceCommandConfig) { c.Clock = nil }, func(c *ControlEvidenceCommandConfig) { c.IDs = nil }} {
		config := s.config
		change(&config)
		if v, err := NewControlEvidenceCommands(config); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("incomplete wiring accepted", v, err)
		}
	}
	var missing *ControlEvidenceCommands
	if v, err := missing.LinkControlEvidence(t.Context(), a, "control", controlEvidenceInput()); !errors.Is(err, ErrValidation) || v != (riskdomain.ControlEvidence{}) {
		t.Fatal("nil command accepted", v, err)
	}
}
