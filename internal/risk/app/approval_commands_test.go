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

type approvalCommandFixture struct {
	subject                                          GovernanceSubjectReference
	reads, evidenceReads, commits                    int
	requests                                         []application.AuthorizationRequest
	writes                                           []riskdomain.ApprovalRecord
	audits                                           []application.AuditEvent
	authErr, readErr, insertErr, auditErr, commitErr error
	evidence                                         bool
}

func (f *approvalCommandFixture) ExecuteApproval(ctx context.Context, fn func(context.Context, ApprovalTransaction) error) error {
	writes, audits := len(f.writes), len(f.audits)
	err := fn(ctx, f)
	if err == nil {
		err = f.commitErr
	}
	if err != nil {
		f.writes, f.audits = f.writes[:writes], f.audits[:audits]
		return err
	}
	f.commits++
	return nil
}
func (f *approvalCommandFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	f.requests = append(f.requests, r)
	return f.authErr
}
func (f *approvalCommandFixture) ReadApprovalSubject(context.Context, string, string, string) (GovernanceSubjectReference, error) {
	f.reads++
	return f.subject, f.readErr
}
func (f *approvalCommandFixture) ApprovalEvidenceExists(context.Context, string, string) (bool, error) {
	f.evidenceReads++
	return f.evidence, nil
}
func (f *approvalCommandFixture) InsertApprovalRecord(_ context.Context, v riskdomain.ApprovalRecord) error {
	f.writes = append(f.writes, v)
	return f.insertErr
}
func (f *approvalCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, f.auditErr
}

func approvalFixture(t *testing.T) (*ApprovalCommands, *approvalCommandFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	f := &approvalCommandFixture{subject: GovernanceSubjectReference{Type: "release", ID: "release", TenantID: "tenant", ProductID: "product", ReleaseID: "release"}, evidence: true}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	s, err := NewApprovalCommands(ApprovalCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeReleaseWrite}}, now
}
func TestApprovalCommandsAppendAndAuthorizeCurrentCoordinates(t *testing.T) {
	s, f, a, now := approvalFixture(t)
	input := CreateApprovalInput{SubjectType: " release ", SubjectID: " release ", Decision: " approved ", Reason: " Review ", EvidenceID: " evidence "}
	v, err := s.CreateApprovalRecord(t.Context(), a, input)
	want := riskdomain.ApprovalRecord{ID: "apr_new", TenantID: "tenant", SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: "Review", ApproverID: "human", EvidenceID: "evidence", SchemaVersion: riskdomain.ApprovalRecordSchemaVersion, CreatedAt: now}
	if err != nil || v != want || len(f.writes) != 1 || f.writes[0] != want || len(f.audits) != 1 || f.audits[0].EntryType != "approval.created" || f.audits[0].SubjectID != v.ID || f.audits[0].ActorID != "human" || f.audits[0].ActorType != "human_user" || f.audits[0].OccurredAt != now || f.reads != 1 || f.evidenceReads != 1 {
		t.Fatal("approval lost transaction, identity, or metadata", v, err)
	}
	wantAuth := []application.AuthorizationRequest{{Scope: ScopeReleaseWrite, ScopeOnly: true}, {Scope: ScopeReleaseWrite, ScopeOnly: true}, {Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}}
	if !reflect.DeepEqual(f.requests, wantAuth) || input.Reason != " Review " {
		t.Fatal("authorization coordinates or caller input changed", f.requests, input)
	}
	if err := s.AuthorizeApproval(t.Context(), a, input); err != nil || len(f.writes) != 1 || len(f.audits) != 1 || f.evidenceReads != 1 {
		t.Fatal("replay authorization emitted effects or loaded evidence", err)
	}
}

func TestApprovalCommandsPreservePublishedDecisions(t *testing.T) {
	for _, decision := range []string{"approved", "rejected", "accepted"} {
		t.Run(decision, func(t *testing.T) {
			s, f, actor, now := approvalFixture(t)
			input := CreateApprovalInput{SubjectType: "release", SubjectID: "release", Decision: " " + decision + " ", Reason: "Reviewed"}
			if err := s.AuthorizeApproval(t.Context(), actor, input); err != nil {
				t.Fatal("published decision rejected before replay", err)
			}
			if len(f.writes)+len(f.audits) != 0 {
				t.Fatal("read-only authorization emitted effects")
			}
			v, err := s.CreateApprovalRecord(t.Context(), actor, input)
			if err != nil || v.Decision != decision || v.CreatedAt != now || len(f.writes) != 1 || f.writes[0] != v || len(f.audits) != 1 || f.audits[0].SubjectID != v.ID || f.commits != 2 {
				t.Fatal("published decision was rejected, changed, or not atomically recorded", v, err)
			}
		})
	}
}
func TestApprovalCommandsRejectInvalidInputsAndForeignSubjects(t *testing.T) {
	for _, input := range []CreateApprovalInput{{}, {SubjectType: "artifact", SubjectID: "artifact", Decision: "approved", Reason: "Review"}, {SubjectType: "release", SubjectID: "release", Decision: "unknown", Reason: "Review"}, {SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: " "}, {SubjectType: "release", SubjectID: "bad\x00", Decision: "approved", Reason: "Review"}, {SubjectType: "release", SubjectID: strings.Repeat("x", 1025), Decision: "approved", Reason: "Review"}, {SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: strings.Repeat("x", 65537)}} {
		s, f, a, _ := approvalFixture(t)
		v, err := s.CreateApprovalRecord(t.Context(), a, input)
		if !errors.Is(err, ErrValidation) || v.ID != "" || f.reads+len(f.writes)+len(f.audits) != 0 {
			t.Fatal("invalid input reached storage", err)
		}
	}
	for _, test := range []struct {
		name   string
		change func(*approvalCommandFixture)
		want   error
	}{
		{"denied", func(f *approvalCommandFixture) { f.authErr = application.ErrForbidden }, application.ErrForbidden},
		{"foreign", func(f *approvalCommandFixture) { f.subject.TenantID = "other" }, ErrNotFound},
		{"wrong identity", func(f *approvalCommandFixture) { f.subject.ID = "other" }, ErrNotFound},
		{"missing ownership", func(f *approvalCommandFixture) { f.subject.ProductID = ""; f.subject.ReleaseID = "" }, ErrNotFound},
		{"wrong release coordinate", func(f *approvalCommandFixture) { f.subject.ReleaseID = "other" }, ErrNotFound},
		{"invalid coordinate", func(f *approvalCommandFixture) { f.subject.ProductID = "bad\x00" }, ErrValidation},
		{"missing evidence", func(f *approvalCommandFixture) { f.evidence = false }, ErrNotFound},
		{"insert", func(f *approvalCommandFixture) { f.insertErr = ErrConflict }, ErrConflict},
		{"audit", func(f *approvalCommandFixture) { f.auditErr = ErrConflict }, ErrConflict},
		{"commit", func(f *approvalCommandFixture) { f.commitErr = ErrConflict }, ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, f, a, _ := approvalFixture(t)
			test.change(f)
			v, err := s.CreateApprovalRecord(t.Context(), a, CreateApprovalInput{SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: "Review", EvidenceID: "evidence"})
			if !errors.Is(err, test.want) || v.ID != "" || len(f.writes)+len(f.audits) != 0 {
				t.Fatal("failed approval leaked effects", v, err)
			}
		})
	}
}

func TestApprovalCommandsRejectIncompleteConfigurationAndCancelledRequests(t *testing.T) {
	s, f, a, _ := approvalFixture(t)
	for _, change := range []func(*ApprovalCommandConfig){func(c *ApprovalCommandConfig) { c.Authorizer = nil }, func(c *ApprovalCommandConfig) { c.Transactions = nil }, func(c *ApprovalCommandConfig) { c.Clock = nil }, func(c *ApprovalCommandConfig) { c.IDs = nil }} {
		config := s.config
		change(&config)
		if _, err := NewApprovalCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal("incomplete approval configuration accepted", err)
		}
	}
	input := CreateApprovalInput{SubjectType: "release", SubjectID: "release", Decision: "approved", Reason: "Review"}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateApprovalRecord(ctx, a, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.AuthorizeApproval(ctx, a, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var missingContext context.Context
	if _, err := s.CreateApprovalRecord(missingContext, a, input); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.reads+len(f.requests)+len(f.writes)+len(f.audits) != 0 {
		t.Fatal("cancelled request reached authorization/storage")
	}
}
