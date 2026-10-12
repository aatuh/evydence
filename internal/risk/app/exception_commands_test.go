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

type exceptionCommandFixture struct {
	subjects                               map[string]GovernanceSubjectReference
	state                                  ExceptionTransitionState
	record                                 riskdomain.Exception
	writes                                 []riskdomain.Exception
	audits                                 []application.AuditEvent
	requests                               []application.AuthorizationRequest
	reads, recordReads                     int
	authErr, writeErr, auditErr, commitErr error
}

func (f *exceptionCommandFixture) ExecuteException(ctx context.Context, fn func(context.Context, ExceptionTransaction) error) error {
	writes, audits := len(f.writes), len(f.audits)
	prior, state := f.record, f.state
	err := fn(ctx, f)
	if err == nil {
		err = f.commitErr
	}
	if err != nil {
		f.writes, f.audits, f.record, f.state = f.writes[:writes], f.audits[:audits], prior, state
	}
	return err
}
func (f *exceptionCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	f.requests = append(f.requests, r)
	if f.authErr != nil {
		return f.authErr
	}
	return NewExceptionWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *exceptionCommandFixture) ReadExceptionSubject(_ context.Context, tenant, kind, id string) (GovernanceSubjectReference, error) {
	f.reads++
	v, ok := f.subjects[kind+"/"+id]
	if !ok || v.TenantID != tenant {
		return GovernanceSubjectReference{}, ErrNotFound
	}
	return v, nil
}
func (f *exceptionCommandFixture) ReadExceptionTransitionState(_ context.Context, tenant, id string) (ExceptionTransitionState, error) {
	f.reads++
	if f.state.ID != id || f.state.TenantID != tenant {
		return ExceptionTransitionState{}, ErrNotFound
	}
	return f.state, nil
}
func (f *exceptionCommandFixture) ReadExceptionForApproval(context.Context, string, string) (riskdomain.Exception, error) {
	f.recordReads++
	return f.record, nil
}
func (f *exceptionCommandFixture) InsertException(_ context.Context, v riskdomain.Exception) error {
	f.writes = append(f.writes, v)
	return f.writeErr
}
func (f *exceptionCommandFixture) ApproveException(_ context.Context, v riskdomain.Exception) error {
	f.writes = append(f.writes, v)
	f.record = v
	f.state.Approved = v.Approved
	return f.writeErr
}
func (f *exceptionCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, f.auditErr
}
func exceptionFixture(t *testing.T) (*ExceptionCommands, *exceptionCommandFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	f := &exceptionCommandFixture{subjects: map[string]GovernanceSubjectReference{
		"release/release": {Type: "release", ID: "release", TenantID: "tenant", ProductID: "product", ReleaseID: "release"},
		"finding/finding": {Type: "finding", ID: "finding", TenantID: "tenant", ProductID: "product", ReleaseID: "release"},
		"control/control": {Type: "control", ID: "control", TenantID: "tenant"},
	}, state: ExceptionTransitionState{ID: "exception", TenantID: "tenant", ReleaseID: "release", FindingID: "finding", ControlID: "control", ExpiresAt: now.Add(time.Hour)}}
	f.record = riskdomain.Exception{ID: "exception", TenantID: "tenant", ReleaseID: "release", FindingID: "finding", ControlID: "control", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(-time.Hour)}
	s, err := NewExceptionCommands(ExceptionCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeReleaseWrite}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{ScopeReleaseWrite}}}}
	return s, f, a, now
}
func TestExceptionCommandsCreateCurrentScopedRecordAndAuditAtomically(t *testing.T) {
	s, f, a, now := exceptionFixture(t)
	in := CreateExceptionInput{ReleaseID: " release ", FindingID: " finding ", ControlID: " control ", Reason: " Reviewed ", Owner: " Owner ", ExpiresAt: now.Add(time.Hour)}
	if err := s.AuthorizeCreateException(t.Context(), a, in); err != nil || len(f.writes)+len(f.audits)+f.recordReads != 0 {
		t.Fatal("replay authorization emitted effects", err)
	}
	v, err := s.CreateException(t.Context(), a, in)
	want := riskdomain.Exception{ID: "ex_new", TenantID: "tenant", ReleaseID: "release", FindingID: "finding", ControlID: "control", Reason: "Reviewed", Owner: "Owner", ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err != nil || !reflect.DeepEqual(v, want) || len(f.writes) != 1 || !reflect.DeepEqual(f.writes[0], want) || len(f.audits) != 1 || f.audits[0].EntryType != "exception.created" || f.audits[0].ActorID != "human" || f.audits[0].SubjectID != v.ID || f.recordReads != 0 || in.Owner != " Owner " {
		t.Fatal("exception lost input, ownership, or atomic audit", v, err)
	}
}
func TestExceptionCommandsApprovalPreservesCoreAndIsNaturallyIdempotent(t *testing.T) {
	s, f, a, now := exceptionFixture(t)
	before := f.record
	if err := s.AuthorizeApproveException(t.Context(), a, "exception"); err != nil || f.recordReads != 0 || len(f.writes)+len(f.audits) != 0 {
		t.Fatal("approval authorization fetched records or emitted effects", err)
	}
	v, err := s.ApproveException(t.Context(), a, " exception ")
	want := before
	want.Approved = true
	want.ApprovedBy = "human"
	want.ApprovedAt = &now
	if err != nil || !reflect.DeepEqual(v, want) || len(f.writes) != 1 || len(f.audits) != 1 || f.audits[0].EntryType != "exception.approved" {
		t.Fatal("approval changed core fields or lost audit", v, err)
	}
	if again, err := s.ApproveException(t.Context(), a, "exception"); err != nil || !reflect.DeepEqual(again, v) || len(f.writes) != 1 || len(f.audits) != 1 {
		t.Fatal("already approved exception lost natural idempotency", again, err)
	}
	f.state.ExpiresAt = now.Add(-time.Hour)
	if err := s.AuthorizeApproveException(t.Context(), a, "exception"); err != nil {
		t.Fatal("completed replay cannot be authorized after expiry", err)
	}
	if _, err := s.ApproveException(t.Context(), a, "exception"); !errors.Is(err, ErrConflict) {
		t.Fatal("expired exception approved", err)
	}
	a.ResourceGrants = nil
	reads := f.recordReads
	if err := s.AuthorizeApproveException(t.Context(), a, "exception"); !errors.Is(err, application.ErrForbidden) || f.recordReads != reads {
		t.Fatal("grant removal failed before payload reads", err)
	}
}
func TestExceptionCommandsRejectInvalidInputsBeforeStorage(t *testing.T) {
	for _, change := range []func(*CreateExceptionInput){func(v *CreateExceptionInput) { v.ReleaseID = "" }, func(v *CreateExceptionInput) { v.ReleaseID = strings.Repeat("x", 1025) }, func(v *CreateExceptionInput) { v.FindingID = "bad\x00" }, func(v *CreateExceptionInput) { v.ControlID = strings.Repeat("x", 1025) }, func(v *CreateExceptionInput) { v.Owner = " " }, func(v *CreateExceptionInput) { v.Owner = strings.Repeat("é", 513) }, func(v *CreateExceptionInput) { v.Reason = strings.Repeat("x", 65537) }, func(v *CreateExceptionInput) { v.Reason = "\xff" }, func(v *CreateExceptionInput) { v.Reason = "" }, func(v *CreateExceptionInput) { v.ExpiresAt = time.Time{} }, func(v *CreateExceptionInput) { v.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }} {
		s, f, a, now := exceptionFixture(t)
		in := CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)}
		change(&in)
		v, err := s.CreateException(t.Context(), a, in)
		if !errors.Is(err, ErrValidation) || v.ID != "" || f.reads+len(f.writes)+len(f.audits) != 0 {
			t.Fatal("invalid exception reached storage", in, v, err)
		}
	}
	s, f, a, now := exceptionFixture(t)
	expired := CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(-time.Hour)}
	if err := s.AuthorizeCreateException(t.Context(), a, expired); err != nil || len(f.writes)+len(f.audits) != 0 {
		t.Fatal("expired successful replay could not be authorized", err)
	}
	if _, err := s.CreateException(t.Context(), a, expired); !errors.Is(err, ErrValidation) || len(f.writes)+len(f.audits) != 0 {
		t.Fatal("expired replay allowed new creation", err)
	}
}

func TestExceptionCommandsRejectInvalidClockAndGeneratedIdentifiers(t *testing.T) {
	for _, op := range []string{"create", "approve"} {
		for _, stage := range []string{"clock", "audit ID", "actor ID", "tenant ID"} {
			s, f, actor, now := exceptionFixture(t)
			switch stage {
			case "clock":
				s.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
			case "audit ID":
				s.config.IDs = application.IDGeneratorFunc(func(prefix string) string {
					if prefix == "ace" {
						return "bad\x00"
					}
					return "exception_new"
				})
			case "actor ID":
				actor.UserID = strings.Repeat("x", 1025)
			case "tenant ID":
				actor.TenantID = strings.Repeat("x", 1025)
			}
			var v riskdomain.Exception
			var err error
			if op == "create" {
				v, err = s.CreateException(t.Context(), actor, CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)})
			} else {
				v, err = s.ApproveException(t.Context(), actor, "exception")
			}
			if !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes)+len(f.audits) != 0 || f.record.Approved {
				t.Fatal("invalid dependency leaked exception effects", op, stage, v, err)
			}
		}
	}
	s, f, actor, now := exceptionFixture(t)
	s.config.IDs = application.IDGeneratorFunc(func(string) string { return strings.Repeat("x", 1025) })
	if v, err := s.CreateException(t.Context(), actor, CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)}); !errors.Is(err, ErrValidation) || v.ID != "" || f.reads+len(f.writes)+len(f.audits) != 0 {
		t.Fatal("invalid generated exception ID reached storage", v, err)
	}
	if _, err := s.ApproveException(nil, actor, "exception"); !errors.Is(err, context.Canceled) { //nolint:staticcheck // Deliberately verify the defensive nil-context boundary.
		t.Fatal("nil context accepted", err)
	}
}
func TestExceptionCommandsRejectForeignOrMisboundParentsForCreateAndApproval(t *testing.T) {
	for _, change := range []func(*exceptionCommandFixture){
		func(f *exceptionCommandFixture) {
			v := f.subjects["release/release"]
			v.ProductID = ""
			f.subjects["release/release"] = v
		},
		func(f *exceptionCommandFixture) {
			v := f.subjects["release/release"]
			v.TenantID = "other"
			f.subjects["release/release"] = v
		},
		func(f *exceptionCommandFixture) {
			v := f.subjects["finding/finding"]
			v.ReleaseID = "other"
			f.subjects["finding/finding"] = v
		},
		func(f *exceptionCommandFixture) {
			v := f.subjects["finding/finding"]
			v.ProductID = "other"
			f.subjects["finding/finding"] = v
		},
		func(f *exceptionCommandFixture) {
			v := f.subjects["control/control"]
			v.TenantID = "other"
			f.subjects["control/control"] = v
		},
	} {
		s, f, a, now := exceptionFixture(t)
		change(f)
		_, err := s.CreateException(t.Context(), a, CreateExceptionInput{ReleaseID: "release", FindingID: "finding", ControlID: "control", Reason: "Reviewed", Owner: "Owner", ExpiresAt: now.Add(time.Hour)})
		if !errors.Is(err, ErrNotFound) || len(f.writes)+len(f.audits) != 0 {
			t.Fatal("foreign/misbound exception parent accepted", err)
		}
		if _, err := s.ApproveException(t.Context(), a, "exception"); !errors.Is(err, ErrNotFound) || f.recordReads+len(f.writes)+len(f.audits) != 0 {
			t.Fatal("approval accepted foreign/misbound references before reading payload", err)
		}
	}
}
func TestExceptionCommandsRollBackWritesAuditAndCommitFailures(t *testing.T) {
	for _, op := range []string{"create", "approve"} {
		for _, stage := range []string{"write", "audit", "commit"} {
			s, f, a, now := exceptionFixture(t)
			before := f.record
			if stage == "write" {
				f.writeErr = ErrConflict
			}
			if stage == "audit" {
				f.auditErr = ErrConflict
			}
			if stage == "commit" {
				f.commitErr = ErrConflict
			}
			var v riskdomain.Exception
			var err error
			if op == "create" {
				v, err = s.CreateException(t.Context(), a, CreateExceptionInput{ReleaseID: "release", Owner: "Owner", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)})
			} else {
				v, err = s.ApproveException(t.Context(), a, "exception")
			}
			if !errors.Is(err, ErrConflict) || v.ID != "" || len(f.writes)+len(f.audits) != 0 || !reflect.DeepEqual(f.record, before) {
				t.Fatal("failed exception command leaked effects", op, stage, v, err)
			}
		}
	}
}
func TestExceptionCommandsRejectInvalidApprovalRecordsAndConfiguration(t *testing.T) {
	for _, change := range []func(*exceptionCommandFixture){func(f *exceptionCommandFixture) { f.record.ReleaseID = "other" }, func(f *exceptionCommandFixture) { f.record.TenantID = "other" }, func(f *exceptionCommandFixture) { f.record.Reason = strings.Repeat("x", 65537) }, func(f *exceptionCommandFixture) { f.record.ApprovedBy = "unrecorded" }, func(f *exceptionCommandFixture) { f.record.CreatedAt = time.Time{} }} {
		s, f, a, _ := exceptionFixture(t)
		change(f)
		if v, err := s.ApproveException(t.Context(), a, "exception"); err == nil || v.ID != "" || len(f.writes)+len(f.audits) != 0 {
			t.Fatal("malformed exception approved", v, err)
		}
	}
	s, f, a, _ := exceptionFixture(t)
	for _, change := range []func(*ExceptionCommandConfig){func(c *ExceptionCommandConfig) { c.Authorizer = nil }, func(c *ExceptionCommandConfig) { c.Transactions = nil }, func(c *ExceptionCommandConfig) { c.Clock = nil }, func(c *ExceptionCommandConfig) { c.IDs = nil }} {
		config := s.config
		change(&config)
		if _, err := NewExceptionCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal("incomplete exception configuration accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateException(ctx, a, CreateExceptionInput{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.ApproveException(ctx, a, "exception"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.AuthorizeCreateException(ctx, a, CreateExceptionInput{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.AuthorizeApproveException(ctx, a, "exception"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.reads+len(f.requests)+len(f.writes)+len(f.audits) != 0 {
		t.Fatal("cancelled exception command reached storage")
	}
}
