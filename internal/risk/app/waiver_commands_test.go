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

type waiverCommandFixture struct {
	subjects                                            map[string]GovernanceSubjectReference
	states                                              map[string]WaiverTransitionState
	record                                              riskdomain.Waiver
	writes                                              []riskdomain.Waiver
	audits                                              []application.AuditEvent
	requests                                            []application.AuthorizationRequest
	reads, recordReads                                  int
	authErr, insertErr, approveErr, auditErr, commitErr error
}

func (f *waiverCommandFixture) ExecuteWaiver(ctx context.Context, fn func(context.Context, WaiverTransaction) error) error {
	writes, audits := len(f.writes), len(f.audits)
	prior := f.record
	err := fn(ctx, f)
	if err == nil {
		err = f.commitErr
	}
	if err != nil {
		f.writes, f.audits, f.record = f.writes[:writes], f.audits[:audits], prior
	}
	return err
}
func (f *waiverCommandFixture) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	f.requests = append(f.requests, request)
	if f.authErr != nil {
		return f.authErr
	}
	return NewWaiverWriteAuthorizer().Authorize(ctx, actor, request)
}
func (f *waiverCommandFixture) ReadWaiverSubject(_ context.Context, tenant, kind, id string) (GovernanceSubjectReference, error) {
	f.reads++
	v, ok := f.subjects[kind+"/"+id]
	if !ok || v.TenantID != tenant {
		return GovernanceSubjectReference{}, ErrNotFound
	}
	return v, nil
}
func (f *waiverCommandFixture) ReadWaiverTransitionState(_ context.Context, tenant, id string) (WaiverTransitionState, error) {
	f.reads++
	v, ok := f.states[id]
	if !ok || v.TenantID != tenant {
		return WaiverTransitionState{}, ErrNotFound
	}
	return v, nil
}
func (f *waiverCommandFixture) ReadWaiverForApproval(context.Context, string, string) (riskdomain.Waiver, error) {
	f.recordReads++
	return f.record, nil
}
func (f *waiverCommandFixture) InsertWaiver(_ context.Context, v riskdomain.Waiver) error {
	f.writes = append(f.writes, v)
	return f.insertErr
}
func (f *waiverCommandFixture) ApproveWaiver(_ context.Context, v riskdomain.Waiver) error {
	f.writes = append(f.writes, v)
	f.record = v
	return f.approveErr
}
func (f *waiverCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, f.auditErr
}
func waiverFixture(t *testing.T) (*WaiverCommands, *waiverCommandFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	f := &waiverCommandFixture{subjects: map[string]GovernanceSubjectReference{
		"release/release": {Type: "release", ID: "release", TenantID: "tenant", ProductID: "product", ReleaseID: "release"},
		"finding/finding": {Type: "finding", ID: "finding", TenantID: "tenant", ProductID: "product", ReleaseID: "release"},
		"control/control": {Type: "control", ID: "control", TenantID: "tenant"},
		"policy/policy":   {Type: "policy", ID: "policy", TenantID: "tenant"},
	}, states: map[string]WaiverTransitionState{"prior": {ID: "prior", TenantID: "tenant", ScopeType: "release", ScopeID: "release", ExpiresAt: now.Add(time.Hour)}}}
	f.record = riskdomain.Waiver{ID: "prior", TenantID: "tenant", ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour), SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: now.Add(-time.Hour)}
	s, err := NewWaiverCommands(WaiverCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopePolicyWrite}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{ScopePolicyWrite}}}}
	return s, f, a, now
}

func TestWaiverCommandsCreateWithCurrentScopedAuthorizationAndAtomicAudit(t *testing.T) {
	s, f, actor, now := waiverFixture(t)
	in := CreateWaiverInput{ScopeType: " release ", ScopeID: " release ", ControlID: " control ", PolicyID: " policy ", Owner: " Owner ", Risk: " low ", Reason: " Reviewed ", ExpiresAt: now.Add(time.Hour), Supersedes: " prior "}
	if err := s.AuthorizeCreateWaiver(t.Context(), actor, in); err != nil || len(f.writes)+len(f.audits)+f.recordReads != 0 {
		t.Fatal("replay authorization changed or loaded records", err)
	}
	v, err := s.CreateWaiver(t.Context(), actor, in)
	want := riskdomain.Waiver{ID: "wv_new", TenantID: "tenant", ScopeType: "release", ScopeID: "release", ControlID: "control", PolicyID: "policy", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour), Supersedes: "prior", SchemaVersion: riskdomain.WaiverSchemaVersion, CreatedAt: now}
	if err != nil || !reflect.DeepEqual(v, want) || len(f.writes) != 1 || !reflect.DeepEqual(f.writes[0], want) || len(f.audits) != 1 || f.audits[0].EntryType != "waiver.created" || f.audits[0].SubjectID != v.ID || f.audits[0].ActorID != "human" || f.audits[0].OccurredAt != now || f.recordReads != 0 || in.Reason != " Reviewed " {
		t.Fatal("creation lost immutable fields or transaction", v, err)
	}
	// Replay authorization must not reject an already superseded prior record.
	state := f.states["prior"]
	state.SupersededBy = v.ID
	f.states["prior"] = state
	if err := s.AuthorizeCreateWaiver(t.Context(), actor, in); err != nil {
		t.Fatal("replay was blocked by its own completed transition", err)
	}
	if _, err := s.CreateWaiver(t.Context(), actor, in); !errors.Is(err, ErrConflict) || len(f.writes) != 1 || len(f.audits) != 1 {
		t.Fatal("superseded prior accepted twice", err)
	}
}

func TestWaiverCommandsApprovePreservesCoreAndReauthorizesReplay(t *testing.T) {
	s, f, actor, now := waiverFixture(t)
	before := f.record
	if err := s.AuthorizeApproveWaiver(t.Context(), actor, "prior"); err != nil || f.recordReads != 0 || len(f.writes)+len(f.audits) != 0 {
		t.Fatal("approval authorization emitted effects or fetched private record", err)
	}
	v, err := s.ApproveWaiver(t.Context(), actor, " prior ")
	want := before
	want.Approved = true
	want.ApprovedBy = "human"
	want.ApprovedAt = &now
	if err != nil || !reflect.DeepEqual(v, want) || len(f.writes) != 1 || !reflect.DeepEqual(f.record, want) || len(f.audits) != 1 || f.audits[0].EntryType != "waiver.approved" || f.audits[0].SubjectID != "prior" {
		t.Fatal("approval changed core fields or failed atomic recording", v, err)
	}
	state := f.states["prior"]
	state.Approved = true
	state.ExpiresAt = now.Add(-time.Hour)
	f.states["prior"] = state
	if err := s.AuthorizeApproveWaiver(t.Context(), actor, "prior"); err != nil {
		t.Fatal("completed replay cannot be authorized", err)
	}
	actor.ResourceGrants = nil
	if err := s.AuthorizeApproveWaiver(t.Context(), actor, "prior"); !errors.Is(err, application.ErrForbidden) || f.recordReads != 1 {
		t.Fatal("revocation did not guard replay before record reads", err)
	}
}

func TestWaiverCommandsRejectInvalidCreationBeforeStorage(t *testing.T) {
	_, _, _, now := waiverFixture(t)
	base := CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)}
	for _, change := range []func(*CreateWaiverInput){func(v *CreateWaiverInput) { v.ScopeType = "product" }, func(v *CreateWaiverInput) { v.ScopeID = "" }, func(v *CreateWaiverInput) { v.Owner = " " }, func(v *CreateWaiverInput) { v.Risk = "" }, func(v *CreateWaiverInput) { v.Reason = "\x00" }, func(v *CreateWaiverInput) { v.ScopeID = strings.Repeat("x", 1025) }, func(v *CreateWaiverInput) { v.Reason = strings.Repeat("x", 65537) }, func(v *CreateWaiverInput) { v.ExpiresAt = now }, func(v *CreateWaiverInput) { v.ExpiresAt = time.Time{} }, func(v *CreateWaiverInput) { v.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) }} {
		s, f, a, _ := waiverFixture(t)
		in := base
		change(&in)
		v, err := s.CreateWaiver(t.Context(), a, in)
		if !errors.Is(err, ErrValidation) || v.ID != "" || f.reads+f.recordReads+len(f.writes)+len(f.audits) != 0 {
			t.Fatal("invalid waiver reached storage", in, err)
		}
	}
}

func TestWaiverCommandsRequireOwnershipAndBothSupersessionGrants(t *testing.T) {
	for _, change := range []func(*waiverCommandFixture){func(f *waiverCommandFixture) { delete(f.subjects, "release/release") }, func(f *waiverCommandFixture) {
		v := f.subjects["release/release"]
		v.ProductID = ""
		f.subjects["release/release"] = v
	}, func(f *waiverCommandFixture) {
		v := f.subjects["release/release"]
		v.ReleaseID = "other"
		f.subjects["release/release"] = v
	}, func(f *waiverCommandFixture) {
		v := f.subjects["release/release"]
		v.TenantID = "other"
		f.subjects["release/release"] = v
	}} {
		s, f, a, now := waiverFixture(t)
		change(f)
		_, err := s.CreateWaiver(t.Context(), a, CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)})
		if !errors.Is(err, ErrNotFound) || len(f.writes)+len(f.audits) != 0 {
			t.Fatal("invalid parent accepted", err)
		}
	}
	s, f, a, now := waiverFixture(t)
	f.subjects["release/other"] = GovernanceSubjectReference{Type: "release", ID: "other", TenantID: "tenant", ProductID: "other-product", ReleaseID: "other"}
	state := f.states["prior"]
	state.ScopeID = "other"
	f.states["prior"] = state
	in := CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour), Supersedes: "prior"}
	if _, err := s.CreateWaiver(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || len(f.writes)+len(f.audits) != 0 {
		t.Fatal("supersession bypassed prior release grant", err)
	}
	a.ResourceGrants = append(a.ResourceGrants, identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "other", Scopes: []string{ScopePolicyWrite}})
	if _, err := s.CreateWaiver(t.Context(), a, in); err != nil {
		t.Fatal("authorized cross-scope supersession rejected", err)
	}
	for _, kind := range []string{"control", "policy"} {
		s, f, a, now = waiverFixture(t)
		in.ScopeType = kind
		in.ScopeID = kind
		in.Supersedes = ""
		in.ExpiresAt = now.Add(time.Hour)
		if _, err := s.CreateWaiver(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || len(f.writes) != 0 {
			t.Fatal("scoped grant created tenant-wide waiver", err)
		}
		a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopePolicyWrite}}}
		if _, err := s.CreateWaiver(t.Context(), a, in); err != nil {
			t.Fatal("tenant grant rejected", err)
		}
	}
}

func TestWaiverCommandsRollBackFailuresAndRejectMismatchedApprovalRecords(t *testing.T) {
	for _, op := range []string{"create", "approve"} {
		for _, stage := range []string{"write", "audit", "commit"} {
			s, f, a, now := waiverFixture(t)
			before := f.record
			if stage == "write" {
				f.insertErr = ErrConflict
				f.approveErr = ErrConflict
			}
			if stage == "audit" {
				f.auditErr = ErrConflict
			}
			if stage == "commit" {
				f.commitErr = ErrConflict
			}
			var v riskdomain.Waiver
			var err error
			if op == "create" {
				v, err = s.CreateWaiver(t.Context(), a, CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)})
			} else {
				v, err = s.ApproveWaiver(t.Context(), a, "prior")
			}
			if !errors.Is(err, ErrConflict) || v.ID != "" || len(f.writes)+len(f.audits) != 0 || !reflect.DeepEqual(f.record, before) {
				t.Fatal("failed waiver command leaked effects", op, stage, v, err)
			}
		}
	}
	for _, change := range []func(*waiverCommandFixture){func(f *waiverCommandFixture) { v := f.states["prior"]; v.Approved = true; f.states["prior"] = v }, func(f *waiverCommandFixture) {
		v := f.states["prior"]
		v.ExpiresAt = f.record.CreatedAt
		f.states["prior"] = v
	}, func(f *waiverCommandFixture) { f.record.TenantID = "other" }, func(f *waiverCommandFixture) { f.record.ScopeID = "other" }, func(f *waiverCommandFixture) { f.record.Reason = strings.Repeat("x", 65537) }} {
		s, f, a, _ := waiverFixture(t)
		change(f)
		v, err := s.ApproveWaiver(t.Context(), a, "prior")
		if err == nil || v.ID != "" || len(f.writes)+len(f.audits) != 0 {
			t.Fatal("invalid or already transitioned record approved", v, err)
		}
	}
}

func TestWaiverCommandsRejectIncompleteConfigurationAndCancelledRequests(t *testing.T) {
	s, f, a, _ := waiverFixture(t)
	for _, change := range []func(*WaiverCommandConfig){func(c *WaiverCommandConfig) { c.Authorizer = nil }, func(c *WaiverCommandConfig) { c.Transactions = nil }, func(c *WaiverCommandConfig) { c.Clock = nil }, func(c *WaiverCommandConfig) { c.IDs = nil }} {
		config := s.config
		change(&config)
		if _, err := NewWaiverCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal("incomplete configuration accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateWaiver(ctx, a, CreateWaiverInput{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.ApproveWaiver(ctx, a, "prior"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.AuthorizeCreateWaiver(ctx, a, CreateWaiverInput{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := s.AuthorizeApproveWaiver(ctx, a, "prior"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	var absent context.Context
	if _, err := s.ApproveWaiver(absent, a, "prior"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.reads+len(f.requests)+len(f.writes)+len(f.audits) != 0 {
		t.Fatal("cancelled command reached storage")
	}
}

func TestWaiverCommandsAuthorizeExpiredCreateReplayWithoutNewEffects(t *testing.T) {
	s, f, a, now := waiverFixture(t)
	in := CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(-time.Hour)}
	if err := s.AuthorizeCreateWaiver(t.Context(), a, in); err != nil || len(f.writes)+len(f.audits)+f.recordReads != 0 {
		t.Fatal("expired successful replay cannot be authorized safely", err)
	}
	if _, err := s.CreateWaiver(t.Context(), a, in); !errors.Is(err, ErrValidation) || len(f.writes)+len(f.audits) != 0 {
		t.Fatal("expired replay policy permitted a new creation", err)
	}
}

func TestWaiverCommandsRejectInvalidGeneratedIdentityAndClock(t *testing.T) {
	for _, stage := range []string{"record", "audit", "clock"} {
		s, f, a, now := waiverFixture(t)
		if stage == "clock" {
			s.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		} else {
			s.config.IDs = application.IDGeneratorFunc(func(prefix string) string {
				if stage == "record" && prefix == "wv" || stage == "audit" && prefix == "ace" {
					return "bad\x00"
				}
				return prefix + "_new"
			})
		}
		v, err := s.CreateWaiver(t.Context(), a, CreateWaiverInput{ScopeType: "release", ScopeID: "release", Owner: "Owner", Risk: "low", Reason: "Reviewed", ExpiresAt: now.Add(time.Hour)})
		if !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes)+len(f.audits) != 0 {
			t.Fatal("invalid generated metadata leaked effects", stage, v, err)
		}
	}
}
