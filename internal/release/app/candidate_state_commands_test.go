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
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type candidateStateFake struct {
	row                 CandidateStateRow
	audit               []application.AuditEvent
	authErr, auditErr   error
	requests            []application.AuthorizationRequest
	reads, writes, runs int
}

type candidateScopeAuthorizer struct {
	requests []application.AuthorizationRequest
	err      error
}

func (f *candidateScopeAuthorizer) Authorize(_ context.Context, _ identitydomain.Actor, req application.AuthorizationRequest) error {
	f.requests = append(f.requests, req)
	return f.err
}

func (f *candidateStateFake) ExecuteCandidateState(ctx context.Context, fn func(context.Context, CandidateStateTransaction) error) error {
	f.runs++
	before := f.row
	n := len(f.audit)
	if err := fn(ctx, f); err != nil {
		f.row, f.audit = before, f.audit[:n]
		return err
	}
	return nil
}
func (f *candidateStateFake) ReadCandidateState(_ context.Context, tenant, id string) (CandidateStateRow, error) {
	f.reads++
	if f.row.Candidate.ID != id || f.row.Candidate.TenantID != tenant {
		return CandidateStateRow{}, ErrNotFound
	}
	return f.row, nil
}
func (f *candidateStateFake) Authorize(_ context.Context, _ identitydomain.Actor, req application.AuthorizationRequest) error {
	f.requests = append(f.requests, req)
	return f.authErr
}
func (f *candidateStateFake) UpdateCandidateState(_ context.Context, v releasedomain.ReleaseCandidate, revision int64, state string) error {
	f.writes++
	if revision != f.row.Candidate.Revision || state != "open" {
		return ErrConflict
	}
	f.row.Candidate = v
	return nil
}
func (f *candidateStateFake) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.auditErr != nil {
		return application.AuditReceipt{}, f.auditErr
	}
	f.audit = append(f.audit, e)
	return application.AuditReceipt{}, nil
}

func TestCandidateStateCommandsAuthorizeLockedCoordinatesAndPreserveSnapshot(t *testing.T) {
	for _, target := range []string{"promoted", "rejected"} {
		t.Run(target, func(t *testing.T) {
			state, _ := releasedomain.ParseReleaseCandidateState("open")
			at := time.Date(2026, 1, 2, 3, 4, 5, 123000, time.UTC)
			original := releasedomain.ReleaseCandidate{ID: "candidate", TenantID: "tenant", ReleaseID: "release", Name: "Candidate", Revision: 1, State: state, BuildIDs: []string{"build"}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}, SnapshotHash: testSHA256('c'), SchemaVersion: releasedomain.ReleaseCandidateSchemaVersion, CreatedAt: at.Add(-time.Hour)}
			f := &candidateStateFake{row: CandidateStateRow{Candidate: original, ProductID: "product"}}
			scope := &candidateScopeAuthorizer{}
			commands, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: scope, Transactions: f, Clock: application.ClockFunc(func() time.Time { return at }), IDs: application.IDGeneratorFunc(func(string) string { return "audit" })})
			if err != nil {
				t.Fatal(err)
			}
			actor := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"release:write"}}
			v, err := commands.UpdateReleaseCandidateState(t.Context(), actor, " candidate ", target, " Reviewed ", 1)
			if err != nil {
				t.Fatal(err)
			}
			want := original
			want.State, _ = releasedomain.ParseReleaseCandidateState(target)
			want.Revision = 2
			if target == "promoted" {
				want.PromotedAt = &at
			} else {
				want.RejectedAt = &at
			}
			if !reflect.DeepEqual(v, want) || !reflect.DeepEqual(f.row.Candidate, want) || f.runs != 1 || f.reads != 1 || f.writes != 1 || len(f.audit) != 1 {
				t.Fatal("transition changed snapshot or effects", v, f)
			}
			if len(f.requests) != 1 || f.requests[0] != (application.AuthorizationRequest{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}) {
				t.Fatal("wrong locked authorization", f.requests)
			}
			if len(scope.requests) != 1 || scope.requests[0] != (application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}) {
				t.Fatal("wrong preflight scope check", scope.requests)
			}
			e := f.audit[0]
			if e.EntryType != "release_candidate."+target || e.SubjectID != "candidate" || e.SubjectType != "release_candidate" || e.TenantID != "tenant" || e.PayloadHash != original.SnapshotHash || !e.OccurredAt.Equal(at) {
				t.Fatal("wrong transition audit", e)
			}
		})
	}
}

func TestCandidateStateCommandsDenyBeforeRevisionAndRollBackAuditFailure(t *testing.T) {
	state, _ := releasedomain.ParseReleaseCandidateState("open")
	for _, tc := range []struct {
		name        string
		auth, audit error
		revision    int64
		want        error
		writes      int
	}{
		{"revoked grant", application.ErrForbidden, nil, 1, application.ErrForbidden, 0},
		{"denial hides revision", application.ErrForbidden, nil, 9, application.ErrForbidden, 0},
		{"stale revision", nil, nil, 9, ErrConflict, 0},
		{"audit failure", nil, errors.New("audit unavailable"), 1, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &candidateStateFake{row: CandidateStateRow{Candidate: releasedomain.ReleaseCandidate{ID: "candidate", TenantID: "tenant", ReleaseID: "release", State: state, Revision: 1}, ProductID: "product"}, authErr: tc.auth, auditErr: tc.audit}
			commands, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "audit" })})
			if err != nil {
				t.Fatal(err)
			}
			v, err := commands.UpdateReleaseCandidateState(t.Context(), identitydomain.Actor{TenantID: "tenant"}, "candidate", "promoted", "reviewed", tc.revision)
			want := tc.want
			if tc.audit != nil {
				want = tc.audit
			}
			if !errors.Is(err, want) || v.ID != "" || f.writes != tc.writes || f.row.Candidate.Revision != 1 || len(f.audit) != 0 {
				t.Fatal("failed command escaped rollback", v, err, f)
			}
			if revision, ok := CurrentRevision(err); tc.auth != nil && ok || tc.name == "stale revision" && (!ok || revision != 1) {
				t.Fatal("revision metadata wrong", revision, ok)
			}
		})
	}
}

func TestCandidateStateCommandsRejectInvalidInputBeforeTransaction(t *testing.T) {
	f := &candidateStateFake{}
	commands, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "audit" })})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, state, reason string
		revision          int64
	}{
		{"candidate", "promoted", " ", 1}, {"candidate", "open", "reviewed", 1}, {"candidate", "promoted", "reviewed", 0},
		{"bad\x00id", "promoted", "reviewed", 1}, {strings.Repeat("x", 1025), "promoted", "reviewed", 1},
		{"candidate", "promoted", "bad\x00reason", 1}, {"candidate", "rejected", string([]byte{255}), 1}, {"candidate", "promoted", strings.Repeat("x", 65537), 1},
	} {
		if v, err := commands.UpdateReleaseCandidateState(t.Context(), identitydomain.Actor{TenantID: "tenant"}, tc.id, tc.state, tc.reason, tc.revision); !errors.Is(err, ErrValidation) || v.ID != "" {
			t.Fatal("invalid input accepted", v, err)
		}
	}
	if f.runs != 0 {
		t.Fatal("invalid input opened transaction", f.runs)
	}
}

func TestCandidateStateCommandsRejectMissingParentsTerminalStateAndMissingScope(t *testing.T) {
	open, _ := releasedomain.ParseReleaseCandidateState("open")
	for _, tc := range []struct {
		name        string
		edit        func(*candidateStateFake)
		actorTenant string
		want        error
	}{
		{"foreign tenant", func(*candidateStateFake) {}, "other", ErrNotFound},
		{"missing parent", func(f *candidateStateFake) { f.row.ProductID = "" }, "tenant", ErrNotFound},
		{"missing release", func(f *candidateStateFake) { f.row.Candidate.ReleaseID = "" }, "tenant", ErrNotFound},
		{"already transitioned", func(f *candidateStateFake) {
			f.row.Candidate.State, _ = releasedomain.ParseReleaseCandidateState("rejected")
		}, "tenant", ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &candidateStateFake{row: CandidateStateRow{Candidate: releasedomain.ReleaseCandidate{ID: "candidate", TenantID: "tenant", ReleaseID: "release", State: open, Revision: 1}, ProductID: "product"}}
			tc.edit(f)
			commands, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "audit" })})
			if err != nil {
				t.Fatal(err)
			}
			if v, err := commands.UpdateReleaseCandidateState(t.Context(), identitydomain.Actor{TenantID: tc.actorTenant}, "candidate", "promoted", "reviewed", 1); !errors.Is(err, tc.want) || v.ID != "" || f.writes != 0 || len(f.audit) != 0 {
				t.Fatal("invalid parent/state accepted", v, err, f)
			}
		})
	}
	f := &candidateStateFake{}
	commands, err := NewCandidateStateCommands(CandidateStateCommandConfig{Authorizer: &candidateScopeAuthorizer{err: application.ErrForbidden}, Transactions: f, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "audit" })})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := commands.UpdateReleaseCandidateState(t.Context(), identitydomain.Actor{TenantID: "tenant"}, "candidate", "promoted", "reviewed", 1); !errors.Is(err, application.ErrForbidden) || v.ID != "" || f.runs != 0 {
		t.Fatal("missing scope reached storage", v, err, f)
	}
}
