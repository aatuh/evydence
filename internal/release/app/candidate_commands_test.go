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

type candidateCreationFake struct {
	parent                                CandidateReleaseCoordinates
	refs                                  ReleaseCandidateReferences
	requests                              []application.AuthorizationRequest
	candidates                            []releasedomain.ReleaseCandidate
	audit                                 []application.AuditEvent
	refsErr, authErr, insertErr, auditErr error
	runs, reads, refCalls                 int
}

func (f *candidateCreationFake) ExecuteCandidateCreation(ctx context.Context, fn func(context.Context, CandidateCreationTransaction) error) error {
	f.runs++
	n, m := len(f.candidates), len(f.audit)
	if err := fn(ctx, f); err != nil {
		f.candidates, f.audit = f.candidates[:n], f.audit[:m]
		return err
	}
	return nil
}
func (f *candidateCreationFake) ReadCandidateRelease(_ context.Context, tenant, id string) (CandidateReleaseCoordinates, error) {
	f.reads++
	if f.parent.TenantID != tenant || f.parent.ID != id {
		return CandidateReleaseCoordinates{}, ErrNotFound
	}
	return f.parent, nil
}
func (f *candidateCreationFake) ValidateReleaseCandidateReferences(_ context.Context, tenant, release string, refs ReleaseCandidateReferences) error {
	f.refCalls++
	if tenant != f.parent.TenantID || release != f.parent.ID {
		return ErrNotFound
	}
	f.refs = refs
	return f.refsErr
}
func (f *candidateCreationFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	f.requests = append(f.requests, r)
	return f.authErr
}
func (f *candidateCreationFake) InsertCandidate(_ context.Context, v releasedomain.ReleaseCandidate) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.candidates = append(f.candidates, v)
	return nil
}
func (f *candidateCreationFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.auditErr != nil {
		return application.AuditReceipt{}, f.auditErr
	}
	f.audit = append(f.audit, v)
	return application.AuditReceipt{}, nil
}

func TestCandidateCreationUsesCurrentCoordinatesAndAtomicSnapshot(t *testing.T) {
	f := &candidateCreationFake{parent: CandidateReleaseCoordinates{ID: "release", TenantID: "tenant", ProductID: "product"}}
	canonicalizer := &fakeReleaseCandidateCanonicalizer{hash: testSHA256('c')}
	scope := &candidateScopeAuthorizer{}
	at := time.Date(2026, 1, 2, 3, 4, 5, 123000, time.UTC)
	commands, err := NewCandidateCommands(CandidateCommandConfig{Authorizer: scope, Transactions: f, Canonicalizer: canonicalizer, Clock: application.ClockFunc(func() time.Time { return at }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_1" })})
	if err != nil {
		t.Fatal(err)
	}
	in := CreateReleaseCandidateInput{ReleaseID: " release ", Name: " Candidate ", BuildIDs: []string{" build2 ", "build1"}, ArtifactIDs: []string{" artifact "}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}}
	v, err := commands.CreateReleaseCandidate(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "key"}, in)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "rc_1" || v.TenantID != "tenant" || v.ReleaseID != "release" || v.Name != "Candidate" || v.Revision != 1 || v.State.String() != "open" || v.SchemaVersion != releasedomain.ReleaseCandidateSchemaVersion || v.SnapshotHash != testSHA256('c') || !v.CreatedAt.Equal(at) || v.PromotedAt != nil || v.RejectedAt != nil {
		t.Fatal("candidate fields changed", v)
	}
	want := ReleaseCandidateReferences{BuildIDs: []string{"build1", "build2"}, ArtifactIDs: []string{"artifact"}, SBOMIDs: []string{"sbom"}, ScanIDs: []string{"scan"}, VEXIDs: []string{"vex"}, ContractIDs: []string{"contract"}, BundleIDs: []string{"bundle"}}
	if !reflect.DeepEqual(f.refs, want) || f.runs != 1 || f.reads != 1 || f.refCalls != 1 || len(f.candidates) != 1 || len(f.audit) != 1 || !reflect.DeepEqual(f.candidates[0], v) {
		t.Fatal("transaction/reference effects changed", f)
	}
	if len(scope.requests) != 1 || scope.requests[0] != (application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}) || !reflect.DeepEqual(f.requests, []application.AuthorizationRequest{{Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}}, {Scope: ScopeReleaseWrite, Resources: application.ResourceReferences{ArtifactID: "artifact"}}}) {
		t.Fatal("authorization skipped current parent or artifact", scope, f.requests)
	}
	hashed := v
	hashed.SnapshotHash = ""
	if canonicalizer.calls != 1 || !reflect.DeepEqual(canonicalizer.candidate, hashed) {
		t.Fatal("canonicalizer input changed", canonicalizer)
	}
	e := f.audit[0]
	if e.EntryType != "release_candidate.created" || e.SubjectType != "release_candidate" || e.SubjectID != v.ID || e.PayloadHash != v.SnapshotHash || e.TenantID != v.TenantID || !e.OccurredAt.Equal(at) {
		t.Fatal("candidate audit mismatch", e)
	}
	in.BuildIDs[0] = "mutated"
	if !reflect.DeepEqual(v.BuildIDs, []string{"build1", "build2"}) {
		t.Fatal("caller retained candidate slice ownership")
	}
}

func TestCandidateCreationDenialsAndFailuresHaveNoDurableEffects(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*candidateCreationFake, *fakeReleaseCandidateCanonicalizer)
		tenant string
		want   error
	}{
		{"foreign parent", func(*candidateCreationFake, *fakeReleaseCandidateCanonicalizer) {}, "other", ErrNotFound},
		{"missing product", func(f *candidateCreationFake, _ *fakeReleaseCandidateCanonicalizer) { f.parent.ProductID = "" }, "tenant", ErrNotFound},
		{"removed grant", func(f *candidateCreationFake, _ *fakeReleaseCandidateCanonicalizer) {
			f.authErr = application.ErrForbidden
		}, "tenant", application.ErrForbidden},
		{"foreign reference", func(f *candidateCreationFake, _ *fakeReleaseCandidateCanonicalizer) { f.refsErr = ErrNotFound }, "tenant", ErrNotFound},
		{"bad hash", func(_ *candidateCreationFake, c *fakeReleaseCandidateCanonicalizer) { c.hash = "invalid" }, "tenant", ErrValidation},
		{"insert failure", func(f *candidateCreationFake, _ *fakeReleaseCandidateCanonicalizer) { f.insertErr = ErrConflict }, "tenant", ErrConflict},
		{"audit failure", func(f *candidateCreationFake, _ *fakeReleaseCandidateCanonicalizer) { f.auditErr = ErrConflict }, "tenant", ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &candidateCreationFake{parent: CandidateReleaseCoordinates{ID: "release", TenantID: "tenant", ProductID: "product"}}
			c := &fakeReleaseCandidateCanonicalizer{hash: testSHA256('c')}
			tc.edit(f, c)
			commands, err := NewCandidateCommands(CandidateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Canonicalizer: c, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_1" })})
			if err != nil {
				t.Fatal(err)
			}
			if v, err := commands.CreateReleaseCandidate(t.Context(), identitydomain.Actor{TenantID: tc.tenant}, CreateReleaseCandidateInput{ReleaseID: "release", Name: "Candidate", ArtifactIDs: []string{"artifact"}}); !errors.Is(err, tc.want) || v.ID != "" || len(f.candidates) != 0 || len(f.audit) != 0 {
				t.Fatal("failed candidate escaped rollback", v, err, f)
			}
			if tc.name == "removed grant" && (f.refCalls != 0 || c.calls != 0) {
				t.Fatal("denied actor reached foreign references or hash")
			}
		})
	}
}

func TestCandidateCreationValidatesBoundsBeforeTransaction(t *testing.T) {
	f := &candidateCreationFake{}
	c := &fakeReleaseCandidateCanonicalizer{hash: testSHA256('c')}
	commands, err := NewCandidateCommands(CandidateCommandConfig{Authorizer: &candidateScopeAuthorizer{}, Transactions: f, Canonicalizer: c, Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(func(string) string { return "id" })})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []CreateReleaseCandidateInput{
		{ReleaseID: "release", Name: " "}, {ReleaseID: "bad\x00id", Name: "Candidate"}, {ReleaseID: strings.Repeat("x", 1025), Name: "Candidate"},
		{ReleaseID: "release", Name: strings.Repeat("x", 65537)}, {ReleaseID: "release", Name: "bad\x00name"}, {ReleaseID: "release", Name: string([]byte{255})},
		{ReleaseID: "release", Name: "Candidate", BuildIDs: []string{" "}}, {ReleaseID: "release", Name: "Candidate", ArtifactIDs: []string{"bad\x00id"}},
		{ReleaseID: "release", Name: "Candidate", SBOMIDs: []string{strings.Repeat("x", 1025)}}, {ReleaseID: "release", Name: "Candidate", BuildIDs: make([]string, 4097)},
	} {
		if v, err := commands.CreateReleaseCandidate(t.Context(), identitydomain.Actor{TenantID: "tenant"}, in); !errors.Is(err, ErrValidation) || v.ID != "" {
			t.Fatal("invalid candidate input accepted", v, err)
		}
	}
	if f.runs != 0 || c.calls != 0 {
		t.Fatal("invalid candidate reached transaction/hash", f, c)
	}
}

func TestCandidateReferenceBudgetsBoundCombinedWorkWithoutDeduplicating(t *testing.T) {
	refs := ReleaseCandidateReferences{BuildIDs: make([]string, 4096)}
	for i := range refs.BuildIDs {
		refs.BuildIDs[i] = "b"
	}
	if !ValidCandidateReferences(refs) {
		t.Fatal("exact count budget rejected")
	}
	refs.ArtifactIDs = []string{"a"}
	if ValidCandidateReferences(refs) {
		t.Fatal("combined reference count exceeded budget")
	}
	refs = ReleaseCandidateReferences{BuildIDs: make([]string, 64)}
	for i := range refs.BuildIDs {
		refs.BuildIDs[i] = strings.Repeat("x", 1024)
	}
	if !ValidCandidateReferences(refs) {
		t.Fatal("exact identifier-byte budget rejected")
	}
	refs.BundleIDs = []string{"b"}
	if ValidCandidateReferences(refs) {
		t.Fatal("combined identifier bytes exceeded budget")
	}
	if got := normalizeReleaseCandidateReferences(CreateReleaseCandidateInput{BuildIDs: []string{" b ", "a", "b"}}).BuildIDs; !reflect.DeepEqual(got, []string{"a", "b", "b"}) {
		t.Fatal("reference normalization removed intentional duplicates", got)
	}
}
