package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type subjectDispatchFake struct {
	calls        []string
	actor        identitydomain.Actor
	id           string
	err, authErr error
	authCalls    int
}

func (f *subjectDispatchFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	f.authCalls++
	if r.Scope != ScopeVerifyRead || !r.ScopeOnly || r.TenantWide || !emptyResources(r.Resources) {
		return errors.New("dispatcher changed resource authorization policy")
	}
	return f.authErr
}
func (f *subjectDispatchFake) run(a identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	f.calls = append(f.calls, kind)
	f.actor, f.id = a, id
	return verificationdomain.VerificationResult{ID: "receipt", SubjectType: kind, SubjectID: id, TenantID: a.TenantID}, f.err
}
func (f *subjectDispatchFake) VerifyAuditChain(_ context.Context, a identitydomain.Actor) (verificationdomain.VerificationResult, error) {
	return f.run(a, "audit_chain", "")
}
func (f *subjectDispatchFake) VerifyEvidence(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "evidence_item", id)
}
func (f *subjectDispatchFake) VerifyReleaseBundle(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "release_bundle", id)
}
func (f *subjectDispatchFake) VerifyDSSEAttestationSignature(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "build_attestation", id)
}
func (f *subjectDispatchFake) VerifyArtifactSignature(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "artifact_signature", id)
}
func (f *subjectDispatchFake) VerifyMerkleBatch(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "merkle_batch", id)
}
func (f *subjectDispatchFake) VerifyMerkleCheckpoint(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "audit_chain_checkpoint", id)
}
func (f *subjectDispatchFake) VerifyReleaseManifestCheckpoint(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "audit_chain_release_manifest", id)
}
func (f *subjectDispatchFake) VerifyBackupManifest(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return f.run(a, "backup_manifest", id)
}

func subjectDispatchFixture(t *testing.T) (*SubjectVerificationCommands, *subjectDispatchFake) {
	t.Helper()
	f := &subjectDispatchFake{}
	c, err := NewSubjectVerificationCommands(SubjectVerificationConfig{Authorizer: f, ReplayTransactions: &subjectScopeFake{}, AuditChain: f, Evidence: f, ReleaseBundle: f, DSSE: f, ArtifactSignature: f, Merkle: f, MerkleCheckpoint: f, ReleaseManifestCheckpoint: f, Backup: f})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestSubjectVerificationDispatchesOnlyToItsFocusedCommand(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, kind := range []string{"audit_chain", "evidence_item", "release_bundle", "build_attestation", "artifact_signature", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest"} {
		t.Run(kind, func(t *testing.T) {
			for _, failure := range []error{nil, ErrVerificationFailed, ErrForbidden, ErrNotFound, ErrConflict, context.Canceled, errors.New("private storage failure")} {
				c, f := subjectDispatchFixture(t)
				f.err = failure
				id := "subject"
				if kind == "audit_chain" {
					id = ""
				}
				r, err := c.VerifySubject(t.Context(), a, " "+kind+" ", " "+id+" ")
				if err != failure || r.ID != "receipt" || r.SubjectType != kind || r.SubjectID != id || r.TenantID != a.TenantID || !reflect.DeepEqual(f.calls, []string{kind}) || !reflect.DeepEqual(f.actor, a) || f.id != id || f.authCalls != 1 {
					t.Fatal(r, err, f)
				}
			}
		})
	}
}

func TestSubjectVerificationRejectsInvalidRequestsBeforeDispatch(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, tc := range []struct {
		kind, id string
		want     error
	}{
		{"", "id", ErrValidation}, {" ", "id", ErrValidation}, {"backup_manifest", "", ErrValidation}, {"backup_manifest", " ", ErrValidation}, {"audit_chain", "id", ErrValidation},
		{strings.Repeat("x", 65), "id", ErrValidation}, {"backup_manifest", strings.Repeat("x", 1025), ErrValidation}, {"bad\x00type", "id", ErrValidation}, {"backup_manifest", "bad\x00id", ErrValidation}, {string([]byte{255}), "id", ErrValidation}, {"backup_manifest", string([]byte{255}), ErrValidation}, {"unknown", "id", ErrValidation},
	} {
		c, f := subjectDispatchFixture(t)
		r, err := c.VerifySubject(t.Context(), a, tc.kind, tc.id)
		if !errors.Is(err, tc.want) || r.ID != "" || len(f.calls) != 0 {
			t.Fatal(tc, r, err, f)
		}
	}
	for _, kind := range []string{"backup_manifest", "unknown"} {
		c, f := subjectDispatchFixture(t)
		f.authErr = ErrForbidden
		if _, err := c.VerifySubject(t.Context(), a, kind, "id"); !errors.Is(err, ErrForbidden) || len(f.calls) != 0 {
			t.Fatal(err, f)
		}
	}
	c, f := subjectDispatchFixture(t)
	if _, err := c.VerifySubject(t.Context(), identitydomain.Actor{}, "backup_manifest", "id"); !errors.Is(err, ErrForbidden) || f.authCalls != 0 {
		t.Fatal(err, f)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if _, err := c.VerifySubject(ctx, a, "backup_manifest", "id"); !errors.Is(err, context.Canceled) || f.authCalls != 0 || len(f.calls) != 0 {
			t.Fatal(err, f)
		}
	}
}

func TestSubjectVerificationRequiresEveryFocusedDependency(t *testing.T) {
	_, f := subjectDispatchFixture(t)
	base := SubjectVerificationConfig{Authorizer: f, ReplayTransactions: &subjectScopeFake{}, AuditChain: f, Evidence: f, ReleaseBundle: f, DSSE: f, ArtifactSignature: f, Merkle: f, MerkleCheckpoint: f, ReleaseManifestCheckpoint: f, Backup: f}
	for _, omit := range []func(*SubjectVerificationConfig){
		func(c *SubjectVerificationConfig) { c.ReplayTransactions = nil },
		func(c *SubjectVerificationConfig) { c.Authorizer = nil }, func(c *SubjectVerificationConfig) { c.AuditChain = nil }, func(c *SubjectVerificationConfig) { c.Evidence = nil }, func(c *SubjectVerificationConfig) { c.ReleaseBundle = nil }, func(c *SubjectVerificationConfig) { c.DSSE = nil }, func(c *SubjectVerificationConfig) { c.ArtifactSignature = nil }, func(c *SubjectVerificationConfig) { c.Merkle = nil }, func(c *SubjectVerificationConfig) { c.MerkleCheckpoint = nil }, func(c *SubjectVerificationConfig) { c.ReleaseManifestCheckpoint = nil }, func(c *SubjectVerificationConfig) { c.Backup = nil },
	} {
		config := base
		omit(&config)
		if c, err := NewSubjectVerificationCommands(config); !errors.Is(err, ErrValidation) || c != nil {
			t.Fatal(c, err)
		}
	}
}

type subjectScopeFake struct {
	subject                                   SubjectReference
	request                                   application.AuthorizationRequest
	actor                                     identitydomain.Actor
	err, authErr, commitErr                   error
	transactions, resolutions, authorizations int
}

func (f *subjectScopeFake) ExecuteSubjectVerificationScope(ctx context.Context, run func(context.Context, SubjectVerificationScopeTransaction) error) error {
	f.transactions++
	if err := run(ctx, f); err != nil {
		return err
	}
	return f.commitErr
}
func (f *subjectScopeFake) ResolveSubjectVerificationScope(_ context.Context, tenant, kind, id string) (SubjectReference, error) {
	f.resolutions++
	if tenant != "tenant" || kind != f.subject.Type || id != f.subject.ID {
		return SubjectReference{}, ErrNotFound
	}
	return f.subject, f.err
}
func (f *subjectScopeFake) Authorize(_ context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	f.authorizations++
	f.actor, f.request = actor, request
	return f.authErr
}

func TestSubjectVerificationReplayGuardUsesOnlyCurrentScope(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, kind := range []string{"audit_chain", "evidence_item", "release_bundle", "build_attestation", "artifact_signature", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest"} {
		t.Run(kind, func(t *testing.T) {
			c, dispatch := subjectDispatchFixture(t)
			id := "id"
			refs := application.ResourceReferences{}
			switch kind {
			case "audit_chain":
				id = ""
			case "evidence_item":
				refs.ProjectID = "project"
			case "release_bundle":
				refs.ProductID, refs.ReleaseID = "product", "release"
			case "build_attestation":
				refs.ProjectID, refs.ReleaseID, refs.BuildID = "project", "release", "build"
			case "artifact_signature":
				refs.ArtifactID = "artifact"
			}
			f := &subjectScopeFake{subject: SubjectReference{TenantID: a.TenantID, Type: kind, ID: id, Resources: refs}}
			c.config.ReplayTransactions = f
			if err := c.AuthorizeSubjectVerification(t.Context(), a, " "+kind+" ", " "+id+" "); err != nil {
				t.Fatal(err)
			}
			want := application.AuthorizationRequest{Scope: ScopeVerifyRead, Resources: refs, TenantWide: emptyResources(refs)}
			if f.transactions != 1 || f.resolutions != 1 || f.authorizations != 1 || f.request != want || !reflect.DeepEqual(f.actor, a) || len(dispatch.calls) != 0 || dispatch.authCalls != 1 {
				t.Fatal("guard inspected or changed policy", f, dispatch)
			}
			for _, failure := range []error{ErrForbidden, ErrNotFound, context.Canceled, errVerificationTestFailure} {
				f.authErr = failure
				if err := c.AuthorizeSubjectVerification(t.Context(), a, kind, id); err != failure || len(dispatch.calls) != 0 {
					t.Fatal(err, dispatch)
				}
			}
			f.authErr = nil
			f.commitErr = errVerificationTestFailure
			if err := c.AuthorizeSubjectVerification(t.Context(), a, kind, id); err != f.commitErr {
				t.Fatal(err)
			}
			f.subject.TenantID = "other"
			before := f.authorizations
			if err := c.AuthorizeSubjectVerification(t.Context(), a, kind, id); !errors.Is(err, ErrNotFound) || f.authorizations != before {
				t.Fatal(err, f)
			}
		})
	}
}

func TestSubjectVerificationReplayRejectsInvalidScopeBeforePermission(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, tc := range []struct {
		kind string
		refs application.ResourceReferences
	}{
		{"audit_chain", application.ResourceReferences{ReleaseID: "release"}},
		{"audit_chain_release_manifest", application.ResourceReferences{ReleaseID: "release"}},
		{"backup_manifest", application.ResourceReferences{ProductID: "product"}},
		{"release_bundle", application.ResourceReferences{ReleaseID: "release"}},
		{"artifact_signature", application.ResourceReferences{ArtifactID: "artifact", ProductID: "product"}},
		{"build_attestation", application.ResourceReferences{ProjectID: "project"}},
		{"evidence_item", application.ResourceReferences{ProductID: " padded "}},
		{"evidence_item", application.ResourceReferences{ProjectID: strings.Repeat("x", 1025)}},
		{"evidence_item", application.ResourceReferences{CustomerPackageID: "package"}},
	} {
		c, dispatch := subjectDispatchFixture(t)
		id := "id"
		if tc.kind == "audit_chain" {
			id = ""
		}
		f := &subjectScopeFake{subject: SubjectReference{TenantID: a.TenantID, Type: tc.kind, ID: id, Resources: tc.refs}}
		c.config.ReplayTransactions = f
		if err := c.AuthorizeSubjectVerification(t.Context(), a, tc.kind, id); !errors.Is(err, ErrConflict) || f.authorizations != 0 || len(dispatch.calls) != 0 {
			t.Fatal(tc, err, f, dispatch)
		}
	}
}

func TestSubjectVerificationReplayRejectsInputAndScopeBeforeStorage(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, tc := range []struct {
		actor    identitydomain.Actor
		kind, id string
		want     error
	}{
		{identitydomain.Actor{}, "audit_chain", "", ErrForbidden},
		{identitydomain.Actor{TenantID: " tenant ", KeyID: "caller"}, "audit_chain", "", ErrValidation},
		{a, "unknown", "id", ErrValidation},
		{a, "audit_chain", strings.Repeat(" ", 1025), ErrValidation},
		{a, "backup_manifest", "bad\x00id", ErrValidation},
	} {
		c, _ := subjectDispatchFixture(t)
		f := &subjectScopeFake{}
		c.config.ReplayTransactions = f
		if err := c.AuthorizeSubjectVerification(t.Context(), tc.actor, tc.kind, tc.id); !errors.Is(err, tc.want) || f.transactions != 0 {
			t.Fatal(tc, err, f)
		}
	}
	c, dispatch := subjectDispatchFixture(t)
	f := &subjectScopeFake{}
	c.config.ReplayTransactions = f
	dispatch.authErr = ErrForbidden
	if err := c.AuthorizeSubjectVerification(t.Context(), a, "audit_chain", ""); !errors.Is(err, ErrForbidden) || f.transactions != 0 {
		t.Fatal(err, f)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := dispatch.authCalls
	for _, ctx := range []context.Context{nil, ctx} {
		if err := c.AuthorizeSubjectVerification(ctx, a, "audit_chain", ""); !errors.Is(err, context.Canceled) || dispatch.authCalls != before || f.transactions != 0 {
			t.Fatal(err, f, dispatch)
		}
	}
}

func TestSubjectVerificationPreservesTransactionalResourceAuthorizationAndEffects(t *testing.T) {
	for _, failure := range []string{"", "auth", "foreign", "failed", "audit", "outbox", "commit"} {
		t.Run(failure, func(t *testing.T) {
			backup, storage := backupVerificationFixture(t)
			c, dispatch := subjectDispatchFixture(t)
			c.config.Backup = backup
			storage.fail = failure
			if failure == "foreign" {
				storage.point.Subject.TenantID = "other"
			}
			if failure == "failed" {
				storage.point.Checks[0].Result = "failed"
			}
			r, err := c.VerifySubject(t.Context(), identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}, "backup_manifest", "backup")
			want := 0
			switch failure {
			case "":
				want = 1
				if err != nil || r.Result.String() != "passed" {
					t.Fatal(r, err)
				}
			case "failed":
				want = 1
				if !errors.Is(err, ErrVerificationFailed) || r.Result.String() != "failed" {
					t.Fatal(r, err)
				}
			case "auth":
				if !errors.Is(err, ErrForbidden) || storage.payloadReads != 0 {
					t.Fatal("scope check bypassed resource authorization", err, storage)
				}
			case "foreign":
				if !errors.Is(err, ErrNotFound) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, errVerificationTestFailure) {
					t.Fatal(err)
				}
			}
			if len(storage.results) != want || len(storage.audits) != want || len(storage.jobs) != want || want == 0 && r.ID != "" || dispatch.authCalls != 1 || len(dispatch.calls) != 0 {
				t.Fatal("dispatcher changed transaction effects", r, storage, dispatch)
			}
		})
	}
}

func TestSubjectVerificationBoundsRawInputBeforeNormalization(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller"}
	for _, tc := range []struct{ kind, id string }{
		{strings.Repeat(" ", 65) + "audit_chain", ""},
		{"backup_manifest", strings.Repeat(" ", 1025) + "id"},
		{"audit_chain", strings.Repeat(" ", 1025)},
	} {
		c, f := subjectDispatchFixture(t)
		if r, err := c.VerifySubject(t.Context(), a, tc.kind, tc.id); !errors.Is(err, ErrValidation) || r.ID != "" || len(f.calls) != 0 {
			t.Fatalf("raw input bypassed budget: result=%+v error=%v dispatch=%v", r, err, f.calls)
		}
	}
	c, f := subjectDispatchFixture(t)
	a.TenantID = " tenant "
	if _, err := c.VerifySubject(t.Context(), a, "audit_chain", ""); !errors.Is(err, ErrValidation) || len(f.calls) != 0 {
		t.Fatalf("noncanonical actor dispatched: error=%v calls=%v", err, f.calls)
	}
}

func TestSubjectVerificationHasReadOnlyReplayAuthorization(t *testing.T) {
	c, _ := subjectDispatchFixture(t)
	if _, ok := any(c).(interface {
		AuthorizeSubjectVerification(context.Context, identitydomain.Actor, string, string) error
	}); !ok {
		t.Fatal("generic verification has no current-ownership replay guard")
	}
}
