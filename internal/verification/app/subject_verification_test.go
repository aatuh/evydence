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
	c, err := NewSubjectVerificationCommands(SubjectVerificationConfig{Authorizer: f, AuditChain: f, Evidence: f, ReleaseBundle: f, DSSE: f, ArtifactSignature: f, Merkle: f, MerkleCheckpoint: f, ReleaseManifestCheckpoint: f, Backup: f})
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
	base := SubjectVerificationConfig{Authorizer: f, AuditChain: f, Evidence: f, ReleaseBundle: f, DSSE: f, ArtifactSignature: f, Merkle: f, MerkleCheckpoint: f, ReleaseManifestCheckpoint: f, Backup: f}
	for _, omit := range []func(*SubjectVerificationConfig){
		func(c *SubjectVerificationConfig) { c.Authorizer = nil }, func(c *SubjectVerificationConfig) { c.AuditChain = nil }, func(c *SubjectVerificationConfig) { c.Evidence = nil }, func(c *SubjectVerificationConfig) { c.ReleaseBundle = nil }, func(c *SubjectVerificationConfig) { c.DSSE = nil }, func(c *SubjectVerificationConfig) { c.ArtifactSignature = nil }, func(c *SubjectVerificationConfig) { c.Merkle = nil }, func(c *SubjectVerificationConfig) { c.MerkleCheckpoint = nil }, func(c *SubjectVerificationConfig) { c.ReleaseManifestCheckpoint = nil }, func(c *SubjectVerificationConfig) { c.Backup = nil },
	} {
		config := base
		omit(&config)
		if c, err := NewSubjectVerificationCommands(config); !errors.Is(err, ErrValidation) || c != nil {
			t.Fatal(c, err)
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
