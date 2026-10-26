package app_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Child ports observe dispatch only; their zero assurance state deliberately
// supplies no signature, storage or verification proof. Those owners execute
// separately in the native inspection and checkpoint properties.
type nativeFuzzDispatch struct {
	subject verificationapp.SubjectReference
	calls   []string
	actor   identitydomain.Actor
	id      string
	err     error
}

func (s *nativeFuzzDispatch) run(actor identitydomain.Actor, kind, id string) (verificationdomain.VerificationResult, error) {
	s.calls = append(s.calls, kind)
	s.actor, s.id = actor, id
	return verificationdomain.VerificationResult{ID: "dispatch-only", TenantID: actor.TenantID, SubjectType: kind, SubjectID: id}, s.err
}
func (s *nativeFuzzDispatch) VerifyAuditChain(_ context.Context, a identitydomain.Actor) (verificationdomain.VerificationResult, error) {
	return s.run(a, "audit_chain", "")
}
func (s *nativeFuzzDispatch) VerifyEvidence(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "evidence_item", id)
}
func (s *nativeFuzzDispatch) VerifyReleaseBundle(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "release_bundle", id)
}
func (s *nativeFuzzDispatch) VerifyDSSEAttestationSignature(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "build_attestation", id)
}
func (s *nativeFuzzDispatch) VerifyArtifactSignature(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "artifact_signature", id)
}
func (s *nativeFuzzDispatch) VerifyMerkleBatch(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "merkle_batch", id)
}
func (s *nativeFuzzDispatch) VerifyMerkleCheckpoint(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "audit_chain_checkpoint", id)
}
func (s *nativeFuzzDispatch) VerifyReleaseManifestCheckpoint(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "audit_chain_release_manifest", id)
}
func (s *nativeFuzzDispatch) VerifyBackupManifest(_ context.Context, a identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	return s.run(a, "backup_manifest", id)
}
func (s *nativeFuzzDispatch) ExecuteSubjectVerificationScope(ctx context.Context, fn func(context.Context, verificationapp.SubjectVerificationScopeTransaction) error) error {
	return fn(ctx, s)
}
func (s *nativeFuzzDispatch) ResolveSubjectVerificationScope(context.Context, string, string, string) (verificationapp.SubjectReference, error) {
	return s.subject, nil
}
func (s *nativeFuzzDispatch) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return verificationquery.NewSubjectVerificationAuthorizer().Authorize(ctx, a, r)
}

func nativeFuzzSubjectCommands(t *testing.T, s *nativeFuzzDispatch) *verificationapp.SubjectVerificationCommands {
	t.Helper()
	c, err := verificationapp.NewSubjectVerificationCommands(verificationapp.SubjectVerificationConfig{Authorizer: s, ReplayTransactions: s, AuditChain: s, Evidence: s, ReleaseBundle: s, DSSE: s, ArtifactSignature: s, Merkle: s, MerkleCheckpoint: s, ReleaseManifestCheckpoint: s, Backup: s})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func FuzzSubjectVerificationDispatch(f *testing.F) {
	for i, kind := range []string{"audit_chain", "evidence_item", "release_bundle", "build_attestation", "artifact_signature", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest"} {
		id := " subject "
		if kind == "audit_chain" {
			id = " \t"
		}
		f.Add(" "+kind+" ", id, uint8(i))
	}
	for _, pair := range [][2]string{{"unknown", "id"}, {"audit_chain", "unexpected"}, {"backup_manifest", ""}, {"bad\x00kind", "id"}, {"evidence_item", string([]byte{255})}, {"evidence_item", strings.Repeat("x", 1025)}} {
		f.Add(pair[0], pair[1], uint8(0))
	}
	f.Fuzz(func(t *testing.T, rawKind, rawID string, mode uint8) {
		if len(rawKind)+len(rawID) > 8192 {
			return
		}
		kind, id := strings.TrimSpace(rawKind), strings.TrimSpace(rawID)
		known := false
		refs := application.ResourceReferences{}
		switch kind {
		case "audit_chain":
			known = id == ""
		case "release_bundle":
			known, refs = id != "", application.ResourceReferences{ProductID: "product", ReleaseID: "release"}
		case "build_attestation":
			known, refs = id != "", application.ResourceReferences{ProjectID: "project", ReleaseID: "release", BuildID: "build"}
		case "artifact_signature":
			known, refs = id != "", application.ResourceReferences{ArtifactID: "artifact"}
		case "evidence_item", "merkle_batch", "audit_chain_checkpoint", "audit_chain_release_manifest", "backup_manifest":
			known = id != ""
		}
		valid := known && len(rawKind) <= 64 && len(rawID) <= 1024 && utf8.ValidString(rawKind) && utf8.ValidString(rawID) && !strings.ContainsRune(rawKind, 0) && !strings.ContainsRune(rawID, 0)
		port := &nativeFuzzDispatch{subject: verificationapp.SubjectReference{TenantID: "tenant", Type: kind, ID: id, Resources: refs}}
		port.err = []error{nil, verificationapp.ErrVerificationFailed, verificationapp.ErrConflict, context.Canceled}[mode%4]
		command := nativeFuzzSubjectCommands(t, port)
		actor := nativeFuzzActor()
		before := nativeFuzzJSON(t, actor)
		result, err := command.VerifySubject(t.Context(), actor, rawKind, rawID)
		if !valid {
			if !errors.Is(err, verificationapp.ErrValidation) || len(port.calls) != 0 || result.ID != "" {
				t.Fatal("invalid/unknown subject dispatched to a child")
			}
			return
		}
		if err != port.err || !reflect.DeepEqual(port.calls, []string{kind}) || !reflect.DeepEqual(port.actor, actor) || port.id != id || result.TenantID != actor.TenantID || result.SubjectType != kind || result.SubjectID != id || result.Result.String() == "passed" || nativeFuzzJSON(t, actor) != before {
			t.Fatal("dispatch changed subject/actor/error or invented assurance")
		}
		if err := command.AuthorizeSubjectVerification(t.Context(), actor, rawKind, rawID); err != nil || len(port.calls) != 1 {
			t.Fatal("scope replay guard invoked child inspection or rejected current owner", err)
		}
		// Current identity is rechecked before durable replay, including for
		// a previously accepted dispatch-only response.
		port.subject.TenantID = "foreign"
		if err := command.AuthorizeSubjectVerification(t.Context(), actor, rawKind, rawID); !errors.Is(err, verificationapp.ErrNotFound) || len(port.calls) != 1 {
			t.Fatal("foreign current ownership accepted for replay")
		}
		actor.Scopes = nil
		if _, err := command.VerifySubject(t.Context(), actor, rawKind, rawID); !errors.Is(err, application.ErrForbidden) || len(port.calls) != 1 {
			t.Fatal("removed scope still dispatched")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := command.VerifySubject(ctx, nativeFuzzActor(), rawKind, rawID); !errors.Is(err, context.Canceled) || len(port.calls) != 1 {
			t.Fatal("canceled request dispatched")
		}
	})
}
