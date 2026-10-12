package app

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type verificationServicePolicy struct {
	t    *testing.T
	want []application.AuthorizationRequest
	seen []application.AuthorizationRequest
}

func (p *verificationServicePolicy) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	p.seen = append(p.seen, request)
	index := len(p.seen) - 1
	if index >= len(p.want) || request != p.want[index] {
		p.t.Errorf("authorization step %d: unexpected action/shape %#v", index, request)
		return application.ErrForbidden
	}
	mode := authz.ResolvedEvaluation
	if request.ScopeOnly {
		mode = authz.ScopeEvaluation
	}
	if request.TenantWide {
		mode = authz.TenantEvaluation
	}
	return authz.Authorize(ctx, actor, authz.Request{Action: request.Action, Resources: request.Resources, Evaluation: mode})
}

func TestGenericVerificationServiceBindsDispatchAndEverySubjectToTypedPolicy(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		action authz.Action
		refs   application.ResourceReferences
	}{
		{"evidence_item", authz.ActionEvidenceVerify, application.ResourceReferences{ProductID: "product", ReleaseID: "release"}},
		{"build_attestation", authz.ActionDSSEVerify, application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release", BuildID: "build"}},
		{"release_bundle", authz.ActionReleaseBundleVerify, application.ResourceReferences{ProductID: "product", ReleaseID: "release"}},
		{"artifact_signature", authz.ActionArtifactSignatureVerify, application.ResourceReferences{ArtifactID: "artifact"}},
		{"audit_chain", authz.ActionAuditChainVerify, application.ResourceReferences{}},
		{"merkle_batch", authz.ActionMerkleBatchVerify, application.ResourceReferences{}},
		{"audit_chain_checkpoint", authz.ActionMerkleCheckpointVerify, application.ResourceReferences{}},
		{"audit_chain_release_manifest", authz.ActionReleaseManifestCheckpointVerify, application.ResourceReferences{}},
		{"backup_manifest", authz.ActionBackupManifestVerify, application.ResourceReferences{}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			state := newVerificationTestState()
			id := "subject"
			if tc.kind == "audit_chain" {
				id = ""
			}
			state.subject = SubjectReference{TenantID: "ten_1", Type: tc.kind, ID: id, Resources: tc.refs}
			state.inspection = SubjectInspection{Profile: verificationdomain.VerificationProfile{ID: "test-profile", RequiredChecks: []string{"check"}}, Checks: []verificationdomain.VerifyCheck{{Name: "check", Result: "passed"}}}
			child := application.AuthorizationRequest{Action: tc.action, Resources: tc.refs, TenantWide: tc.refs == (application.ResourceReferences{})}
			policy := &verificationServicePolicy{t: t, want: []application.AuthorizationRequest{{Action: authz.ActionSubjectVerificationDispatch, ScopeOnly: true}, child, child}}
			state.policy = policy
			service := newVerificationTestService(t, state)
			service.authorizer = policy
			actor := identitydomain.Actor{TenantID: "ten_1", KeyID: "key", Scopes: []string{"verify:read"}}
			result, err := service.VerifySubject(t.Context(), actor, tc.kind, id)
			if err != nil || result.ID == "" || result.SubjectType != tc.kind || result.Result.String() != "passed" || len(state.results) != 1 || len(state.audit) != 1 || len(state.outbox) != 1 || !reflect.DeepEqual(policy.seen, policy.want) {
				t.Fatal("typed verification did not commit its complete receipt", err, result.ID, len(state.results), len(state.audit), len(state.outbox))
			}
		})
	}
}

func TestGenericVerificationServiceBindsSigningDiagnosticsCosignAndBackupActions(t *testing.T) {
	for _, tc := range []struct {
		name        string
		action      authz.Action
		transaction bool
		run         func(*Service, identitydomain.Actor) error
	}{
		{"keys", authz.ActionSigningKeysRead, false, func(s *Service, a identitydomain.Actor) error {
			_, err := s.ListSigningKeys(t.Context(), a)
			return err
		}},
		{"custody", authz.ActionSigningCustodyRead, false, func(s *Service, a identitydomain.Actor) error {
			_, err := s.SigningCustodyReviewReport(t.Context(), a)
			return err
		}},
		{"merkle", authz.ActionMerkleBatchesCreate, true, func(s *Service, a identitydomain.Actor) error {
			_, err := s.CreateMerkleBatch(t.Context(), a, CreateMerkleBatchInput{})
			return err
		}},
		{"checkpoint", authz.ActionTransparencyCheckpointsRecord, true, func(s *Service, a identitydomain.Actor) error {
			_, err := s.CreateTransparencyCheckpoint(t.Context(), a, CreateTransparencyCheckpointInput{BatchID: "batch", Provider: "rfc3161", ExternalID: "external"})
			return err
		}},
		{"backup", authz.ActionBackupGenerate, true, func(s *Service, a identitydomain.Actor) error {
			_, err := s.GenerateBackupManifest(t.Context(), a)
			return err
		}},
		{"cosign", authz.ActionCosignVerify, true, func(s *Service, a identitydomain.Actor) error {
			_, err := s.VerifyCosign(t.Context(), a, VerifyCosignInput{ArtifactSignatureID: "signature", Mode: CosignVerificationModeKey, Offline: true})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newVerificationTestState()
			state.auditChain = []AuditChainLeaf{{Sequence: 1, EntryHash: "hash"}}
			state.merkleBatches["batch"] = verificationdomain.MerkleBatch{ID: "batch", TenantID: "ten_1", RootHash: "root"}
			state.backupSnapshot = BackupSnapshot{TenantID: "ten_1", StateHash: "backup-hash"}
			state.cosignSubject = CosignSubject{TenantID: "ten_1", ArtifactID: "artifact", ArtifactSignatureID: "signature", SubjectDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Resources: application.ResourceReferences{ArtifactID: "artifact"}}
			state.cosignInspection = CosignInspection{Profile: CosignFullProfile(CosignVerificationModeKey, state.cosignSubject.SubjectDigest), LibraryVersion: "test", TrustRootVersion: "test"}
			for _, check := range state.cosignInspection.Profile.RequiredChecks {
				state.cosignInspection.Checks = append(state.cosignInspection.Checks, verificationdomain.VerifyCheck{Name: check, Result: "passed"})
			}
			request := application.AuthorizationRequest{Action: tc.action, TenantWide: true}
			want := []application.AuthorizationRequest{request}
			want = append(want, request)
			if tc.name == "cosign" {
				child := application.AuthorizationRequest{Action: tc.action, Resources: state.cosignSubject.Resources}
				want = []application.AuthorizationRequest{{Action: tc.action, ScopeOnly: true}, child, child}
			}
			policy := &verificationServicePolicy{t: t, want: want}
			state.policy = policy
			service := newVerificationTestService(t, state)
			service.authorizer = policy
			if err := tc.run(service, identitydomain.Actor{TenantID: "ten_1", KeyID: "key", Scopes: []string{"*"}}); err != nil || !reflect.DeepEqual(policy.seen, policy.want) {
				t.Fatal("operation did not use its typed policy at every boundary", err)
			}
			if tc.transaction && len(state.audit) != 1 {
				t.Fatal("authorized operation lost atomic audit", len(state.audit))
			}
		})
	}
}

type genericVerificationReadBoundary struct {
	*verificationTestState
	hook func()
}

type genericCosignInspectionBoundary struct {
	*verificationTestState
	calls int
}

func (i *genericCosignInspectionBoundary) InspectCosign(ctx context.Context, subject CosignSubject, input VerifyCosignInput) (CosignInspection, error) {
	i.calls++
	return i.verificationTestState.InspectCosign(ctx, subject, input)
}

func (r genericVerificationReadBoundary) ListSigningKeys(ctx context.Context, tenant string) ([]verificationdomain.SigningKey, error) {
	values, err := r.verificationTestState.ListSigningKeys(ctx, tenant)
	if r.hook != nil {
		r.hook()
	}
	return values, err
}
func (r genericVerificationReadBoundary) ReadSigningCustodySnapshot(ctx context.Context, tenant string) (SigningCustodySnapshot, error) {
	value, err := r.verificationTestState.ReadSigningCustodySnapshot(ctx, tenant)
	if r.hook != nil {
		r.hook()
	}
	return value, err
}

func TestGenericVerificationReadsWithholdDiagnosticsAfterCancellationOrGrantRevocation(t *testing.T) {
	for _, custody := range []bool{false, true} {
		for _, canceled := range []bool{false, true} {
			t.Run(map[bool]string{false: "keys", true: "custody"}[custody]+"/"+map[bool]string{false: "revoked", true: "canceled"}[canceled], func(t *testing.T) {
				state := newVerificationTestState()
				service := newVerificationTestService(t, state)
				action, scope := authz.ActionSigningKeysRead, "verify:read"
				if custody {
					action, scope = authz.ActionSigningCustodyRead, "keys:admin"
				}
				request := application.AuthorizationRequest{Action: action, TenantWide: true}
				policy := &verificationServicePolicy{t: t, want: []application.AuthorizationRequest{request, request}}
				service.authorizer = policy
				actor := identitydomain.Actor{TenantID: "ten_1", UserID: "human", Scopes: []string{scope}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{scope}}}}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				boundary := genericVerificationReadBoundary{verificationTestState: state, hook: func() { actor.ResourceGrants[0].ResourceID = "foreign" }}
				wantErr := application.ErrForbidden
				if canceled {
					boundary.hook, wantErr = cancel, context.Canceled
				}
				service.reader, service.integrity = boundary, boundary
				var err error
				if custody {
					var result verificationdomain.SigningCustodyReviewReport
					result, err = service.SigningCustodyReviewReport(ctx, actor)
					if !reflect.DeepEqual(result, verificationdomain.SigningCustodyReviewReport{}) {
						t.Error("late denial leaked custody diagnostics")
					}
				} else {
					var result []verificationdomain.SigningKey
					result, err = service.ListSigningKeys(ctx, actor)
					if result != nil {
						t.Error("late denial returned signing keys")
					}
				}
				if !errors.Is(err, wantErr) || !reflect.DeepEqual(policy.seen, policy.want) {
					t.Fatal("late authority was not rechecked", err)
				}
			})
		}
	}
}

func TestGenericCosignRejectsArtifactCoordinateSubstitutionBeforeInspection(t *testing.T) {
	for _, refs := range []application.ResourceReferences{{ArtifactID: "foreign"}, {ArtifactID: "artifact", ProductID: "stray"}, {}} {
		state := newVerificationTestState()
		state.cosignSubject = CosignSubject{TenantID: "ten_1", ArtifactID: "artifact", ArtifactSignatureID: "signature", SubjectDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Resources: refs}
		policy := &verificationServicePolicy{t: t, want: []application.AuthorizationRequest{{Action: authz.ActionCosignVerify, ScopeOnly: true}}}
		state.policy = policy
		service := newVerificationTestService(t, state)
		service.authorizer = policy
		inspector := &genericCosignInspectionBoundary{verificationTestState: state}
		service.cosignInspector = inspector
		result, err := service.VerifyCosign(t.Context(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key", Scopes: []string{"verify:read"}}, VerifyCosignInput{ArtifactSignatureID: "signature", Mode: CosignVerificationModeKey, Offline: true})
		if !errors.Is(err, ErrNotFound) || result.ID != "" || inspector.calls != 0 || len(state.results)+len(state.cosignRecords)+len(state.audit) != 0 || !reflect.DeepEqual(policy.seen, policy.want) {
			t.Error("substituted artifact coordinates reached inspection or writes", err)
		}
	}
}

func TestGenericVerificationReadsRequireCurrentTenantAuthorityBeforeStorage(t *testing.T) {
	for _, grant := range []identitydomain.ResourceGrant{{}, {ResourceType: "tenant", ResourceID: "foreign", Scopes: []string{"*"}}, {ResourceType: "product", ResourceID: "product", Scopes: []string{"*"}}, {ResourceType: "tenant", ResourceID: "ten_1", Scopes: []string{"unrelated"}}} {
		for _, custody := range []bool{false, true} {
			state := newVerificationTestState()
			service := newVerificationTestService(t, state)
			action := authz.ActionSigningKeysRead
			if custody {
				action = authz.ActionSigningCustodyRead
			}
			policy := &verificationServicePolicy{t: t, want: []application.AuthorizationRequest{{Action: action, TenantWide: true}}}
			service.authorizer = policy
			reads := 0
			boundary := genericVerificationReadBoundary{verificationTestState: state, hook: func() { reads++ }}
			service.reader, service.integrity = boundary, boundary
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "human", SessionID: "session", Scopes: []string{"*"}, ResourceGrants: []identitydomain.ResourceGrant{grant}}
			var err error
			if custody {
				_, err = service.SigningCustodyReviewReport(t.Context(), actor)
			} else {
				_, err = service.ListSigningKeys(t.Context(), actor)
			}
			if !errors.Is(err, application.ErrForbidden) || reads != 0 || !reflect.DeepEqual(policy.seen, policy.want) {
				t.Fatal("missing/foreign/narrow grant reached tenant diagnostics", grant.ResourceType, err, reads)
			}
		}
	}
}

type genericSubjectInspectionBoundary struct {
	*verificationTestState
	resolves, inspections int
	afterInspect          func()
}

func (i *genericSubjectInspectionBoundary) ResolveVerificationSubject(ctx context.Context, tenant, kind, id string) (SubjectReference, error) {
	i.resolves++
	return i.verificationTestState.ResolveVerificationSubject(ctx, tenant, kind, id)
}
func (i *genericSubjectInspectionBoundary) InspectSubject(ctx context.Context, subject SubjectReference) (SubjectInspection, error) {
	i.inspections++
	inspection, err := i.verificationTestState.InspectSubject(ctx, subject)
	if i.afterInspect != nil {
		i.afterInspect()
	}
	return inspection, err
}

func TestGenericSubjectVerificationRechecksCurrentGrantAtReceiptCommit(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoked", true: "canceled"}[canceled], func(t *testing.T) {
			state := newVerificationTestState()
			state.subject = SubjectReference{TenantID: "ten_1", Type: "evidence_item", ID: "evidence", Resources: application.ResourceReferences{ProductID: "product"}}
			state.inspection = SubjectInspection{Profile: verificationdomain.VerificationProfile{ID: "test-profile", RequiredChecks: []string{"check"}}, Checks: []verificationdomain.VerifyCheck{{Name: "check", Result: "passed"}}}
			child := application.AuthorizationRequest{Action: authz.ActionEvidenceVerify, Resources: state.subject.Resources}
			policy := &verificationServicePolicy{t: t, want: []application.AuthorizationRequest{{Action: authz.ActionSubjectVerificationDispatch, ScopeOnly: true}, child, child}}
			state.policy = policy
			service := newVerificationTestService(t, state)
			service.authorizer = policy
			actor := identitydomain.Actor{TenantID: "ten_1", UserID: "human", SessionID: "session", Scopes: []string{"verify:read"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"verify:read"}}}}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			boundary := &genericSubjectInspectionBoundary{verificationTestState: state, afterInspect: func() { actor.ResourceGrants[0].ResourceID = "foreign" }}
			wantErr := application.ErrForbidden
			if canceled {
				boundary.afterInspect, wantErr = cancel, context.Canceled
			}
			service.subjects, service.inspector = boundary, boundary
			result, err := service.VerifySubject(ctx, actor, "evidence_item", "evidence")
			if !errors.Is(err, wantErr) || result.ID != "" || len(state.results)+len(state.audit)+len(state.outbox) != 0 || boundary.resolves != 1 || boundary.inspections != 1 || !reflect.DeepEqual(policy.seen, policy.want) {
				t.Fatal("late denial published a verification receipt or effects", err, boundary.resolves, boundary.inspections)
			}
		})
	}
}

func TestGenericSubjectVerificationRejectsUnknownKindAndForeignSubjectBeforeInspection(t *testing.T) {
	for _, kind := range []string{"unknown", "evidence_item"} {
		state := newVerificationTestState()
		state.subject = SubjectReference{TenantID: "foreign", Type: kind, ID: "subject"}
		service := newVerificationTestService(t, state)
		policy := &verificationServicePolicy{t: t, want: []application.AuthorizationRequest{{Action: authz.ActionSubjectVerificationDispatch, ScopeOnly: true}}}
		service.authorizer = policy
		boundary := &genericSubjectInspectionBoundary{verificationTestState: state}
		service.subjects, service.inspector = boundary, boundary
		wantErr, wantResolves := ErrNotFound, 1
		if kind == "unknown" {
			wantErr, wantResolves = ErrValidation, 0
		}
		result, err := service.VerifySubject(t.Context(), identitydomain.Actor{TenantID: "ten_1", KeyID: "key", Scopes: []string{"verify:read"}}, kind, "subject")
		if !errors.Is(err, wantErr) || result.ID != "" || boundary.resolves != wantResolves || boundary.inspections != 0 || len(state.results)+len(state.audit)+len(state.outbox) != 0 || !reflect.DeepEqual(policy.seen, policy.want) {
			t.Fatal("unknown/foreign subject reached inspection or writes", kind, err)
		}
	}
}
