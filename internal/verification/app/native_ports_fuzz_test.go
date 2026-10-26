package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

var errNativeFuzzWrite = errors.New("synthetic receipt write failure")

// These bounded ports supply one immutable subject/snapshot and capture only
// the command's append-only effects. No Ledger, SQL, provider or permissive
// cryptographic fake is involved. Atomic rollback is a port model; the live
// persistence gates separately establish database behavior.
type nativeFuzzPorts struct {
	nativeFuzzChain
	subject    verificationapp.SubjectReference
	merkle     verificationapp.MerkleVerificationSnapshot
	bundle     verificationapp.ReleaseBundleVerificationSnapshot
	dsse       verificationapp.DSSEVerificationSnapshot
	cosign     verificationapp.CosignSnapshot
	evidence   verificationapp.EvidenceVerificationSnapshot
	artifact   verificationapp.ArtifactSignatureVerificationSnapshot
	backup     verificationapp.BackupVerificationSnapshot
	authorizer application.Authorizer
	results    []verificationdomain.VerificationResult
	audits     []application.AuditEvent
	jobs       []application.OutboxEvent
	cosigns    []verificationdomain.CosignVerification
	requests   []application.AuthorizationRequest
	payloads   int
	fail       string
}

func nativeFuzzActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"verify:read"}}
}

func nativeFuzzIDs() application.IDGenerator {
	return application.IDGeneratorFunc(func(prefix string) string { return prefix + "-synthetic" })
}

func (s *nativeFuzzPorts) Authorize(ctx context.Context, actor identitydomain.Actor, req application.AuthorizationRequest) error {
	s.requests = append(s.requests, req)
	policy := s.authorizer
	if policy == nil {
		policy = verificationquery.NewSubjectVerificationAuthorizer()
	}
	return policy.Authorize(ctx, actor, req)
}

func (s *nativeFuzzPorts) InsertVerificationResult(_ context.Context, result verificationdomain.VerificationResult) error {
	if s.fail == "result" {
		return errNativeFuzzWrite
	}
	if result.TenantID != "tenant" || len(s.results) != 0 {
		return verificationapp.ErrConflict
	}
	s.results = append(s.results, result)
	return nil
}

func (s *nativeFuzzPorts) AppendAudit(_ context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	if s.fail == "audit" {
		return application.AuditReceipt{}, errNativeFuzzWrite
	}
	if event.TenantID != "tenant" || len(s.audits) != 0 {
		return application.AuditReceipt{}, verificationapp.ErrConflict
	}
	s.audits = append(s.audits, event)
	return application.AuditReceipt{ID: event.ID}, nil
}

func (s *nativeFuzzPorts) EnqueueOutbox(_ context.Context, event application.OutboxEvent) error {
	if s.fail == "outbox" {
		return errNativeFuzzWrite
	}
	if event.TenantID != "tenant" || len(s.jobs) != 0 {
		return verificationapp.ErrConflict
	}
	s.jobs = append(s.jobs, event)
	return nil
}

func (s *nativeFuzzPorts) InsertCosignVerification(_ context.Context, record verificationdomain.CosignVerification) error {
	if s.fail == "cosign" {
		return errNativeFuzzWrite
	}
	if record.TenantID != "tenant" || len(s.cosigns) != 0 {
		return verificationapp.ErrConflict
	}
	s.cosigns = append(s.cosigns, record)
	return nil
}

func (s *nativeFuzzPorts) run(fn func(*nativeFuzzPorts) error) error {
	tx := *s
	tx.results, tx.audits, tx.jobs, tx.cosigns = nil, nil, nil, nil
	tx.reads, tx.payloads = 0, 0
	err := fn(&tx)
	s.reads, s.payloads, s.requests = tx.reads, tx.payloads, tx.requests
	if err != nil {
		return err
	}
	if s.fail == "commit" {
		return errNativeFuzzWrite
	}
	s.results, s.audits, s.jobs, s.cosigns = tx.results, tx.audits, tx.jobs, tx.cosigns
	return nil
}

func (s *nativeFuzzPorts) ExecuteMerkleCheckpointVerification(ctx context.Context, fn func(context.Context, verificationapp.MerkleCheckpointVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteAuditChainVerification(ctx context.Context, fn func(context.Context, verificationapp.AuditChainVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteReleaseBundleVerification(ctx context.Context, fn func(context.Context, verificationapp.ReleaseBundleVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteMerkleVerification(ctx context.Context, fn func(context.Context, verificationapp.MerkleVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteReleaseManifestCheckpointVerification(ctx context.Context, fn func(context.Context, verificationapp.ReleaseManifestCheckpointTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteDSSEVerification(ctx context.Context, fn func(context.Context, verificationapp.DSSEVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteCosignVerification(ctx context.Context, fn func(context.Context, verificationapp.CosignVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteEvidenceVerification(ctx context.Context, fn func(context.Context, verificationapp.EvidenceVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteArtifactSignatureVerification(ctx context.Context, fn func(context.Context, verificationapp.ArtifactSignatureVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) ExecuteBackupVerification(ctx context.Context, fn func(context.Context, verificationapp.BackupVerificationTransaction) error) error {
	return s.run(func(tx *nativeFuzzPorts) error { return fn(ctx, tx) })
}

func (s *nativeFuzzPorts) LockAuditChainVerification(_ context.Context, tenant string) (verificationapp.AuditChainVerificationView, error) {
	if tenant != "tenant" {
		return verificationapp.AuditChainVerificationView{}, verificationapp.ErrNotFound
	}
	return s.view, nil
}

func (s *nativeFuzzPorts) resolve(tenant, id string) (verificationapp.SubjectReference, error) {
	if tenant != "tenant" || id != s.subject.ID {
		return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
	}
	return s.subject, nil
}

func (s *nativeFuzzPorts) ResolveMerkleVerificationSubject(_ context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	return s.resolve(tenant, id)
}
func (s *nativeFuzzPorts) ReadMerkleVerification(context.Context, verificationapp.SubjectReference) (verificationapp.MerkleVerificationSnapshot, error) {
	s.payloads++
	return s.merkle, nil
}
func (s *nativeFuzzPorts) ResolveReleaseBundleVerificationSubject(_ context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	return s.resolve(tenant, id)
}
func (s *nativeFuzzPorts) ReadReleaseBundleVerification(context.Context, verificationapp.SubjectReference) (verificationapp.ReleaseBundleVerificationSnapshot, error) {
	s.payloads++
	return s.bundle, nil
}
func (s *nativeFuzzPorts) ResolveDSSEVerificationSubject(_ context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	return s.resolve(tenant, id)
}
func (s *nativeFuzzPorts) ReadDSSEVerification(context.Context, verificationapp.SubjectReference) (verificationapp.DSSEVerificationSnapshot, error) {
	s.payloads++
	return s.dsse, nil
}
func (s *nativeFuzzPorts) ResolveEvidenceVerificationSubject(_ context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	return s.resolve(tenant, id)
}
func (s *nativeFuzzPorts) ReadEvidenceVerification(context.Context, verificationapp.SubjectReference) (verificationapp.EvidenceVerificationSnapshot, error) {
	s.payloads++
	return s.evidence, nil
}
func (s *nativeFuzzPorts) ResolveArtifactSignatureVerificationSubject(_ context.Context, tenant, id string) (verificationapp.SubjectReference, error) {
	return s.resolve(tenant, id)
}
func (s *nativeFuzzPorts) ReadArtifactSignatureVerification(context.Context, verificationapp.SubjectReference) (verificationapp.ArtifactSignatureVerificationSnapshot, error) {
	s.payloads++
	return s.artifact, nil
}
func (s *nativeFuzzPorts) ReadBackupVerification(_ context.Context, subject verificationapp.SubjectReference) (verificationapp.BackupVerificationSnapshot, error) {
	s.payloads++
	if subject != s.subject {
		return verificationapp.BackupVerificationSnapshot{}, verificationapp.ErrNotFound
	}
	return s.backup, nil
}
func (s *nativeFuzzPorts) ResolveCosignSubject(_ context.Context, tenant, id string) (verificationapp.CosignSubject, error) {
	if tenant != "tenant" || id != s.cosign.Subject.ArtifactSignatureID {
		return verificationapp.CosignSubject{}, verificationapp.ErrNotFound
	}
	return s.cosign.Subject, nil
}
func (s *nativeFuzzPorts) LockCosignVerificationScope(ctx context.Context, tenant, id string) (application.ResourceReferences, error) {
	subject, err := s.ResolveCosignSubject(ctx, tenant, id)
	return subject.Resources, err
}
func (s *nativeFuzzPorts) ReadCosignSnapshot(context.Context, verificationapp.CosignSubject) (verificationapp.CosignSnapshot, error) {
	s.payloads++
	return s.cosign, nil
}

func nativeFuzzAssertReceipt(t *testing.T, s *nativeFuzzPorts, result verificationdomain.VerificationResult, kind, id, expected string) {
	t.Helper()
	if result.Result.String() != expected || result.TenantID != "tenant" || result.SubjectType != kind || result.SubjectID != id || len(s.results) != 1 || len(s.audits) != 1 || len(s.jobs) != 1 || s.audits[0].SubjectID != result.ID || s.jobs[0].SubjectType != kind || s.jobs[0].SubjectID != id || s.jobs[0].Payload["result_id"] != result.ID {
		t.Fatal("native result lost its tenant, verdict or append-only receipt binding")
	}
}

func nativeFuzzAssertNoWrites(t *testing.T, s *nativeFuzzPorts) {
	t.Helper()
	if len(s.results)+len(s.audits)+len(s.jobs)+len(s.cosigns) != 0 {
		t.Fatal("rejected native operation committed partial receipt effects")
	}
}
