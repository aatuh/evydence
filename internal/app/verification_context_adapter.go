package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func (l *Ledger) configureVerificationCommands() error {
	service, err := verificationapp.NewService(verificationapp.Config{
		Subjects: ledgerVerificationSubjects{ledger: l}, Inspector: ledgerVerificationInspector{ledger: l},
		CosignSubjects: ledgerVerificationCosign{ledger: l}, CosignInspector: ledgerVerificationCosign{ledger: l},
		Integrity: ledgerVerificationReader{ledger: l}, Signer: ledgerVerificationSigner{ledger: l}, CanonicalHasher: ledgerVerificationHasher{},
		RetentionVerifier: ledgerVerificationRetentionVerifier{ledger: l},
		Reader:            ledgerVerificationReader{ledger: l}, Transactions: ledgerVerificationTransactions{ledger: l},
		KeyFactory: ledgerVerificationKeyFactory{ledger: l}, Authorizer: ledgerContextAuthorizer{ledger: l},
		Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID),
	})
	if err != nil {
		return err
	}
	l.verificationCommands = service
	return nil
}

type ledgerVerificationSubjects struct{ ledger *Ledger }

func (r ledgerVerificationSubjects) ResolveVerificationSubject(ctx context.Context, tenantID, subjectType, subjectID string) (verificationapp.SubjectReference, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.SubjectReference{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return verificationapp.SubjectReference{}, toVerificationContextError(err)
	}
	return resolveVerificationSubjectLocked(r.ledger, tenantID, subjectType, subjectID)
}

type ledgerVerificationInspector struct{ ledger *Ledger }

func (i ledgerVerificationInspector) InspectSubject(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.SubjectInspection, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.SubjectInspection{}, err
	}
	if subject.Type == "build_attestation" {
		return i.inspectBuildAttestation(ctx, subject)
	}
	i.ledger.mu.Lock()
	defer i.ledger.mu.Unlock()
	current, err := resolveVerificationSubjectLocked(i.ledger, subject.TenantID, subject.Type, subject.ID)
	if err != nil {
		return verificationapp.SubjectInspection{}, err
	}
	if current != subject {
		return verificationapp.SubjectInspection{}, verificationapp.ErrConflict
	}
	return inspectVerificationSubjectLocked(ctx, i.ledger, subject)
}

func (i ledgerVerificationInspector) inspectBuildAttestation(ctx context.Context, subject verificationapp.SubjectReference) (verificationapp.SubjectInspection, error) {
	l := i.ledger
	l.mu.Lock()
	current, err := resolveVerificationSubjectLocked(l, subject.TenantID, subject.Type, subject.ID)
	if err != nil {
		l.mu.Unlock()
		return verificationapp.SubjectInspection{}, err
	}
	if current != subject {
		l.mu.Unlock()
		return verificationapp.SubjectInspection{}, verificationapp.ErrConflict
	}
	attestation := l.attestations[subject.ID]
	build := l.buildRuns[attestation.BuildID]
	expectedSubjects := l.registeredReleaseBuildOutputDigestsLocked(subject.TenantID, build)
	roots := make([]domain.DSSETrustRoot, 0)
	for _, root := range l.dsseTrustRoots {
		if root.TenantID == subject.TenantID && root.Status == "active" && validDSSETrustRoot(root) {
			root.AllowedPredicateTypes = append([]string(nil), root.AllowedPredicateTypes...)
			root.ExpectedBuilderIDs = append([]string(nil), root.ExpectedBuilderIDs...)
			root.RequiredClaims = append([]string(nil), root.RequiredClaims...)
			roots = append(roots, root)
		}
	}
	objects, store := l.objects, l.store
	l.mu.Unlock()

	if objects == nil || attestation.PayloadRef == "" {
		return verificationapp.SubjectInspection{}, verificationapp.ErrValidation
	}
	objectKey := strings.TrimPrefix(attestation.PayloadRef, "object://")
	if lifecycle, ok := store.(ObjectPayloadLifecycleStore); ok {
		if err := RequireFinalizedObjectPayload(ctx, lifecycle, subject.TenantID, attestation.PayloadHash, objectKey); err != nil {
			return verificationapp.SubjectInspection{}, toVerificationContextError(err)
		}
	}
	object, err := objects.Get(ctx, objectKey)
	if err != nil {
		return verificationapp.SubjectInspection{}, err
	}
	if hashBytes(object.Bytes) != attestation.PayloadHash {
		return verificationapp.SubjectInspection{}, verificationapp.ErrValidation
	}
	verification, err := verifyDSSEAgainstConfiguredRoots(ctx, object.Bytes, roots, expectedSubjects)
	if err != nil {
		return verificationapp.SubjectInspection{}, verificationapp.ErrValidation
	}
	facts := verificationapp.DSSEVerificationFacts{AcceptedRootIDs: verification.AcceptedRootIDs}
	for _, check := range verification.Checks {
		facts.Checks = append(facts.Checks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return verificationapp.DSSEInspection(facts, attestation.PayloadHash), nil
}

type ledgerVerificationReader struct{ ledger *Ledger }

func (r ledgerVerificationReader) ReadAuditChain(ctx context.Context, tenantID string) ([]verificationapp.AuditChainLeaf, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return nil, toVerificationContextError(err)
	}
	entries := r.ledger.chain[tenantID]
	result := make([]verificationapp.AuditChainLeaf, 0, len(entries))
	for _, entry := range entries {
		if entry.TenantID != tenantID {
			return nil, verificationapp.ErrNotFound
		}
		result = append(result, verificationapp.AuditChainLeaf{Sequence: entry.Sequence, EntryHash: entry.EntryHash})
	}
	return result, nil
}

func (r ledgerVerificationReader) ReadMerkleBatch(ctx context.Context, tenantID, id string) (verificationdomain.MerkleBatch, error) {
	if err := ctx.Err(); err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	batch, ok := r.ledger.merkleBatches[strings.TrimSpace(id)]
	if !ok || batch.TenantID != tenantID {
		return verificationdomain.MerkleBatch{}, verificationapp.ErrNotFound
	}
	return merkleBatchToVerificationContext(batch), nil
}

type ledgerVerificationSigner struct{ ledger *Ledger }

func (s ledgerVerificationSigner) Sign(ctx context.Context, request verificationapp.SigningRequest) (verificationapp.SigningResult, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.SigningResult{}, err
	}
	s.ledger.mu.Lock()
	defer s.ledger.mu.Unlock()
	var active domain.SigningKey
	version := 1
	for _, key := range s.ledger.signingKeys {
		if key.TenantID != request.TenantID || signingKeyProvider(key) != domain.SigningKeyDefaultProvider {
			continue
		}
		if key.Version >= version {
			version = key.Version + 1
		}
		if key.Status == domain.SigningKeyStatusActive && (active.ID == "" || key.Version > active.Version || (key.Version == active.Version && key.ID < active.ID)) {
			active = key
		}
	}
	var prepared *verificationapp.PreparedSigningKey
	if active.ID == "" {
		key, err := s.ledger.newSigningKeyAt(request.TenantID, domain.SigningKeyDefaultProvider, version, request.CreatedAt)
		if err != nil {
			return verificationapp.SigningResult{}, err
		}
		private := append([]byte(nil), key.Private...)
		key.Private = nil
		mapped, err := signingKeyToVerificationContext(key)
		if err != nil {
			clear(private)
			return verificationapp.SigningResult{}, verificationapp.ErrValidation
		}
		prepared = &verificationapp.PreparedSigningKey{Key: mapped, PrivateMaterial: private}
		active = signingKeyFromVerificationContext(mapped, private)
	}
	if active.Algorithm != "Ed25519" || len(active.Private) != ed25519.PrivateKeySize {
		if prepared != nil {
			clear(prepared.PrivateMaterial)
		}
		return verificationapp.SigningResult{}, verificationapp.ErrConflict
	}
	value := ed25519.Sign(ed25519.PrivateKey(active.Private), request.Payload)
	return verificationapp.SigningResult{Signature: verificationdomain.Signature{
		ID: newID("sig"), TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID,
		KeyID: active.ID, Algorithm: active.Algorithm, Value: base64.RawStdEncoding.EncodeToString(value), CreatedAt: request.CreatedAt.UTC(),
	}, NewKey: prepared}, nil
}

type ledgerVerificationHasher struct{}

func (ledgerVerificationHasher) Hash(value any) (string, error) { return canonicalAnyHash(value) }

type ledgerVerificationCosign struct{ ledger *Ledger }

func (r ledgerVerificationCosign) ResolveCosignSubject(ctx context.Context, tenantID, signatureID string) (verificationapp.CosignSubject, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.CosignSubject{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return resolveCosignSubjectLocked(r.ledger, tenantID, signatureID)
}

func (r ledgerVerificationCosign) InspectCosign(ctx context.Context, subject verificationapp.CosignSubject, input verificationapp.VerifyCosignInput) (verificationapp.CosignInspection, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.CosignInspection{}, err
	}
	l := r.ledger
	l.mu.Lock()
	current, err := resolveCosignSubjectLocked(l, subject.TenantID, subject.ArtifactSignatureID)
	if err != nil {
		l.mu.Unlock()
		return verificationapp.CosignInspection{}, err
	}
	if current != subject {
		l.mu.Unlock()
		return verificationapp.CosignInspection{}, verificationapp.ErrConflict
	}
	signature := l.artifactSigs[subject.ArtifactSignatureID]
	artifact := l.artifacts[subject.ArtifactID]
	verifier, objects, store := l.cosign, l.objects, l.store
	l.mu.Unlock()

	mode := CosignVerificationMode(input.Mode)
	profile := cosignVerificationProfile(mode, subject.SubjectDigest)
	receipt := CosignVerificationReceipt{}
	outcome := ""
	switch {
	case verifier == nil:
		outcome = verificationapp.CosignOutcomeUnavailable
		receipt.Checks = []domain.VerifyCheck{{Name: "verification_configuration", Result: "failed", Detail: "no Sigstore verifier and trust policy are configured"}}
	case signature.Algorithm != "cosign":
		outcome = verificationapp.CosignOutcomeVerificationFailed
		receipt.Checks = []domain.VerifyCheck{{Name: "signature_algorithm", Result: "failed", Detail: "artifact signature is not recorded as a Cosign bundle"}}
	case artifact.Digest != signature.SubjectDigest || !validDigest(signature.SubjectDigest):
		outcome = verificationapp.CosignOutcomeVerificationFailed
		receipt.Checks = []domain.VerifyCheck{{Name: "subject_digest", Result: "failed", Detail: "stored artifact and signature digest binding does not match"}}
	default:
		bundle, err := loadCosignBundle(ctx, subject.TenantID, signature, objects, store)
		if err != nil {
			outcome = verificationapp.CosignOutcomeVerificationFailed
			receipt.Checks = []domain.VerifyCheck{{Name: "sigstore_bundle", Result: "failed", Detail: "stored Sigstore bundle is unavailable, not finalized, or does not match its recorded digest"}}
		} else {
			receipt, err = verifier.VerifyCosign(ctx, CosignVerificationRequest{
				Bundle: bundle, ArtifactDigest: artifact.Digest, ExpectedIdentity: input.ExpectedIdentity,
				ExpectedIssuer: input.ExpectedIssuer, Mode: mode, Offline: input.Offline,
			})
			if err != nil {
				if errors.Is(err, ErrFullVerificationUnavailable) {
					outcome = verificationapp.CosignOutcomeUnavailable
				} else {
					outcome = verificationapp.CosignOutcomeVerificationFailed
				}
			}
		}
	}
	checks := append([]domain.VerifyCheck(nil), receipt.Checks...)
	if len(checks) == 0 {
		checks = []domain.VerifyCheck{{Name: "cryptographic_verification", Result: "failed", Detail: "Sigstore verification produced no receipt"}}
		outcome = verificationapp.CosignOutcomeVerificationFailed
	}
	mapped := verificationInspectionFromLegacy(checks, profile)
	return verificationapp.CosignInspection{
		Profile: mapped.Profile, Checks: mapped.Checks, CertificateIdentity: strings.TrimSpace(receipt.CertificateIdentity),
		CertificateIssuer: strings.TrimSpace(receipt.CertificateIssuer), LibraryVersion: strings.TrimSpace(receipt.LibraryVersion),
		TrustRootVersion: strings.TrimSpace(receipt.TrustRootVersion), Limitations: append([]string(nil), receipt.Limitations...), Outcome: outcome,
	}, nil
}

func resolveCosignSubjectLocked(ledger *Ledger, tenantID, signatureID string) (verificationapp.CosignSubject, error) {
	signature, ok := ledger.artifactSigs[strings.TrimSpace(signatureID)]
	if !ok || signature.TenantID != tenantID {
		return verificationapp.CosignSubject{}, verificationapp.ErrNotFound
	}
	artifact, ok := ledger.artifacts[signature.ArtifactID]
	if !ok || artifact.TenantID != tenantID {
		return verificationapp.CosignSubject{}, verificationapp.ErrNotFound
	}
	var imageID string
	for _, image := range ledger.images {
		if image.TenantID == tenantID && image.ArtifactID == artifact.ID && image.Digest == artifact.Digest {
			imageID = image.ID
			break
		}
	}
	return verificationapp.CosignSubject{
		TenantID: tenantID, ArtifactID: artifact.ID, ContainerImageID: imageID, ArtifactSignatureID: signature.ID,
		SubjectDigest: signature.SubjectDigest, Resources: application.ResourceReferences{ArtifactID: artifact.ID},
	}, nil
}

func (r ledgerVerificationReader) ListSigningKeys(ctx context.Context, tenantID string) ([]verificationdomain.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	result := make([]verificationdomain.SigningKey, 0)
	for _, key := range r.ledger.signingKeys {
		if key.TenantID != tenantID {
			continue
		}
		mapped, err := signingKeyToVerificationContext(key)
		if err != nil {
			return nil, verificationapp.ErrValidation
		}
		result = append(result, mapped)
	}
	return result, nil
}

func (r ledgerVerificationReader) ReadObjectRetentionPolicy(ctx context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	if err := ctx.Err(); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	policy, ok := r.ledger.retentionPolicies[strings.TrimSpace(id)]
	if !ok || policy.TenantID != tenantID {
		return verificationdomain.ObjectRetentionPolicy{}, verificationapp.ErrNotFound
	}
	return objectRetentionPolicyToVerificationContext(policy), nil
}

func (r ledgerVerificationReader) ReadSigningCustodySnapshot(ctx context.Context, tenantID string) (verificationapp.SigningCustodySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.SigningCustodySnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	providers := make([]verificationdomain.SigningProvider, 0)
	for _, provider := range r.ledger.signingProviders {
		if provider.TenantID == tenantID {
			providers = append(providers, signingProviderToVerificationContext(provider))
		}
	}
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0)
	for _, policy := range r.ledger.retentionPolicies {
		if policy.TenantID == tenantID {
			policies = append(policies, objectRetentionPolicyToVerificationContext(policy))
		}
	}
	return verificationapp.SigningCustodySnapshot{
		TenantID: tenantID, SigningProviders: providers, ObjectRetentionPolicies: policies,
	}, nil
}

func (r ledgerVerificationReader) ReadCommittedBackupSnapshot(ctx context.Context, tenantID string) (verificationapp.BackupSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.BackupSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return verificationapp.BackupSnapshot{}, toVerificationContextError(err)
	}
	state, err := r.ledger.snapshotLocked()
	if err != nil {
		return verificationapp.BackupSnapshot{}, toVerificationContextError(err)
	}
	// The manifest commits to persisted state without exposing secret key
	// material. Raw object payloads are held by the object store and are not
	// part of PersistedState.
	state.SigningKeyPrivate = nil
	hash, err := canonicalAnyHash(state)
	if err != nil {
		return verificationapp.BackupSnapshot{}, toVerificationContextError(err)
	}
	checks := r.ledger.verifyChainLocked(tenantID)
	mappedChecks := make([]verificationdomain.VerifyCheck, 0, len(checks))
	for _, check := range checks {
		mappedChecks = append(mappedChecks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return verificationapp.BackupSnapshot{
		TenantID: tenantID, StateHash: hash, ResourceCounts: r.ledger.resourceCountsLocked(tenantID),
		ConsistencyChecks: mappedChecks,
	}, nil
}

type ledgerVerificationRetentionVerifier struct{ ledger *Ledger }

func (v ledgerVerificationRetentionVerifier) VerifyRetention(ctx context.Context, request verificationapp.RetentionRequest) (verificationapp.RetentionObservation, bool, error) {
	if err := ctx.Err(); err != nil {
		return verificationapp.RetentionObservation{}, false, err
	}
	v.ledger.mu.Lock()
	verifier := v.ledger.retention
	v.ledger.mu.Unlock()
	if verifier == nil {
		return verificationapp.RetentionObservation{}, false, nil
	}
	result, err := verifier.VerifyObjectRetention(ctx, ObjectRetentionRequest{
		TenantID: request.TenantID, ObjectPrefix: request.ObjectPrefix, ObjectKey: request.ObjectKey,
		Mode: request.Mode, RetentionDays: request.RetentionDays, RequireLegalHold: request.RequireLegalHold,
	})
	if err != nil {
		return verificationapp.RetentionObservation{}, true, err
	}
	checks := make([]verificationdomain.VerifyCheck, 0, len(result.Checks))
	for _, check := range result.Checks {
		checks = append(checks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return verificationapp.RetentionObservation{
		Provider: result.Provider, Bucket: result.Bucket, ObjectKey: result.ObjectKey, Mode: result.Mode,
		RetentionDays: result.RetentionDays, Enforced: result.Enforced, LegalHold: copyBool(result.LegalHold),
		ObservedAt: result.ObservedAt, Checks: checks, Limitations: append([]string(nil), result.Limitations...),
	}, true, nil
}

type ledgerVerificationKeyFactory struct{ ledger *Ledger }

func (f ledgerVerificationKeyFactory) GenerateSigningKey(_ context.Context, tenantID, provider string, version int, now time.Time) (verificationapp.PreparedSigningKey, error) {
	key, err := f.ledger.newSigningKeyAt(tenantID, provider, version, now)
	if err != nil {
		return verificationapp.PreparedSigningKey{}, err
	}
	private := append([]byte(nil), key.Private...)
	key.Private = nil
	mapped, err := signingKeyToVerificationContext(key)
	if err != nil {
		return verificationapp.PreparedSigningKey{}, verificationapp.ErrValidation
	}
	return verificationapp.PreparedSigningKey{Key: mapped, PrivateMaterial: private}, nil
}

type ledgerVerificationTransactions struct{ ledger *Ledger }

func (r ledgerVerificationTransactions) Execute(ctx context.Context, command verificationapp.TransactionCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := r.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	tx := newLedgerVerificationTransaction(l)
	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			tx.repositories = &repositories
			return command(ctx, tx)
		})
		if err != nil {
			return toVerificationContextError(err)
		}
		tx.publish()
		return nil
	}
	if err := command(ctx, tx); err != nil {
		return toVerificationContextError(err)
	}
	return tx.commitCompatibility(ctx)
}

type ledgerVerificationTransaction struct {
	ledger       *Ledger
	repositories *Repositories
	results      map[string]domain.VerificationResult
	keys         map[string]domain.SigningKey
	providers    map[string]domain.SigningProvider
	roots        map[string]domain.DSSETrustRoot
	cosign       map[string]domain.CosignVerification
	signatures   map[string]domain.Signature
	merkle       map[string]domain.MerkleBatch
	checkpoints  map[string]domain.TransparencyCheckpoint
	retention    map[string]domain.ObjectRetentionPolicy
	backups      map[string]domain.BackupManifest
	audit        []domain.AuditChainEntry
	outbox       []OutboxJob
}

func newLedgerVerificationTransaction(ledger *Ledger) *ledgerVerificationTransaction {
	return &ledgerVerificationTransaction{
		ledger: ledger, results: map[string]domain.VerificationResult{}, keys: map[string]domain.SigningKey{},
		providers: map[string]domain.SigningProvider{}, roots: map[string]domain.DSSETrustRoot{}, cosign: map[string]domain.CosignVerification{},
		signatures: map[string]domain.Signature{}, merkle: map[string]domain.MerkleBatch{}, checkpoints: map[string]domain.TransparencyCheckpoint{},
		retention: map[string]domain.ObjectRetentionPolicy{}, backups: map[string]domain.BackupManifest{},
	}
}

func (t *ledgerVerificationTransaction) Verification() verificationapp.Repository { return t }
func (t *ledgerVerificationTransaction) Authorization() application.Authorizer {
	return ledgerLockedContextAuthorizer{ledger: t.ledger}
}
func (t *ledgerVerificationTransaction) Audit() application.AuditAppender   { return t }
func (t *ledgerVerificationTransaction) Outbox() application.OutboxEnqueuer { return t }

func (t *ledgerVerificationTransaction) InsertVerificationResult(ctx context.Context, result verificationdomain.VerificationResult) error {
	legacy := domain.VerificationResultFromContextModel(result)
	if _, exists := t.ledger.verifications[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.results[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Verification.InsertVerificationResult(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.results[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) GetSigningKeyForUpdate(ctx context.Context, tenantID, id string) (verificationdomain.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return verificationdomain.SigningKey{}, err
	}
	value, ok := t.keys[id]
	if !ok {
		value, ok = t.ledger.signingKeys[id]
	}
	if !ok || value.TenantID != tenantID {
		return verificationdomain.SigningKey{}, verificationapp.ErrNotFound
	}
	mapped, err := signingKeyToVerificationContext(value)
	if err != nil {
		return verificationdomain.SigningKey{}, verificationapp.ErrValidation
	}
	return mapped, nil
}

// ListLocalSigningKeysForUpdate runs under the compatibility transaction's
// Ledger lock. The PostgreSQL profile binds its own focused repository path.
func (t *ledgerVerificationTransaction) ListLocalSigningKeysForUpdate(ctx context.Context, tenantID string) ([]verificationdomain.SigningKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	keys := make(map[string]domain.SigningKey, len(t.ledger.signingKeys)+len(t.keys))
	for id, key := range t.ledger.signingKeys {
		keys[id] = key
	}
	for id, key := range t.keys {
		keys[id] = key
	}
	result := make([]verificationdomain.SigningKey, 0)
	for _, key := range keys {
		if key.TenantID != tenantID || key.Provider != "" && key.Provider != verificationdomain.SigningKeyDefaultProvider {
			continue
		}
		mapped, err := signingKeyToVerificationContext(key)
		if err != nil {
			return nil, verificationapp.ErrValidation
		}
		result = append(result, mapped)
		if len(result) > verificationapp.MaxSigningRotationKeys {
			return nil, verificationapp.ErrConflict
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (t *ledgerVerificationTransaction) UpdateSigningKey(ctx context.Context, key verificationdomain.SigningKey, expectedStatus string) error {
	current, ok := t.keys[key.ID]
	if !ok {
		current, ok = t.ledger.signingKeys[key.ID]
	}
	if !ok || current.TenantID != key.TenantID {
		return verificationapp.ErrNotFound
	}
	if current.Status != expectedStatus {
		return verificationapp.ErrConflict
	}
	legacy := signingKeyFromVerificationContext(key, current.Private)
	if t.repositories != nil {
		if err := t.repositories.Signatures.UpdateSigningKey(ctx, legacy, expectedStatus); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.keys[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertSigningKey(ctx context.Context, prepared verificationapp.PreparedSigningKey) error {
	legacy := signingKeyFromVerificationContext(prepared.Key, prepared.PrivateMaterial)
	if _, exists := t.ledger.signingKeys[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.keys[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Signatures.InsertSigningKey(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.keys[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertSigningProvider(ctx context.Context, provider verificationdomain.SigningProvider) error {
	legacy := signingProviderFromVerificationContext(provider)
	if _, exists := t.ledger.signingProviders[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.providers[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertSigningProvider(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.providers[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertDSSETrustRoot(ctx context.Context, root verificationdomain.DSSETrustRoot) error {
	legacy := dsseTrustRootFromVerificationContext(root)
	if _, exists := t.ledger.dsseTrustRoots[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.roots[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertDSSETrustRoot(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.roots[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertCosignVerification(ctx context.Context, verification verificationdomain.CosignVerification) error {
	legacy := cosignVerificationFromVerificationContext(verification)
	if _, exists := t.ledger.cosignVerifs[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.cosign[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertCosignVerification(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.cosign[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertSignature(ctx context.Context, signature verificationdomain.Signature) error {
	legacy := signatureFromVerificationContext(signature)
	if _, exists := t.ledger.signatures[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.signatures[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	key, ok := t.keys[legacy.KeyID]
	if !ok {
		key, ok = t.ledger.signingKeys[legacy.KeyID]
	}
	if !ok || key.TenantID != legacy.TenantID {
		return verificationapp.ErrNotFound
	}
	if t.repositories != nil {
		if err := t.repositories.Signatures.InsertSignature(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.signatures[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertMerkleBatch(ctx context.Context, batch verificationdomain.MerkleBatch) error {
	legacy := merkleBatchFromVerificationContext(batch)
	if _, exists := t.ledger.merkleBatches[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.merkle[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if !merkleBatchMatchesChain(legacy, t.ledger.chain[legacy.TenantID]) {
		return verificationapp.ErrConflict
	}
	for _, signatureID := range legacy.SignatureRefs {
		signature, ok := t.signatures[signatureID]
		if !ok || signature.TenantID != legacy.TenantID || signature.SubjectType != "merkle_batch" || signature.SubjectID != legacy.ID {
			return verificationapp.ErrNotFound
		}
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertMerkleBatch(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.merkle[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertTransparencyCheckpoint(ctx context.Context, checkpoint verificationdomain.TransparencyCheckpoint) error {
	legacy := transparencyCheckpointFromVerificationContext(checkpoint)
	if _, exists := t.ledger.transparency[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.checkpoints[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	batch, ok := t.merkle[legacy.BatchID]
	if !ok {
		batch, ok = t.ledger.merkleBatches[legacy.BatchID]
	}
	if !ok || batch.TenantID != legacy.TenantID {
		return verificationapp.ErrNotFound
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertTransparencyCheckpoint(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.checkpoints[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) GetObjectRetentionPolicyForUpdate(ctx context.Context, tenantID, id string) (verificationdomain.ObjectRetentionPolicy, error) {
	if err := ctx.Err(); err != nil {
		return verificationdomain.ObjectRetentionPolicy{}, err
	}
	policy, ok := t.retention[id]
	if !ok {
		policy, ok = t.ledger.retentionPolicies[id]
	}
	if !ok || policy.TenantID != tenantID {
		return verificationdomain.ObjectRetentionPolicy{}, verificationapp.ErrNotFound
	}
	return objectRetentionPolicyToVerificationContext(policy), nil
}

func (t *ledgerVerificationTransaction) InsertObjectRetentionPolicy(ctx context.Context, policy verificationdomain.ObjectRetentionPolicy) error {
	legacy := objectRetentionPolicyFromVerificationContext(policy)
	if _, exists := t.ledger.retentionPolicies[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.retention[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertObjectRetentionPolicy(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.retention[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) UpdateObjectRetentionPolicy(ctx context.Context, policy verificationdomain.ObjectRetentionPolicy, expectedStatus string) error {
	current, ok := t.retention[policy.ID]
	if !ok {
		current, ok = t.ledger.retentionPolicies[policy.ID]
	}
	if !ok || current.TenantID != policy.TenantID {
		return verificationapp.ErrNotFound
	}
	if current.Status != expectedStatus {
		return verificationapp.ErrConflict
	}
	legacy := objectRetentionPolicyFromVerificationContext(policy)
	if t.repositories != nil {
		if err := t.repositories.Integrity.UpdateObjectRetentionPolicy(ctx, legacy, expectedStatus); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.retention[legacy.ID] = legacy
	return nil
}

func (t *ledgerVerificationTransaction) InsertBackupManifest(ctx context.Context, manifest verificationdomain.BackupManifest) error {
	legacy := backupManifestFromVerificationContext(manifest)
	if _, exists := t.ledger.backupManifests[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if _, exists := t.backups[legacy.ID]; exists {
		return verificationapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Integrity.InsertBackupManifest(ctx, legacy); err != nil {
			return toVerificationContextError(err)
		}
	}
	t.backups[legacy.ID] = legacy
	return nil
}

func merkleBatchMatchesChain(batch domain.MerkleBatch, entries []domain.AuditChainEntry) bool {
	if batch.FromSequence < 1 || batch.ToSequence < batch.FromSequence || int64(len(batch.LeafHashes)) != batch.ToSequence-batch.FromSequence+1 || batch.EntryCount != len(batch.LeafHashes) {
		return false
	}
	hashes := make([]string, 0, len(batch.LeafHashes))
	for _, entry := range entries {
		if entry.TenantID == batch.TenantID && entry.Sequence >= batch.FromSequence && entry.Sequence <= batch.ToSequence {
			hashes = append(hashes, entry.EntryHash)
		}
	}
	return reflect.DeepEqual(hashes, batch.LeafHashes) && merkleRoot(batch.LeafHashes) == batch.RootHash
}

func (t *ledgerVerificationTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry := domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if t.repositories != nil {
		committed, err := t.repositories.Audit.Append(ctx, entry)
		if err != nil {
			return application.AuditReceipt{}, toVerificationContextError(err)
		}
		entry = committed
	} else if err := t.completeCompatibilityAudit(&entry); err != nil {
		return application.AuditReceipt{}, toVerificationContextError(err)
	}
	t.audit = append(t.audit, entry)
	return application.AuditReceipt{ID: entry.ID}, nil
}

func (t *ledgerVerificationTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	job := OutboxJob{
		ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, Payload: cloneMap(event.Payload), CreatedAt: event.CreatedAt,
	}
	if err := EnsureOutboxDeduplicationKey(&job); err != nil {
		return verificationapp.ErrValidation
	}
	if t.repositories != nil {
		if err := t.repositories.Outbox.Enqueue(ctx, job); err != nil {
			return toVerificationContextError(err)
		}
		return nil
	}
	t.outbox = append(t.outbox, job)
	return nil
}

func (t *ledgerVerificationTransaction) completeCompatibilityAudit(entry *domain.AuditChainEntry) error {
	entries := t.ledger.chain[entry.TenantID]
	for _, pending := range t.audit {
		if pending.TenantID == entry.TenantID {
			entries = append(entries, pending)
		}
	}
	entry.Sequence = int64(len(entries) + 1)
	if len(entries) > 0 {
		entry.PreviousEntryHash = entries[len(entries)-1].EntryHash
	}
	return RehashAuditChainEntry(entry)
}

func (t *ledgerVerificationTransaction) publish() {
	for id, result := range t.results {
		t.ledger.verifications[id] = result
	}
	for id, key := range t.keys {
		t.ledger.signingKeys[id] = key
	}
	for id, provider := range t.providers {
		t.ledger.signingProviders[id] = provider
	}
	for id, root := range t.roots {
		t.ledger.dsseTrustRoots[id] = root
	}
	for id, verification := range t.cosign {
		t.ledger.cosignVerifs[id] = verification
	}
	for id, signature := range t.signatures {
		t.ledger.signatures[id] = signature
	}
	for id, batch := range t.merkle {
		t.ledger.merkleBatches[id] = batch
	}
	for id, checkpoint := range t.checkpoints {
		t.ledger.transparency[id] = checkpoint
	}
	for id, policy := range t.retention {
		t.ledger.retentionPolicies[id] = policy
	}
	for id, manifest := range t.backups {
		t.ledger.backupManifests[id] = manifest
	}
	for _, entry := range t.audit {
		t.ledger.publishCommittedAuditEntryLocked(entry)
	}
}

func (t *ledgerVerificationTransaction) commitCompatibility(ctx context.Context) error {
	results := cloneVerificationResultMap(t.ledger.verifications)
	keys := cloneSigningKeyMap(t.ledger.signingKeys)
	providers := cloneSigningProviderMap(t.ledger.signingProviders)
	roots := cloneDSSETrustRootMap(t.ledger.dsseTrustRoots)
	cosign := cloneCosignVerificationMap(t.ledger.cosignVerifs)
	signatures := cloneSignatureMap(t.ledger.signatures)
	merkle := cloneMerkleBatchMap(t.ledger.merkleBatches)
	checkpoints := cloneTransparencyCheckpointMap(t.ledger.transparency)
	retention := cloneObjectRetentionPolicyMap(t.ledger.retentionPolicies)
	backups := cloneBackupManifestMap(t.ledger.backupManifests)
	chain := cloneAuditChainMap(t.ledger.chain)
	t.publish()
	persist := t.ledger.persistLocked
	if len(t.providers) == 0 && len(t.roots) == 0 && len(t.cosign) == 0 && len(t.signatures) == 0 && len(t.merkle) == 0 && len(t.checkpoints) == 0 && len(t.retention) == 0 && len(t.backups) == 0 {
		mutation, err := t.ledger.criticalMutationLocked()
		if err != nil {
			t.restore(results, keys, providers, roots, cosign, signatures, merkle, checkpoints, retention, backups, chain)
			return toVerificationContextError(err)
		}
		mutation.OutboxJobs = append(mutation.OutboxJobs, t.outbox...)
		persist = func(ctx context.Context) error {
			if _, ok := t.ledger.store.(CriticalMutationStore); !ok {
				for _, job := range t.outbox {
					if err := t.ledger.enqueueJob(ctx, job); err != nil {
						return err
					}
				}
			}
			return t.ledger.persistCriticalLocked(ctx, mutation)
		}
	} else if len(t.outbox) > 0 {
		t.restore(results, keys, providers, roots, cosign, signatures, merkle, checkpoints, retention, backups, chain)
		return verificationapp.ErrValidation
	}
	if err := persist(ctx); err != nil {
		t.restore(results, keys, providers, roots, cosign, signatures, merkle, checkpoints, retention, backups, chain)
		return toVerificationContextError(err)
	}
	return nil
}

func (t *ledgerVerificationTransaction) restore(results map[string]domain.VerificationResult, keys map[string]domain.SigningKey, providers map[string]domain.SigningProvider, roots map[string]domain.DSSETrustRoot, cosign map[string]domain.CosignVerification, signatures map[string]domain.Signature, merkle map[string]domain.MerkleBatch, checkpoints map[string]domain.TransparencyCheckpoint, retention map[string]domain.ObjectRetentionPolicy, backups map[string]domain.BackupManifest, chain map[string][]domain.AuditChainEntry) {
	t.ledger.verifications = results
	t.ledger.signingKeys = keys
	t.ledger.signingProviders = providers
	t.ledger.dsseTrustRoots = roots
	t.ledger.cosignVerifs = cosign
	t.ledger.signatures = signatures
	t.ledger.merkleBatches = merkle
	t.ledger.transparency = checkpoints
	t.ledger.retentionPolicies = retention
	t.ledger.backupManifests = backups
	t.ledger.chain = chain
}

func resolveVerificationSubjectLocked(ledger *Ledger, tenantID, subjectType, subjectID string) (verificationapp.SubjectReference, error) {
	subjectType = strings.TrimSpace(subjectType)
	subjectID = strings.TrimSpace(subjectID)
	reference := verificationapp.SubjectReference{TenantID: tenantID, Type: subjectType, ID: subjectID}
	switch subjectType {
	case "audit_chain":
		if subjectID != "" {
			return verificationapp.SubjectReference{}, verificationapp.ErrValidation
		}
	case "audit_chain_checkpoint":
		batch, ok := ledger.merkleBatches[subjectID]
		if !ok || batch.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
	case "merkle_batch":
		batch, ok := ledger.merkleBatches[subjectID]
		if !ok || batch.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
	case "backup_manifest":
		manifest, ok := ledger.backupManifests[subjectID]
		if !ok || manifest.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
	case "build_attestation":
		attestation, ok := ledger.attestations[subjectID]
		if !ok || attestation.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
		build, ok := ledger.buildRuns[attestation.BuildID]
		if !ok || build.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
		reference.Resources = application.ResourceReferences{ProjectID: build.ProjectID, ReleaseID: build.ReleaseID, BuildID: build.ID}
	case "audit_chain_release_manifest", "release_bundle":
		bundle, ok := ledger.bundles[subjectID]
		if !ok || bundle.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
		reference.Resources.ReleaseID = bundle.ReleaseID
	case "evidence_item":
		item, ok := ledger.evidence[subjectID]
		if !ok || item.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
		reference.Resources = application.ResourceReferences{
			ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
			BuildID: item.BuildID, DeploymentID: item.DeploymentID,
		}
	case "artifact_signature":
		signature, ok := ledger.artifactSigs[subjectID]
		if !ok || signature.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
		artifact, ok := ledger.artifacts[signature.ArtifactID]
		if !ok || artifact.TenantID != tenantID {
			return verificationapp.SubjectReference{}, verificationapp.ErrNotFound
		}
		reference.Resources.ArtifactID = artifact.ID
	default:
		return verificationapp.SubjectReference{}, verificationapp.ErrValidation
	}
	return reference, nil
}

func inspectVerificationSubjectLocked(ctx context.Context, ledger *Ledger, subject verificationapp.SubjectReference) (verificationapp.SubjectInspection, error) {
	var checks []domain.VerifyCheck
	var profile domain.VerificationProfile
	switch subject.Type {
	case "audit_chain":
		checks = ledger.verifyChainLocked(subject.TenantID)
		profile = assuranceProfile(domain.VerificationProfileAuditChainIntegrity, requiredCheckNames(checks), []string{"Evydence audit-chain canonical hashes"}, "tenant-scoped verification authorization", "not_evaluated", "tenant audit-chain entries", "", []string{"Audit-chain verification does not prove external anchoring or third-party log inclusion."})
	case "audit_chain_checkpoint":
		var found bool
		checks, found = ledger.verifyMerkleAuditChainCheckpointLocked(subject.TenantID, subject.ID)
		if !found {
			return verificationapp.SubjectInspection{}, verificationapp.ErrNotFound
		}
		profile = assuranceProfile(domain.VerificationProfileAuditChainMerkleCheckpoint, requiredCheckNames(checks), []string{"Evydence audit-chain hashes", "tenant signing keys"}, "tenant-scoped verification authorization", "not_evaluated", "tenant audit-chain range and signed Merkle root", "", []string{"This signed checkpoint detects truncation or rewrites within its covered sequence range, but does not prove external publication or third-party log inclusion."})
	case "merkle_batch":
		batch := ledger.merkleBatches[subject.ID]
		snapshot := verificationapp.MerkleVerificationSnapshot{Subject: subject, Batch: merkleBatchToVerificationContext(batch)}
		if batch.FromSequence > 0 && batch.ToSequence >= batch.FromSequence && batch.ToSequence-batch.FromSequence < verificationapp.MaxMerkleVerificationLeaves {
			for _, entry := range ledger.chain[subject.TenantID] {
				if entry.Sequence >= batch.FromSequence && entry.Sequence <= batch.ToSequence {
					snapshot.Leaves = append(snapshot.Leaves, verificationapp.AuditChainLeaf{Sequence: entry.Sequence, EntryHash: entry.EntryHash})
				}
			}
		}
		for _, ref := range batch.SignatureRefs {
			if sig, ok := ledger.signatures[ref]; ok && sig.TenantID == subject.TenantID {
				snapshot.Signatures = append(snapshot.Signatures, verificationdomain.Signature{ID: sig.ID, TenantID: sig.TenantID, SubjectType: sig.SubjectType, SubjectID: sig.SubjectID, KeyID: sig.KeyID, Algorithm: sig.Algorithm, Value: sig.Value, CreatedAt: sig.CreatedAt})
				if key, ok := ledger.signingKeys[sig.KeyID]; ok && key.TenantID == subject.TenantID {
					mapped, err := signingKeyToVerificationContext(key)
					if err != nil {
						return verificationapp.SubjectInspection{}, verificationapp.ErrConflict
					}
					snapshot.Keys = append(snapshot.Keys, mapped)
				}
			}
		}
		return verificationapp.InspectMerkleBatch(snapshot, ledger.now().UTC(), ledgerVerificationPayloadVerifier{})
	case "backup_manifest":
		manifest := ledger.backupManifests[subject.ID]
		recorded := make([]verificationdomain.VerifyCheck, 0, len(manifest.ConsistencyChecks))
		for _, check := range manifest.ConsistencyChecks {
			recorded = append(recorded, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
		}
		return verificationapp.InspectBackupManifestRecordedChecks(verificationapp.BackupVerificationSnapshot{Subject: subject, StateHash: manifest.StateHash, Checks: recorded})
	case "audit_chain_release_manifest":
		bundle := ledger.bundles[subject.ID]
		var found bool
		checks, found = ledger.verifyReleaseManifestAuditChainCheckpointLocked(subject.TenantID, bundle.ID)
		if !found {
			return verificationapp.SubjectInspection{}, verificationapp.ErrNotFound
		}
		profile = assuranceProfile(domain.VerificationProfileAuditChainReleaseManifest, requiredCheckNames(checks), []string{"release bundle manifest", "tenant signing keys"}, "tenant-scoped verification authorization", "not_evaluated", "signed release manifest audit-chain checkpoint", bundle.ManifestHash, []string{"This signed checkpoint detects truncation or rewrites within its covered sequence range, but does not prove external publication or third-party log inclusion."})
	case "evidence_item":
		item := ledger.evidence[subject.ID]
		snapshot := verificationapp.EvidenceVerificationSnapshot{Subject: subject, Item: domain.EvidenceToContextModel(item)}
		for _, event := range ledger.lifecycle {
			if event.TenantID == item.TenantID && event.EvidenceID == item.ID {
				snapshot.Lifecycle = append(snapshot.Lifecycle, evidencedomain.EvidenceLifecycleEvent{TenantID: event.TenantID, EvidenceID: event.EvidenceID, SchemaVersion: event.SchemaVersion, Details: event.Details})
			}
		}
		return verificationapp.InspectEvidenceCanonicalHash(ctx, snapshot, ledgerEvidenceCanonicalizer{})
	case "release_bundle":
		bundle := ledger.bundles[subject.ID]
		snapshot := verificationapp.ReleaseBundleVerificationSnapshot{Subject: subject, Manifest: bundle.Manifest, ManifestHash: bundle.ManifestHash, SignatureRefs: bundle.SignatureRefs}
		seenKeys := map[string]bool{}
		for _, ref := range bundle.SignatureRefs {
			sig, ok := ledger.signatures[ref]
			if !ok || sig.TenantID != subject.TenantID {
				continue
			}
			snapshot.Signatures = append(snapshot.Signatures, verificationdomain.Signature{ID: sig.ID, TenantID: sig.TenantID, SubjectType: sig.SubjectType, SubjectID: sig.SubjectID, KeyID: sig.KeyID, Algorithm: sig.Algorithm, Value: sig.Value, CreatedAt: sig.CreatedAt})
			if !seenKeys[sig.KeyID] {
				if key, ok := ledger.signingKeys[sig.KeyID]; ok && key.TenantID == subject.TenantID {
					mapped, err := signingKeyToVerificationContext(key)
					if err != nil {
						return verificationapp.SubjectInspection{}, verificationapp.ErrConflict
					}
					snapshot.Keys = append(snapshot.Keys, mapped)
					seenKeys[sig.KeyID] = true
				}
			}
		}
		return verificationapp.InspectReleaseBundle(snapshot, ledger.now().UTC(), ledgerVerificationHasher{}, ledgerVerificationPayloadVerifier{})
	case "artifact_signature":
		signature := ledger.artifactSigs[subject.ID]
		artifact := ledger.artifacts[signature.ArtifactID]
		return verificationapp.InspectArtifactSignatureMetadata(verificationapp.ArtifactSignatureVerificationSnapshot{Subject: subject, SignatureDigest: signature.SubjectDigest, ArtifactDigest: artifact.Digest, AlgorithmPresent: signature.Algorithm != "", SignaturePresent: signature.Signature != ""}), nil
	default:
		return verificationapp.SubjectInspection{}, verificationapp.ErrValidation
	}
	return verificationInspectionFromLegacy(checks, profile), nil
}

func verificationInspectionFromLegacy(checks []domain.VerifyCheck, profile domain.VerificationProfile) verificationapp.SubjectInspection {
	mappedChecks := make([]verificationdomain.VerifyCheck, 0, len(checks))
	for _, check := range checks {
		mappedChecks = append(mappedChecks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return verificationapp.SubjectInspection{Checks: mappedChecks, Profile: verificationdomain.VerificationProfile{
		ID: profile.ID, Version: profile.Version, RequiredChecks: append([]string(nil), profile.RequiredChecks...),
		TrustMaterial: append([]string(nil), profile.TrustMaterial...), IdentityPolicy: profile.IdentityPolicy,
		TransparencyProof: profile.TransparencyProof, PayloadScope: profile.PayloadScope, PayloadDigest: profile.PayloadDigest,
		Limitations: append([]string(nil), profile.Limitations...),
	}}
}

func signingKeyToVerificationContext(value domain.SigningKey) (verificationdomain.SigningKey, error) {
	statusValue := value.Status
	if statusValue == "" {
		statusValue = verificationdomain.SigningKeyStatusLegacyUnspecifiedValue
	}
	status, err := verificationdomain.ParseSigningKeyStatus(statusValue)
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return verificationdomain.SigningKey{
		ID: value.ID, TenantID: value.TenantID, KID: value.KID, Version: value.Version, Provider: value.Provider,
		Algorithm: value.Algorithm, Status: status, PublicKey: value.PublicKey, PublicKeyFingerprint: value.PublicKeyFingerprint,
		ValidFrom: value.ValidFrom, ValidUntil: cloneTimePtr(value.ValidUntil), CreatedAt: value.CreatedAt,
		RevokedAt: cloneTimePtr(value.RevokedAt), RevocationReason: value.RevocationReason,
		RevocationSemantics: value.RevocationSemantics, HistoricalValidityPolicy: value.HistoricalValidityPolicy,
		CompromisedAt: cloneTimePtr(value.CompromisedAt),
	}, nil
}

func signingKeyFromVerificationContext(value verificationdomain.SigningKey, private []byte) domain.SigningKey {
	return domain.SigningKey{
		ID: value.ID, TenantID: value.TenantID, KID: value.KID, Version: value.Version, Provider: value.Provider,
		Algorithm: value.Algorithm, Status: value.Status.String(), PublicKey: value.PublicKey,
		PublicKeyFingerprint: value.PublicKeyFingerprint, Private: append([]byte(nil), private...),
		ValidFrom: value.ValidFrom, ValidUntil: cloneTimePtr(value.ValidUntil), CreatedAt: value.CreatedAt,
		RevokedAt: cloneTimePtr(value.RevokedAt), RevocationReason: value.RevocationReason,
		RevocationSemantics: value.RevocationSemantics, HistoricalValidityPolicy: value.HistoricalValidityPolicy,
		CompromisedAt: cloneTimePtr(value.CompromisedAt),
	}
}

func signingProviderFromVerificationContext(value verificationdomain.SigningProvider) domain.SigningProvider {
	return domain.SigningProvider{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Status: value.Status,
		KeyRef: value.KeyRef, Encrypted: value.Encrypted, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func signingProviderToVerificationContext(value domain.SigningProvider) verificationdomain.SigningProvider {
	return domain.SigningProviderToContextModel(value)
}

func objectRetentionPolicyToVerificationContext(value domain.ObjectRetentionPolicy) verificationdomain.ObjectRetentionPolicy {
	return domain.ObjectRetentionPolicyToContextModel(value)
}

func objectRetentionPolicyFromVerificationContext(value verificationdomain.ObjectRetentionPolicy) domain.ObjectRetentionPolicy {
	return domain.ObjectRetentionPolicyFromContextModel(value)
}

func backupManifestFromVerificationContext(value verificationdomain.BackupManifest) domain.BackupManifest {
	return domain.BackupManifestFromContextModel(value)
}

func dsseTrustRootFromVerificationContext(value verificationdomain.DSSETrustRoot) domain.DSSETrustRoot {
	return domain.DSSETrustRootFromContextModel(value)
}

func cosignVerificationFromVerificationContext(value verificationdomain.CosignVerification) domain.CosignVerification {
	return domain.CosignVerificationFromContextModel(value)
}

func signatureFromVerificationContext(value verificationdomain.Signature) domain.Signature {
	return domain.Signature{
		ID: value.ID, TenantID: value.TenantID, SubjectType: value.SubjectType, SubjectID: value.SubjectID,
		KeyID: value.KeyID, Algorithm: value.Algorithm, Value: value.Value, CreatedAt: value.CreatedAt,
	}
}

func merkleBatchToVerificationContext(value domain.MerkleBatch) verificationdomain.MerkleBatch {
	return verificationdomain.MerkleBatch{
		ID: value.ID, TenantID: value.TenantID, FromSequence: value.FromSequence, ToSequence: value.ToSequence,
		EntryCount: value.EntryCount, LeafHashes: append([]string(nil), value.LeafHashes...), RootHash: value.RootHash,
		SignatureRefs: append([]string(nil), value.SignatureRefs...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func merkleBatchFromVerificationContext(value verificationdomain.MerkleBatch) domain.MerkleBatch {
	return domain.MerkleBatch{
		ID: value.ID, TenantID: value.TenantID, FromSequence: value.FromSequence, ToSequence: value.ToSequence,
		EntryCount: value.EntryCount, LeafHashes: append([]string(nil), value.LeafHashes...), RootHash: value.RootHash,
		SignatureRefs: append([]string(nil), value.SignatureRefs...), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func transparencyCheckpointFromVerificationContext(value verificationdomain.TransparencyCheckpoint) domain.TransparencyCheckpoint {
	return domain.TransparencyCheckpoint{
		ID: value.ID, TenantID: value.TenantID, BatchID: value.BatchID, Provider: value.Provider,
		ExternalURL: value.ExternalURL, ExternalID: value.ExternalID, TimestampHash: value.TimestampHash,
		State: value.State, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func verificationProfileFromContext(value verificationdomain.VerificationProfile) domain.VerificationProfile {
	return domain.VerificationProfile{
		ID: value.ID, Version: value.Version, RequiredChecks: append([]string(nil), value.RequiredChecks...),
		TrustMaterial: append([]string(nil), value.TrustMaterial...), IdentityPolicy: value.IdentityPolicy,
		TransparencyProof: value.TransparencyProof, PayloadScope: value.PayloadScope, PayloadDigest: value.PayloadDigest,
		Limitations: append([]string(nil), value.Limitations...),
	}
}

func cloneVerificationResultMap(values map[string]domain.VerificationResult) map[string]domain.VerificationResult {
	result := make(map[string]domain.VerificationResult, len(values))
	for id, value := range values {
		value.Checks = append([]domain.VerifyCheck(nil), value.Checks...)
		value.Profile.RequiredChecks = append([]string(nil), value.Profile.RequiredChecks...)
		value.Profile.TrustMaterial = append([]string(nil), value.Profile.TrustMaterial...)
		value.Profile.Limitations = append([]string(nil), value.Profile.Limitations...)
		value.Limitations = append([]string(nil), value.Limitations...)
		result[id] = value
	}
	return result
}

func cloneSigningProviderMap(values map[string]domain.SigningProvider) map[string]domain.SigningProvider {
	result := make(map[string]domain.SigningProvider, len(values))
	for id, value := range values {
		result[id] = value
	}
	return result
}

func cloneDSSETrustRootMap(values map[string]domain.DSSETrustRoot) map[string]domain.DSSETrustRoot {
	result := make(map[string]domain.DSSETrustRoot, len(values))
	for id, value := range values {
		value.AllowedPredicateTypes = append([]string(nil), value.AllowedPredicateTypes...)
		value.ExpectedBuilderIDs = append([]string(nil), value.ExpectedBuilderIDs...)
		value.RequiredClaims = append([]string(nil), value.RequiredClaims...)
		result[id] = value
	}
	return result
}

func cloneCosignVerificationMap(values map[string]domain.CosignVerification) map[string]domain.CosignVerification {
	result := make(map[string]domain.CosignVerification, len(values))
	for id, value := range values {
		value.Checks = append([]domain.VerifyCheck(nil), value.Checks...)
		value.Profile.RequiredChecks = append([]string(nil), value.Profile.RequiredChecks...)
		value.Profile.TrustMaterial = append([]string(nil), value.Profile.TrustMaterial...)
		value.Profile.Limitations = append([]string(nil), value.Profile.Limitations...)
		value.Limitations = append([]string(nil), value.Limitations...)
		result[id] = value
	}
	return result
}

func cloneMerkleBatchMap(values map[string]domain.MerkleBatch) map[string]domain.MerkleBatch {
	result := make(map[string]domain.MerkleBatch, len(values))
	for id, value := range values {
		value.LeafHashes = append([]string(nil), value.LeafHashes...)
		value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
		result[id] = value
	}
	return result
}

func cloneTransparencyCheckpointMap(values map[string]domain.TransparencyCheckpoint) map[string]domain.TransparencyCheckpoint {
	result := make(map[string]domain.TransparencyCheckpoint, len(values))
	for id, value := range values {
		result[id] = value
	}
	return result
}

func cloneObjectRetentionPolicyMap(values map[string]domain.ObjectRetentionPolicy) map[string]domain.ObjectRetentionPolicy {
	result := make(map[string]domain.ObjectRetentionPolicy, len(values))
	for id, value := range values {
		result[id] = objectRetentionPolicyFromVerificationContext(objectRetentionPolicyToVerificationContext(value))
	}
	return result
}

func cloneBackupManifestMap(values map[string]domain.BackupManifest) map[string]domain.BackupManifest {
	result := make(map[string]domain.BackupManifest, len(values))
	for id, value := range values {
		checks := append([]domain.VerifyCheck(nil), value.ConsistencyChecks...)
		counts := make(map[string]int, len(value.ResourceCounts))
		for name, count := range value.ResourceCounts {
			counts[name] = count
		}
		value.ResourceCounts = counts
		value.ConsistencyChecks = checks
		value.Limitations = append([]string(nil), value.Limitations...)
		result[id] = value
	}
	return result
}

func toVerificationContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrValidation):
		return verificationapp.ErrValidation
	case errors.Is(err, ErrForbidden):
		return verificationapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return verificationapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return verificationapp.ErrConflict
	case errors.Is(err, ErrVerificationFailed):
		return verificationapp.ErrVerificationFailed
	case errors.Is(err, ErrFullVerificationUnavailable):
		return verificationapp.ErrFullVerificationUnavailable
	default:
		return err
	}
}

func fromVerificationContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, verificationapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, verificationapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, verificationapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, verificationapp.ErrConflict):
		return ErrConflict
	case errors.Is(err, verificationapp.ErrVerificationFailed):
		return ErrVerificationFailed
	case errors.Is(err, verificationapp.ErrFullVerificationUnavailable):
		return ErrFullVerificationUnavailable
	default:
		return err
	}
}
