// Package app owns verification policy aggregation and signing-metadata
// command orchestration. Cryptographic inspection and key generation remain
// adapter responsibilities behind the ports declared here.
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const (
	ScopeAdmin      = "admin"
	ScopeVerifyRead = "verify:read"
	ScopeKeysAdmin  = "keys:admin"
)

var (
	ErrValidation                  = errors.New("validation failed")
	ErrForbidden                   = application.ErrForbidden
	ErrNotFound                    = errors.New("not found")
	ErrConflict                    = errors.New("conflict")
	ErrVerificationFailed          = errors.New("verification failed")
	ErrFullVerificationUnavailable = errors.New("full verification unavailable")
)

// SubjectReference is the minimum tenant-owned coordinate needed to
// authorize and inspect a verification subject.
type SubjectReference struct {
	TenantID  string
	Type      string
	ID        string
	Resources application.ResourceReferences
}

// SubjectInspection contains only locally obtained verification facts. The
// Inspector adapter is responsible for cryptographic checks and must not
// silently downgrade a provider-required profile to metadata-only checks.
type SubjectInspection struct {
	Profile verificationdomain.VerificationProfile
	Checks  []verificationdomain.VerifyCheck
	// StateOverride is reserved for a conservative not_verified result when
	// every required check explicitly reports that verification was not
	// performed (for example, no tenant trust root is configured).
	StateOverride verificationdomain.VerificationState
}

// SubjectResolver must resolve within the supplied tenant. A foreign subject
// is returned as ErrNotFound so identifier existence is not disclosed.
type SubjectResolver interface {
	ResolveVerificationSubject(context.Context, string, string, string) (SubjectReference, error)
}

// SubjectInspector performs the data and cryptographic inspection for an
// already-authorized subject. Verification policy aggregation remains here.
type SubjectInspector interface {
	InspectSubject(context.Context, SubjectReference) (SubjectInspection, error)
}

type CosignSubjectResolver interface {
	ResolveCosignSubject(context.Context, string, string) (CosignSubject, error)
}

type CosignInspector interface {
	InspectCosign(context.Context, CosignSubject, VerifyCosignInput) (CosignInspection, error)
}

type IntegrityReader interface {
	ReadAuditChain(context.Context, string) ([]AuditChainLeaf, error)
	ReadMerkleBatch(context.Context, string, string) (verificationdomain.MerkleBatch, error)
	ReadObjectRetentionPolicy(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
	ReadSigningCustodySnapshot(context.Context, string) (SigningCustodySnapshot, error)
	ReadCommittedBackupSnapshot(context.Context, string) (BackupSnapshot, error)
}

type RetentionVerifier interface {
	VerifyRetention(context.Context, RetentionRequest) (RetentionObservation, bool, error)
}

type Signer interface {
	Sign(context.Context, SigningRequest) (SigningResult, error)
}

type CanonicalHasher interface {
	Hash(any) (string, error)
}

// Reader exposes committed signing metadata without private key material.
type Reader interface {
	ListSigningKeys(context.Context, string) ([]verificationdomain.SigningKey, error)
}

// PreparedSigningKey contains transient secret material produced by a key
// adapter. Repositories must persist PrivateMaterial securely and must never
// return it through a SigningKey read model.
type PreparedSigningKey struct {
	Key             verificationdomain.SigningKey
	PrivateMaterial []byte
}

// KeyFactory is an adapter boundary for cryptographic key generation.
type KeyFactory interface {
	GenerateSigningKey(context.Context, string, string, int, time.Time) (PreparedSigningKey, error)
}

// Repository is transaction-scoped. Its compare-and-swap methods must remain
// stable until the surrounding transaction commits.
type Repository interface {
	InsertVerificationResult(context.Context, verificationdomain.VerificationResult) error
	GetSigningKeyForUpdate(context.Context, string, string) (verificationdomain.SigningKey, error)
	UpdateSigningKey(context.Context, verificationdomain.SigningKey, string) error
	InsertSigningKey(context.Context, PreparedSigningKey) error
	InsertSigningProvider(context.Context, verificationdomain.SigningProvider) error
	InsertDSSETrustRoot(context.Context, verificationdomain.DSSETrustRoot) error
	InsertCosignVerification(context.Context, verificationdomain.CosignVerification) error
	InsertSignature(context.Context, verificationdomain.Signature) error
	InsertMerkleBatch(context.Context, verificationdomain.MerkleBatch) error
	InsertTransparencyCheckpoint(context.Context, verificationdomain.TransparencyCheckpoint) error
	GetObjectRetentionPolicyForUpdate(context.Context, string, string) (verificationdomain.ObjectRetentionPolicy, error)
	InsertObjectRetentionPolicy(context.Context, verificationdomain.ObjectRetentionPolicy) error
	UpdateObjectRetentionPolicy(context.Context, verificationdomain.ObjectRetentionPolicy, string) error
	InsertBackupManifest(context.Context, verificationdomain.BackupManifest) error
}

type Transaction interface {
	Verification() Repository
	Authorization() application.Authorizer
	Audit() application.AuditAppender
	Outbox() application.OutboxEnqueuer
}

type TransactionCommand func(context.Context, Transaction) error

type TransactionRunner interface {
	Execute(context.Context, TransactionCommand) error
}

type Config struct {
	Subjects          SubjectResolver
	Inspector         SubjectInspector
	CosignSubjects    CosignSubjectResolver
	CosignInspector   CosignInspector
	Integrity         IntegrityReader
	Signer            Signer
	CanonicalHasher   CanonicalHasher
	RetentionVerifier RetentionVerifier
	Reader            Reader
	Transactions      TransactionRunner
	KeyFactory        KeyFactory
	Authorizer        application.Authorizer
	Clock             application.Clock
	IDs               application.IDGenerator
}

type Service struct {
	subjects          SubjectResolver
	inspector         SubjectInspector
	cosignSubjects    CosignSubjectResolver
	cosignInspector   CosignInspector
	integrity         IntegrityReader
	signer            Signer
	canonicalHasher   CanonicalHasher
	retentionVerifier RetentionVerifier
	reader            Reader
	transactions      TransactionRunner
	keyFactory        KeyFactory
	authorizer        application.Authorizer
	clock             application.Clock
	ids               application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Subjects == nil || config.Inspector == nil || config.CosignSubjects == nil || config.CosignInspector == nil || config.Integrity == nil || config.Signer == nil || config.CanonicalHasher == nil || config.RetentionVerifier == nil || config.Reader == nil || config.Transactions == nil || config.KeyFactory == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &Service{
		subjects: config.Subjects, inspector: config.Inspector, cosignSubjects: config.CosignSubjects, cosignInspector: config.CosignInspector,
		integrity: config.Integrity, signer: config.Signer, canonicalHasher: config.CanonicalHasher, reader: config.Reader,
		retentionVerifier: config.RetentionVerifier,
		transactions:      config.Transactions, keyFactory: config.KeyFactory,
		authorizer: config.Authorizer, clock: config.Clock, ids: config.IDs,
	}, nil
}

// PrepareInitialSigningKey creates the Verification-owned key material needed
// for a new tenant. It performs no writes so the composition layer can combine
// it atomically with the Identity-owned bootstrap records.
func (s *Service) PrepareInitialSigningKey(ctx context.Context, tenantID string) (PreparedSigningKey, error) {
	return (&InitialSigningKeyCommands{InitialSigningKeyConfig{KeyFactory: s.keyFactory, Clock: s.clock}}).PrepareInitialSigningKey(ctx, tenantID)
}

// CommitInitialSigningKey writes a prepared bootstrap key through the
// Verification repository participating in the shared tenant transaction.
func (s *Service) CommitInitialSigningKey(ctx context.Context, repository Repository, tenantID string, prepared PreparedSigningKey) error {
	return (&InitialSigningKeyCommands{InitialSigningKeyConfig{KeyFactory: s.keyFactory, Clock: s.clock}}).CommitInitialSigningKey(ctx, repository, tenantID, prepared)
}

func (s *Service) VerifySubject(ctx context.Context, actor identitydomain.Actor, subjectType, subjectID string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{}, true, false); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	subjectType = strings.TrimSpace(subjectType)
	subjectID = strings.TrimSpace(subjectID)
	if subjectType == "" || (subjectID == "" && subjectType != "audit_chain") {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	subject, err := s.subjects.ResolveVerificationSubject(ctx, actor.TenantID, subjectType, subjectID)
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if !validSubjectReference(subject, actor.TenantID, subjectType, subjectID) {
		return verificationdomain.VerificationResult{}, ErrNotFound
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, subject.Resources, false, emptyResources(subject.Resources)); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	inspection, err := s.inspector.InspectSubject(ctx, subject)
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	inspection = cloneSubjectInspection(inspection)
	inspection.Profile = verificationdomain.NormalizeVerificationProfile(inspection.Profile)
	if !validInspection(inspection) {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	now := s.clock.Now().UTC()
	state := verificationdomain.AggregateVerificationState(inspection.Profile, inspection.Checks)
	if !inspection.StateOverride.IsZero() {
		if !validConservativeStateOverride(inspection, state) {
			return verificationdomain.VerificationResult{}, ErrValidation
		}
		state = inspection.StateOverride
	}
	result := verificationdomain.VerificationResult{
		ID: s.ids.NewID("vr"), TenantID: actor.TenantID, SubjectType: subject.Type, SubjectID: subject.ID,
		Result: state,
		Checks: inspection.Checks, Profile: inspection.Profile, Limitations: append([]string(nil), inspection.Profile.Limitations...),
		SchemaVersion: verificationdomain.VerificationResultSchemaVersion, VerifiedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{
			Scope: ScopeVerifyRead, Resources: subject.Resources, TenantWide: emptyResources(subject.Resources),
		}); err != nil {
			return err
		}
		if err := tx.Verification().InsertVerificationResult(ctx, result); err != nil {
			return err
		}
		if _, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "subject.verified", "verification_result", result.ID)); err != nil {
			return err
		}
		return tx.Outbox().EnqueueOutbox(ctx, application.OutboxEvent{
			ID: s.ids.NewID("job"), TenantID: actor.TenantID, Kind: "verify_subject",
			SubjectType: subject.Type, SubjectID: subject.ID, Payload: map[string]any{"result_id": result.ID}, CreatedAt: now,
		})
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	result = cloneVerificationResult(result)
	if verificationReturnsFailure(result.Result) {
		return result, ErrVerificationFailed
	}
	return result, nil
}

func (s *Service) ListSigningKeys(ctx context.Context, actor identitydomain.Actor) ([]verificationdomain.SigningKey, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if err := validateActor(actor); err != nil {
		return nil, err
	}
	if err := s.authorize(ctx, actor, ScopeVerifyRead, application.ResourceReferences{}, false, true); err != nil {
		return nil, err
	}
	values, err := s.reader.ListSigningKeys(ctx, actor.TenantID)
	if err != nil {
		return nil, err
	}
	result := make([]verificationdomain.SigningKey, 0, len(values))
	for _, value := range values {
		if value.TenantID != actor.TenantID {
			return nil, ErrNotFound
		}
		result = append(result, cloneSigningKey(value))
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

type SigningKeyRevocationInput struct {
	Reason                   string
	Semantics                string
	HistoricalValidityPolicy string
}

func NormalizeSigningKeyRevocationInput(input SigningKeyRevocationInput) (SigningKeyRevocationInput, error) {
	reason, err := NormalizeSigningKeyReason(input.Reason)
	if err != nil || len(input.Semantics) > 64 || len(input.HistoricalValidityPolicy) > 64 {
		return SigningKeyRevocationInput{}, ErrValidation
	}
	input.Reason = reason
	input.Semantics = strings.TrimSpace(input.Semantics)
	input.HistoricalValidityPolicy = strings.TrimSpace(input.HistoricalValidityPolicy)
	if !validSigningKeyText(input.Reason) {
		return SigningKeyRevocationInput{}, ErrValidation
	}
	if input.Semantics == "" {
		input.Semantics = verificationdomain.SigningKeyRevocationOrdinary
	}
	if input.HistoricalValidityPolicy == "" {
		input.HistoricalValidityPolicy = verificationdomain.SigningKeyHistoricalValidityPreserve
	}
	validSemantics := input.Semantics == verificationdomain.SigningKeyRevocationOrdinary || input.Semantics == verificationdomain.SigningKeyRevocationCompromised
	validPolicy := input.HistoricalValidityPolicy == verificationdomain.SigningKeyHistoricalValidityPreserve || input.HistoricalValidityPolicy == verificationdomain.SigningKeyHistoricalValidityInvalidateFromCompromise || input.HistoricalValidityPolicy == verificationdomain.SigningKeyHistoricalValidityInvalidateAll
	if !validSemantics || !validPolicy || (input.Semantics == verificationdomain.SigningKeyRevocationOrdinary && input.HistoricalValidityPolicy != verificationdomain.SigningKeyHistoricalValidityPreserve) {
		return SigningKeyRevocationInput{}, ErrValidation
	}
	return input, nil
}

func validSigningProviderInput(input CreateSigningProviderInput) bool {
	if !validRetentionText(input.Name, 4096) || !validRetentionText(input.KeyRef, 4096) || !validSigningProviderType(input.Type) || signingProviderRefContainsSecret(input.KeyRef) {
		return false
	}
	if input.Type == "local_encrypted_dev" && !input.Encrypted {
		return false
	}
	if input.Type == "native_pkcs11_hsm" && (!input.Encrypted || !strings.HasPrefix(input.KeyRef, "pkcs11:") || signingProviderRefContainsSecret(input.KeyRef)) {
		return false
	}
	return true
}

func validSigningProviderType(value string) bool {
	switch value {
	case "local_encrypted_dev", "aws_kms", "gcp_kms", "azure_key_vault", "pkcs11_hsm", "native_pkcs11_hsm":
		return true
	default:
		return false
	}
}

func validDSSETrustRootInput(input CreateDSSETrustRootInput) bool {
	if !validRetentionText(input.Name, 4096) || !validRetentionText(input.KeyID, 1024) || len(input.PublicKey) > 128 || input.Algorithm != "Ed25519" {
		return false
	}
	publicKey, err := base64.StdEncoding.DecodeString(input.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(input.AllowedPredicateTypes) == 0 || len(input.ExpectedBuilderIDs) == 0 || len(input.RequiredClaims) == 0 {
		return false
	}
	if !uniqueAllowedValues(input.AllowedPredicateTypes, map[string]struct{}{"https://slsa.dev/provenance/v1": {}}) {
		return false
	}
	if !uniqueNonEmpty(input.ExpectedBuilderIDs) {
		return false
	}
	return uniqueAllowedValues(input.RequiredClaims, map[string]struct{}{"builder_id": {}, "build_type": {}, "external_parameters": {}})
}

func uniqueAllowedValues(values []string, allowed map[string]struct{}) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func uniqueNonEmpty(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" {
			return false
		}
		if _, ok := seen[value]; ok {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func sortedTrimmedStrings(values []string) []string {
	result := append([]string(nil), values...)
	for index := range result {
		result[index] = strings.TrimSpace(result[index])
	}
	sort.Strings(result)
	return result
}

func signingProviderRefContainsSecret(value string) bool {
	lowered := strings.ToLower(value)
	for _, marker := range []string{"pin-value=", "pin-source=", "password=", "secret=", "token=secret"} {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return false
}

func validSubjectReference(value SubjectReference, tenantID, subjectType, subjectID string) bool {
	return value.TenantID == tenantID && strings.TrimSpace(value.Type) == subjectType && strings.TrimSpace(value.ID) == subjectID
}

func validInspection(value SubjectInspection) bool {
	if value.Profile.ID == "" || len(value.Profile.RequiredChecks) == 0 || len(value.Checks) == 0 {
		return false
	}
	for _, check := range value.Checks {
		if strings.TrimSpace(check.Name) == "" || strings.TrimSpace(check.Result) == "" {
			return false
		}
	}
	return true
}

func validConservativeStateOverride(inspection SubjectInspection, aggregate verificationdomain.VerificationState) bool {
	if inspection.StateOverride.String() != verificationdomain.VerificationStateNotVerified || aggregate.String() != verificationdomain.VerificationStateLimited {
		return false
	}
	results := make(map[string][]string, len(inspection.Checks))
	for _, check := range inspection.Checks {
		results[strings.TrimSpace(check.Name)] = append(results[strings.TrimSpace(check.Name)], strings.TrimSpace(check.Result))
	}
	for _, required := range inspection.Profile.RequiredChecks {
		values := results[required]
		if len(values) == 0 {
			return false
		}
		for _, value := range values {
			if value != verificationdomain.VerificationStateNotVerified {
				return false
			}
		}
	}
	return true
}

func validPreparedSigningKey(value PreparedSigningKey, tenantID, provider string, version int, now time.Time) bool {
	key := value.Key
	return key.ID != "" && key.TenantID == tenantID && key.KID != "" && key.Version == version && key.Provider == provider && key.Algorithm != "" && key.Status.String() == verificationdomain.SigningKeyStatusActive && key.PublicKey != "" && key.PublicKeyFingerprint != "" && !key.ValidFrom.After(now) && !key.CreatedAt.After(now) && len(value.PrivateMaterial) > 0
}

func (s *Service) authorize(ctx context.Context, actor identitydomain.Actor, scope string, resources application.ResourceReferences, scopeOnly, tenantWide bool) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources, ScopeOnly: scopeOnly, TenantWide: tenantWide})
}

func (s *Service) auditEvent(actor identitydomain.Actor, at time.Time, entryType, subjectType, subjectID string) application.AuditEvent {
	return application.AuditEvent{
		ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType, SubjectType: subjectType,
		SubjectID: subjectID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC(),
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func validateActor(actor identitydomain.Actor) error {
	if strings.TrimSpace(actor.TenantID) == "" || auditActorID(actor) == "" {
		return ErrForbidden
	}
	return nil
}

func auditActorType(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func auditActorID(actor identitydomain.Actor) string {
	if actor.CollectorID != "" {
		return strings.TrimSpace(actor.CollectorID)
	}
	if actor.UserID != "" {
		return strings.TrimSpace(actor.UserID)
	}
	return strings.TrimSpace(actor.KeyID)
}

func emptyResources(value application.ResourceReferences) bool {
	return value == (application.ResourceReferences{})
}

func verificationReturnsFailure(state verificationdomain.VerificationState) bool {
	return state.String() == verificationdomain.VerificationStateFailed || state.String() == verificationdomain.VerificationStateError
}

func cloneSubjectInspection(value SubjectInspection) SubjectInspection {
	value.Checks = append([]verificationdomain.VerifyCheck(nil), value.Checks...)
	value.Profile = cloneVerificationProfile(value.Profile)
	return value
}

func cloneVerificationResult(value verificationdomain.VerificationResult) verificationdomain.VerificationResult {
	value.Checks = append([]verificationdomain.VerifyCheck(nil), value.Checks...)
	value.Profile = cloneVerificationProfile(value.Profile)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneVerificationProfile(value verificationdomain.VerificationProfile) verificationdomain.VerificationProfile {
	value.RequiredChecks = append([]string(nil), value.RequiredChecks...)
	value.TrustMaterial = append([]string(nil), value.TrustMaterial...)
	value.Limitations = append([]string(nil), value.Limitations...)
	return value
}

func cloneSigningKey(value verificationdomain.SigningKey) verificationdomain.SigningKey {
	value.ValidUntil = timePointerValue(value.ValidUntil)
	value.RevokedAt = timePointerValue(value.RevokedAt)
	value.CompromisedAt = timePointerValue(value.CompromisedAt)
	return value
}

func cloneDSSETrustRoot(value verificationdomain.DSSETrustRoot) verificationdomain.DSSETrustRoot {
	value.AllowedPredicateTypes = append([]string(nil), value.AllowedPredicateTypes...)
	value.ExpectedBuilderIDs = append([]string(nil), value.ExpectedBuilderIDs...)
	value.RequiredClaims = append([]string(nil), value.RequiredClaims...)
	return value
}

func clonePreparedSigningKey(value PreparedSigningKey) PreparedSigningKey {
	value.Key = cloneSigningKey(value.Key)
	value.PrivateMaterial = append([]byte(nil), value.PrivateMaterial...)
	return value
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}

func timePointerValue(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	return timePointer(*value)
}
