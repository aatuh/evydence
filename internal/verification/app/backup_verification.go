package app

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

const MaxBackupVerificationChecks = 4096
const MaxBackupVerificationBytes = 8 << 20

// BackupVerificationSnapshot contains recorded facts only: no present-day
// database state, private material, payload bytes or restore observations.
type BackupVerificationSnapshot struct {
	Subject   SubjectReference
	StateHash string
	Checks    []verificationdomain.VerifyCheck
}
type BackupVerificationReader interface {
	ReadBackupVerification(context.Context, SubjectReference) (BackupVerificationSnapshot, error)
}
type BackupVerificationTransaction interface {
	BackupVerificationReader
	application.Authorizer
	verificationReceiptTransaction
}
type BackupVerificationTransactions interface {
	ExecuteBackupVerification(context.Context, func(context.Context, BackupVerificationTransaction) error) error
}
type BackupVerificationConfig struct {
	Transactions BackupVerificationTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type BackupVerificationCommands struct{ config BackupVerificationConfig }

func NewBackupVerificationCommands(c BackupVerificationConfig) (*BackupVerificationCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &BackupVerificationCommands{c}, nil
}
func (s *BackupVerificationCommands) VerifyBackupManifest(ctx context.Context, actor identitydomain.Actor, id string) (verificationdomain.VerificationResult, error) {
	if err := contextError(ctx); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := validateActor(actor); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, ScopeOnly: true}); err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	id = strings.TrimSpace(id)
	if !validSigningKeyText(id) || len(id) > 1024 {
		return verificationdomain.VerificationResult{}, ErrValidation
	}
	var result verificationdomain.VerificationResult
	err := s.config.Transactions.ExecuteBackupVerification(ctx, func(ctx context.Context, tx BackupVerificationTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeVerifyRead, TenantWide: true}); err != nil {
			return err
		}
		subject := SubjectReference{TenantID: actor.TenantID, Type: "backup_manifest", ID: id}
		snapshot, err := tx.ReadBackupVerification(ctx, subject)
		if err != nil {
			return err
		}
		if snapshot.Subject != subject {
			return ErrNotFound
		}
		inspection, err := InspectBackupManifestRecordedChecks(snapshot)
		if err != nil {
			return err
		}
		result, err = persistVerificationReceipt(ctx, tx, actor, subject, inspection, s.config.Clock.Now().UTC(), s.config.IDs)
		return err
	})
	if err != nil {
		return verificationdomain.VerificationResult{}, err
	}
	if verificationReturnsFailure(result.Result) {
		return cloneVerificationResult(result), ErrVerificationFailed
	}
	return cloneVerificationResult(result), nil
}

// InspectBackupManifestRecordedChecks preserves the legacy recorded-check
// profile. It does not rehash a live export or establish successful restoration.
func InspectBackupManifestRecordedChecks(s BackupVerificationSnapshot) (SubjectInspection, error) {
	validText := func(text string, limit int, empty bool) bool {
		return (empty || strings.TrimSpace(text) != "") && len(text) <= limit && utf8.ValidString(text) && !strings.ContainsRune(text, 0)
	}
	if s.Subject.Type != "backup_manifest" || s.Subject.Resources != (application.ResourceReferences{}) || !validText(s.Subject.ID, 1024, false) || !validText(s.Subject.TenantID, 1024, false) || !validText(s.StateHash, 1024, false) || len(s.Checks) > MaxBackupVerificationChecks {
		return SubjectInspection{}, ErrConflict
	}
	checks := append([]verificationdomain.VerifyCheck(nil), s.Checks...)
	for _, check := range checks {
		if !validText(check.Name, 128, false) || !validText(check.Result, 64, false) || !validText(check.Detail, 1024, true) {
			return SubjectInspection{}, ErrConflict
		}
	}
	raw, err := json.Marshal(checks)
	if err != nil || len(raw)+len(s.StateHash) > MaxBackupVerificationBytes {
		return SubjectInspection{}, ErrConflict
	}
	checks = append(checks, verificationdomain.VerifyCheck{Name: "backup_manifest_present", Result: "passed", Detail: s.StateHash})
	required := []string{}
	seen := map[string]bool{}
	for _, check := range checks {
		name := strings.TrimSpace(check.Name)
		if !seen[name] {
			required = append(required, name)
			seen[name] = true
		}
	}
	return SubjectInspection{Checks: checks, Profile: verificationdomain.NormalizeVerificationProfile(verificationdomain.VerificationProfile{ID: verificationdomain.VerificationProfileBackupManifest, Version: verificationdomain.VerificationProfileSchemaVersion, RequiredChecks: required, TrustMaterial: []string{"backup manifest canonical hash"}, IdentityPolicy: "tenant-scoped verification authorization", TransparencyProof: "not_evaluated", PayloadScope: "backup manifest consistency counts and state hash", PayloadDigest: s.StateHash, Limitations: []string{"Backup manifest verification does not prove an external backup can be restored or meets an operator's retention policy."}})}, nil
}
