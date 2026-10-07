package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Only legacy HTTP tests use these adapters. They retain actual fixture
// authorization/verification; runtime ports use bounded durable snapshots.
type verificationReadFixtureCommands struct{ catalogFixtureCommands }

func fixtureVerificationResult(value domain.VerificationResult, err error) (verificationdomain.VerificationResult, error) {
	if err != nil && !errors.Is(err, app.ErrVerificationFailed) {
		return verificationdomain.VerificationResult{}, err
	}
	result, conversionErr := domain.VerificationResultToContextModel(value)
	if conversionErr != nil {
		return verificationdomain.VerificationResult{}, app.ErrConflict
	}
	return result, err
}
func (f verificationReadFixtureCommands) VerifyAuditChain(ctx context.Context, actor domain.Actor) (verificationdomain.VerificationResult, error) {
	value, err := f.commandLedger(ctx).VerifySubject(ctx, actor, "audit_chain", "")
	return fixtureVerificationResult(value, err)
}
func (f verificationReadFixtureCommands) VerifyMerkleBatch(ctx context.Context, actor domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	value, err := f.commandLedger(ctx).VerifyMerkleBatch(ctx, actor, id)
	return fixtureVerificationResult(value, err)
}
func (f verificationReadFixtureCommands) VerifyBackupManifest(ctx context.Context, actor domain.Actor, id string) (verificationdomain.VerificationResult, error) {
	value, err := f.commandLedger(ctx).VerifyBackupManifest(ctx, actor, id)
	return fixtureVerificationResult(value, err)
}

type signingKeyFixtureQuery struct{ catalogFixtureCommands }

func signingKeyFixtureModel(value domain.SigningKey) (verificationdomain.SigningKey, error) {
	status, err := verificationdomain.ParseSigningKeyStatus(value.Status)
	if err != nil {
		return verificationdomain.SigningKey{}, verificationquery.ErrSigningKeyProjection
	}
	// Private bytes have no field in this public query model.
	return verificationdomain.SigningKey{
		ID: value.ID, TenantID: value.TenantID, KID: value.KID, Version: value.Version,
		Provider: value.Provider, Algorithm: value.Algorithm, Status: status, PublicKey: value.PublicKey, PublicKeyFingerprint: value.PublicKeyFingerprint,
		ValidFrom: value.ValidFrom, ValidUntil: value.ValidUntil, CreatedAt: value.CreatedAt, RevokedAt: value.RevokedAt,
		RevocationReason: value.RevocationReason, RevocationSemantics: value.RevocationSemantics, HistoricalValidityPolicy: value.HistoricalValidityPolicy, CompromisedAt: value.CompromisedAt,
	}, nil
}
func (f signingKeyFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[verificationdomain.SigningKey], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[verificationdomain.SigningKey]{}, err
	}
	values, err := f.commandLedger(ctx).ListSigningKeys(ctx, actor)
	if err != nil {
		return appquery.Result[verificationdomain.SigningKey]{}, err
	}
	items := make([]verificationdomain.SigningKey, 0, len(values))
	for _, value := range values {
		item, err := signingKeyFixtureModel(value)
		if err != nil {
			return appquery.Result[verificationdomain.SigningKey]{}, err
		}
		items = append(items, item)
	}
	return appquery.Page(items, request, after, func(value verificationdomain.SigningKey, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.CreatedAt, sort)
	})
}

type auditLogFixtureQuery struct{ catalogFixtureCommands }

func (f auditLogFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, filter verificationquery.AuditFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	if err := appquery.Validate(request, after); err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	// Retain the former local fixture's 500-entry inventory cap. The runtime
	// query applies SQL tenant/filter/cursor predicates before its page limit.
	values, err := f.commandLedger(ctx).ListAuditLog(ctx, actor, app.AuditLogFilter{SubjectType: filter.SubjectType, SubjectID: filter.SubjectID, Since: filter.Since, Limit: 500})
	if err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	items := make([]verificationdomain.AuditChainEntry, 0, len(values))
	for _, value := range values {
		items = append(items, verificationdomain.AuditChainEntry(value))
	}
	return appquery.Page(items, request, after, func(value verificationdomain.AuditChainEntry, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(value.ID, value.OccurredAt, sort)
	})
}

type custodyFixtureQuery struct{ catalogFixtureCommands }

func (f custodyFixtureQuery) Report(ctx context.Context, actor domain.Actor) (verificationdomain.SigningCustodyReviewReport, error) {
	value, err := f.commandLedger(ctx).SigningCustodyReviewReport(ctx, actor)
	providers := make([]verificationdomain.SigningProvider, 0, len(value.SigningProviders))
	for _, provider := range value.SigningProviders {
		providers = append(providers, domain.SigningProviderToContextModel(provider))
	}
	policies := make([]verificationdomain.ObjectRetentionPolicy, 0, len(value.ObjectRetentionPolicies))
	for _, policy := range value.ObjectRetentionPolicies {
		policies = append(policies, domain.ObjectRetentionPolicyToContextModel(policy))
	}
	checks := make([]verificationdomain.VerifyCheck, 0, len(value.Checks))
	for _, check := range value.Checks {
		checks = append(checks, verificationdomain.VerifyCheck(check))
	}
	return verificationdomain.SigningCustodyReviewReport{ReportType: value.ReportType, TenantID: value.TenantID, SigningProviders: providers, ObjectRetentionPolicies: policies, Checks: checks, Assumptions: value.Assumptions, Limitations: value.Limitations, GeneratedAt: value.GeneratedAt}, err
}

func (s *Server) bindVerificationReadFixturePorts(ledger *app.Ledger) {
	commands := verificationReadFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.auditChainVerification.(verificationReadFixtureCommands); s.auditChainVerification == nil || fixture {
		s.auditChainVerification = commands
	}
	if _, fixture := s.merkleVerification.(verificationReadFixtureCommands); s.merkleVerification == nil || fixture {
		s.merkleVerification = commands
	}
	if _, fixture := s.backupVerification.(verificationReadFixtureCommands); s.backupVerification == nil || fixture {
		s.backupVerification = commands
	}
	if _, fixture := s.signingKeyQuery.(signingKeyFixtureQuery); s.signingKeyQuery == nil || fixture {
		s.signingKeyQuery = signingKeyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	}
	if _, fixture := s.auditLogQuery.(auditLogFixtureQuery); s.auditLogQuery == nil || fixture {
		s.auditLogQuery = auditLogFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	}
	if _, fixture := s.signingCustodyQuery.(custodyFixtureQuery); s.signingCustodyQuery == nil || fixture {
		s.signingCustodyQuery = custodyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	}
}

var (
	_ AuditChainVerification = verificationReadFixtureCommands{}
	_ MerkleVerification     = verificationReadFixtureCommands{}
	_ BackupVerification     = verificationReadFixtureCommands{}
	_ SigningKeyQuery        = signingKeyFixtureQuery{}
	_ AuditLogQuery          = auditLogFixtureQuery{}
	_ SigningCustodyQuery    = custodyFixtureQuery{}
)
