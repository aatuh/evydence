package httpapi

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
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

// Existing command regressions compare complete public inventories. Traverse
// actual native pages rather than reviving an aggregate read for their setup.
func listFixtureSigningKeys(ctx context.Context, ledger *app.Ledger, actor domain.Actor) ([]domain.SigningKey, error) {
	query := signingKeyFixtureQuery{catalogFixtureCommands{ledger: ledger}}
	request := appquery.PageRequest{PageSize: appquery.MaxPageSize, Sort: appquery.SortID, Direction: appquery.Ascending}
	var after *appquery.SortKey
	items := make([]domain.SigningKey, 0)
	for {
		page, err := query.ListPage(ctx, actor, request, after)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Items {
			items = append(items, signingKeyFromQuery(v))
		}
		if page.Next == nil {
			return items, nil
		}
		after = page.Next
	}
}

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
	query, err := verificationquery.NewSigningKeys(f)
	if err != nil {
		return appquery.Result[verificationdomain.SigningKey]{}, err
	}
	page, err := query.ListPage(ctx, actor, request, after)
	return page, mapSigningKeyQueryError(err)
}

func (f signingKeyFixtureQuery) PageSigningKeys(ctx context.Context, request verificationquery.SigningKeyPageRequest) (appquery.Result[verificationdomain.SigningKey], error) {
	var out appquery.Result[verificationdomain.SigningKey]
	if ctx == nil {
		return out, verificationquery.ErrSigningKeyValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Signatures.(verificationquery.SigningKeyReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageSigningKeys(ctx, request)
		return err
	})
	if err != nil {
		return appquery.Result[verificationdomain.SigningKey]{}, err
	}
	return out, nil
}

type auditLogFixtureQuery struct{ catalogFixtureCommands }

func (f auditLogFixtureQuery) ListPage(ctx context.Context, actor domain.Actor, filter verificationquery.AuditFilter, request appquery.PageRequest, after *appquery.SortKey) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	query, err := verificationquery.NewAuditLog(f)
	if err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	page, err := query.ListPage(ctx, actor, filter, request, after)
	if errors.Is(err, verificationquery.ErrValidation) || errors.Is(err, appquery.ErrInvalidPage) || errors.Is(err, appquery.ErrInvalidCursor) {
		err = app.ErrValidation
	} else if errors.Is(err, verificationquery.ErrInvalidProjection) {
		err = app.ErrConflict
	} else if errors.Is(err, application.ErrForbidden) {
		err = app.ErrForbidden
	} else if errors.Is(err, application.ErrUnauthorized) {
		err = app.ErrUnauthorized
	}
	return page, err
}

func (f auditLogFixtureQuery) PageAuditLog(ctx context.Context, request verificationquery.AuditPageRequest) (appquery.Result[verificationdomain.AuditChainEntry], error) {
	var out appquery.Result[verificationdomain.AuditChainEntry]
	if ctx == nil {
		return out, verificationquery.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Audit.(verificationquery.AuditLogReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.PageAuditLog(ctx, request)
		return err
	})
	if err != nil {
		return appquery.Result[verificationdomain.AuditChainEntry]{}, err
	}
	return out, nil
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
