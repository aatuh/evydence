package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Historical declarations retained unchanged for package-local regressions.
// HTTP fixtures use focused services and transaction repositories, not these
// caches. Neither fake provider calls nor physical staging is SQL evidence.

type CreatePDFReportPackageInput struct {
	ReportType string
	ProductID  string
	ReleaseID  string
	Title      string
}

type CreateSigningOperationInput struct {
	ProviderID        string
	SubjectType       string
	SubjectID         string
	PayloadHash       string
	ExternalSignature string
}

const signingRequestProfile = verificationapp.ProviderSigningProfile

func (l *Ledger) CreatePDFReportPackage(ctx context.Context, actor domain.Actor, in CreatePDFReportPackageInput) (domain.PDFReportPackage, error) {
	if err := ctx.Err(); err != nil {
		return domain.PDFReportPackage{}, err
	}
	if err := require(actor, ScopeReportRead); err != nil {
		return domain.PDFReportPackage{}, err
	}
	v, err := packageapp.NormalizePDFReportInput(packageapp.CreatePDFReportInput{ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title})
	if err != nil {
		return domain.PDFReportPackage{}, fromPackageContextError(err)
	}
	reportType, title, productID, releaseID := v.ReportType, v.Title, v.ProductID, v.ReleaseID
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.authorizeProductReleaseLocked(actor, ScopeReportRead, productID, releaseID); err != nil {
		return domain.PDFReportPackage{}, err
	}
	body, err := packageapp.PDFReportPayload(v)
	if err != nil {
		return domain.PDFReportPackage{}, fromPackageContextError(err)
	}
	digest := hashBytes(body)
	stagedPayload, err := l.stagePayload(ctx, actor.TenantID, "application/pdf", digest, body)
	if err != nil {
		return domain.PDFReportPackage{}, err
	}
	ref := stagedPayload.Reference()
	record := domain.PDFReportPackage{ID: newID("pdf"), TenantID: actor.TenantID, ReportType: reportType, ProductID: productID, ReleaseID: releaseID, Title: title, PayloadRef: ref, PayloadHash: digest, PayloadSize: int64(len(body)), Limitations: []string{"PDF output is reproducible report packaging and does not provide legal compliance or security certification."}, SchemaVersion: domain.PDFReportPackageVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := l.persistStagedObjectPayload(ctx, repos, stagedPayload); err != nil {
				return err
			}
			if err := repos.Future.InsertPDFReportPackage(ctx, record); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(record.CreatedAt, actor.TenantID, "pdf_report.created", "pdf_report", record.ID, actorType(actor), actorID(actor), digest, ""))
			return err
		}); err != nil {
			return domain.PDFReportPackage{}, err
		}
		saved := record
		saved.Limitations = append([]string(nil), record.Limitations...)
		l.pdfReports[record.ID] = saved
		l.publishCommittedAuditEntryLocked(entry)
		return record, nil
	}
	saved := record
	saved.Limitations = append([]string(nil), record.Limitations...)
	l.pdfReports[record.ID] = saved
	_, _ = l.appendChainLocked(actor.TenantID, "pdf_report.created", "pdf_report", record.ID, actorType(actor), actorID(actor), digest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.PDFReportPackage{}, err
	}
	return record, nil
}

func (l *Ledger) CreateSigningOperation(ctx context.Context, actor domain.Actor, in CreateSigningOperationInput) (domain.SigningOperation, error) {
	if err := ctx.Err(); err != nil {
		return domain.SigningOperation{}, err
	}
	if err := l.AuthorizeCreateSigningOperation(ctx, actor, in); err != nil {
		return domain.SigningOperation{}, err
	}
	if strings.TrimSpace(in.ExternalSignature) != "" {
		return domain.SigningOperation{}, ErrValidation
	}
	v, err := verificationapp.NormalizeSigningOperationInput(verificationapp.SigningOperationInput{ProviderID: in.ProviderID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash})
	if err != nil {
		return domain.SigningOperation{}, mapSigningOperationContextError(err)
	}
	providerID, subjectType, subjectID, payloadHash := v.ProviderID, v.SubjectType, v.SubjectID, v.PayloadHash
	l.mu.Lock()
	provider, ok := l.signingProviders[providerID]
	if !ok || provider.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.SigningOperation{}, ErrNotFound
	}
	if _, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID); err != nil {
		l.mu.Unlock()
		return domain.SigningOperation{}, err
	}
	providerActive := provider.Status == "active"
	l.mu.Unlock()

	checks := []domain.VerifyCheck{
		{Name: "provider_active", Result: "passed"},
		{Name: "payload_hash_valid", Result: "passed"},
	}
	if !providerActive {
		checks[0].Result = "failed"
	}
	signatureAlgorithm := "external-" + provider.Type
	if l.signer == nil {
		return domain.SigningOperation{}, ErrValidation
	}
	if !providerActive {
		return domain.SigningOperation{}, ErrVerificationFailed
	}
	request := SigningRequest{
		Profile:              signingRequestProfile,
		TenantID:             actor.TenantID,
		ProviderID:           provider.ID,
		ProviderType:         provider.Type,
		ExpectedProviderType: provider.Type,
		KeyRef:               provider.KeyRef,
		SubjectType:          subjectType,
		SubjectID:            subjectID,
		PayloadHash:          payloadHash,
		RequestID:            newID("sreq"),
		Nonce:                newID("snonce"),
	}
	canonicalPayloadHash, err := canonicalSigningRequestHash(request)
	if err != nil {
		return domain.SigningOperation{}, ErrValidation
	}
	request.CanonicalPayloadHash = canonicalPayloadHash
	signed, err := l.signer.Sign(ctx, request)
	if err != nil {
		return domain.SigningOperation{}, err
	}
	if err := validateSigningResult(request, signed); err != nil {
		return domain.SigningOperation{}, ErrVerificationFailed
	}
	signed = SanitizeSigningResultMetadata(signed)
	signatureValue := strings.TrimSpace(signed.Signature)
	if signatureValue == "" || len(signatureValue) > 32768 {
		return domain.SigningOperation{}, ErrValidation
	}
	if strings.TrimSpace(signed.Algorithm) != "" {
		signatureAlgorithm = strings.TrimSpace(signed.Algorithm)
	}
	checks = append(checks, signed.Checks...)
	checks = append(checks,
		domain.VerifyCheck{Name: "canonical_signing_request", Result: "passed", Detail: request.Profile},
		domain.VerifyCheck{Name: "signing_executor_invoked", Result: "passed", Detail: strings.TrimSpace(signed.KeyID)},
	)
	result := "passed"
	for _, check := range checks {
		if check.Result == "failed" {
			result = "failed"
			break
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	provider, ok = l.signingProviders[providerID]
	if !ok || provider.TenantID != actor.TenantID {
		return domain.SigningOperation{}, ErrNotFound
	}
	if err := verificationapp.ValidateSigningOperationProvider(verificationapp.SigningOperationProvider{ID: provider.ID, TenantID: provider.TenantID, Type: provider.Type, Status: provider.Status, KeyRef: provider.KeyRef}, actor.TenantID, providerID); err != nil {
		return domain.SigningOperation{}, mapSigningOperationContextError(err)
	}
	if provider.Type != request.ProviderType || provider.KeyRef != request.KeyRef {
		return domain.SigningOperation{}, ErrVerificationFailed
	}
	if _, err := l.ensureFutureSubjectLocked(actor.TenantID, subjectType, subjectID); err != nil {
		return domain.SigningOperation{}, err
	}
	signature := domain.Signature{ID: newID("sig"), TenantID: actor.TenantID, SubjectType: subjectType, SubjectID: subjectID, KeyID: provider.ID, Algorithm: signatureAlgorithm, Value: signatureValue, CreatedAt: l.now()}
	op := domain.SigningOperation{ID: newID("sop"), TenantID: actor.TenantID, ProviderID: provider.ID, SubjectType: subjectType, SubjectID: subjectID, PayloadHash: payloadHash, CanonicalPayloadHash: request.CanonicalPayloadHash, RequestID: request.RequestID, ProviderRequestID: strings.TrimSpace(signed.ProviderRequestID), SignatureRef: signature.ID, Result: result, Checks: checks, SchemaVersion: domain.SigningOperationVersion, CreatedAt: l.now()}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertSigningOperation(ctx, signature, op); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(op.CreatedAt, actor.TenantID, "signing_operation.created", "signing_operation", op.ID, actorType(actor), actorID(actor), op.PayloadHash, signature.ID))
			return err
		}); err != nil {
			return domain.SigningOperation{}, err
		}
		l.signatures[signature.ID] = signature
		l.signingOperations[op.ID] = cloneLocalSigningOperation(op)
		l.publishCommittedAuditEntryLocked(entry)
		if result != "passed" {
			return op, ErrVerificationFailed
		}
		return op, nil
	}
	l.signatures[signature.ID] = signature
	l.signingOperations[op.ID] = cloneLocalSigningOperation(op)
	_, _ = l.appendChainLocked(actor.TenantID, "signing_operation.created", "signing_operation", op.ID, actorType(actor), actorID(actor), op.PayloadHash, signature.ID)
	if err := l.persistLocked(ctx); err != nil {
		return domain.SigningOperation{}, err
	}
	if result != "passed" {
		return op, ErrVerificationFailed
	}
	return op, nil
}

func canonicalSigningRequestHash(request SigningRequest) (string, error) {
	v, err := verificationapp.CanonicalProviderSigningRequestHash(signingRequestToVerification(request))
	return v, mapSigningOperationContextError(err)
}

func validateSigningResult(request SigningRequest, result SigningResult) error {
	return mapSigningOperationContextError(verificationapp.ValidateProviderSigningResult(signingRequestToVerification(request), SigningResultToVerification(result)))
}

func (l *Ledger) AuthorizeCreatePDFReportPackage(ctx context.Context, a domain.Actor, in CreatePDFReportPackageInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeReportRead); err != nil {
		return err
	}
	v, err := packageapp.NormalizePDFReportInput(packageapp.CreatePDFReportInput{ReportType: in.ReportType, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title})
	if err != nil {
		return fromPackageContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeProductReleaseLocked(a, ScopeReportRead, v.ProductID, v.ReleaseID)
	return err
}

func signingRequestToVerification(v SigningRequest) verificationapp.ProviderSigningRequest {
	return verificationapp.ProviderSigningRequest{Profile: v.Profile, TenantID: v.TenantID, ProviderID: v.ProviderID, ProviderType: v.ProviderType, ExpectedProviderType: v.ExpectedProviderType, KeyRef: v.KeyRef, SubjectType: v.SubjectType, SubjectID: v.SubjectID, PayloadHash: v.PayloadHash, CanonicalPayloadHash: v.CanonicalPayloadHash, RequestID: v.RequestID, Nonce: v.Nonce}
}

func cloneLocalSigningOperation(v domain.SigningOperation) domain.SigningOperation {
	v.Checks = append([]domain.VerifyCheck(nil), v.Checks...)
	return v
}

func (l *Ledger) AuthorizeCreateSigningOperation(ctx context.Context, a domain.Actor, in CreateSigningOperationInput) error {
	if err := verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeKeysAdmin, TenantWide: true}); err != nil {
		return mapSigningOperationContextError(err)
	}
	v, err := verificationapp.NormalizeSigningOperationInput(verificationapp.SigningOperationInput{ProviderID: in.ProviderID, SubjectType: in.SubjectType, SubjectID: in.SubjectID, PayloadHash: in.PayloadHash})
	if err != nil {
		return mapSigningOperationContextError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p, ok := l.signingProviders[v.ProviderID]
	if !ok || p.TenantID != a.TenantID {
		return ErrNotFound
	}
	if err := verificationapp.ValidateSigningOperationProvider(verificationapp.SigningOperationProvider{ID: p.ID, TenantID: p.TenantID, Type: p.Type, Status: p.Status, KeyRef: p.KeyRef}, a.TenantID, v.ProviderID); err != nil {
		return mapSigningOperationContextError(err)
	}
	_, err = l.ensureFutureSubjectLocked(a.TenantID, v.SubjectType, v.SubjectID)
	return err
}
