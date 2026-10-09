package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

const packageSnapshotVersion = packageapp.CustomerPackageSnapshotVersion

func (l *Ledger) configurePackageCommands() error {
	service, err := packageapp.NewService(packageapp.Config{
		Reader: ledgerPackageReader{ledger: l}, Transactions: ledgerPackageTransactions{ledger: l},
		Authorizer: ledgerContextAuthorizer{ledger: l}, Canonicalizer: ledgerPackageCanonicalizer{},
		Signer:              ledgerPackageSigner{ledger: l},
		ProjectionRefresher: ledgerPackageProjectionRefresher{ledger: l}, Clock: application.ClockFunc(l.now),
		IDs: application.IDGeneratorFunc(newID),
	})
	if err != nil {
		return err
	}
	l.packageCommands = service
	return nil
}

type ledgerPackageCanonicalizer struct{}

func (ledgerPackageCanonicalizer) HashPackageManifest(_ context.Context, manifest map[string]any) (string, error) {
	return canonicalAnyHash(manifest)
}

func (ledgerPackageCanonicalizer) HashPackageBytes(_ context.Context, body []byte) (string, error) {
	return hashBytes(body), nil
}

type ledgerPackageSigner struct{ ledger *Ledger }

func (s ledgerPackageSigner) SignPackage(ctx context.Context, request packageapp.PackageSigningRequest) (packageapp.PackageSignature, error) {
	if err := ctx.Err(); err != nil {
		return packageapp.PackageSignature{}, err
	}
	s.ledger.mu.Lock()
	defer s.ledger.mu.Unlock()
	var active domain.SigningKey
	for _, key := range s.ledger.signingKeys {
		if key.TenantID != request.TenantID || key.Status != domain.SigningKeyStatusActive {
			continue
		}
		if active.ID == "" || key.Version > active.Version || (key.Version == active.Version && key.ID < active.ID) {
			active = key
		}
	}
	if active.ID == "" || active.Algorithm != "Ed25519" || len(active.Private) != ed25519.PrivateKeySize {
		return packageapp.PackageSignature{}, packageapp.ErrConflict
	}
	value := ed25519.Sign(ed25519.PrivateKey(active.Private), []byte(request.PayloadHash))
	return packageapp.PackageSignature{
		ID: newID("sig"), TenantID: request.TenantID, SubjectType: request.SubjectType, SubjectID: request.SubjectID,
		KeyID: active.ID, Algorithm: active.Algorithm, Value: base64.RawStdEncoding.EncodeToString(value), CreatedAt: request.CreatedAt,
	}, nil
}

type ledgerPackageProjectionRefresher struct{ ledger *Ledger }

func (r ledgerPackageProjectionRefresher) RefreshPackageProjection(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return toPackageContextError(r.ledger.refreshWorkerProjectionLocked(ctx, tenantID))
}

type ledgerPackageReader struct{ ledger *Ledger }

func (r ledgerPackageReader) GetRedactionProfile(ctx context.Context, tenantID, id string) (packagedomain.RedactionProfile, error) {
	if err := ctx.Err(); err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getPackageRedactionProfileLocked(r.ledger, tenantID, id)
}

func (r ledgerPackageReader) GetCustomerSecurityPackage(ctx context.Context, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	if err := ctx.Err(); err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	return getCustomerSecurityPackageLocked(r.ledger, tenantID, id)
}

func (r ledgerPackageReader) GetCustomReportTemplate(ctx context.Context, tenantID, id string) (packagedomain.CustomReportTemplate, error) {
	if err := ctx.Err(); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	value, ok := r.ledger.reportTemplates[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return packagedomain.CustomReportTemplate{}, packageapp.ErrNotFound
	}
	return customReportTemplateToPackageContext(value), nil
}

// ReadCommittedPackageSnapshot holds the compatibility read-model lock for the
// entire snapshot. Focused command adapters publish their maps only after the
// durable transaction commits, so this view cannot observe a partial local
// command. EVY-905 replaces this bridge with a database snapshot query.
func (r ledgerPackageReader) ReadCommittedPackageSnapshot(ctx context.Context, tenantID, productID, releaseID string) (packageapp.PackageSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return packageapp.PackageSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.ensureScopeLocked(tenantID, productID, "", releaseID); err != nil {
		return packageapp.PackageSnapshot{}, toPackageContextError(err)
	}
	readinessChecks := []packagedomain.PolicyCheckSnapshot(nil)
	if releaseID != "" {
		readinessSnapshot, err := buildRiskReadinessSnapshotLocked(r.ledger, tenantID, releaseID)
		if err != nil {
			return packageapp.PackageSnapshot{}, toPackageContextError(fromRiskContextError(err))
		}
		evaluation, err := riskapp.EvaluateReadinessSnapshot(readinessSnapshot, r.ledger.now().UTC())
		if err != nil {
			return packageapp.PackageSnapshot{}, toPackageContextError(fromRiskContextError(err))
		}
		readinessChecks = packageRiskChecksToContext(evaluation.Checks)
	}
	permissiveProfile := domain.RedactionProfile{AllowedTypes: []string{"vulnerability_decision", "build", "build_attestation"}}
	snapshot := packageapp.PackageSnapshot{
		SnapshotVersion: packageSnapshotVersion, TenantID: tenantID, ProductID: productID, ReleaseID: releaseID,
		Tenant: r.ledger.packageTenantMetadataLocked(tenantID), Organization: r.ledger.packageOrganizationMetadataLocked(tenantID),
		Product: packageProductMetadata(r.ledger.products[productID]), Release: packageReleaseMetadata(r.ledger.releases[releaseID]),
		Artifacts: r.ledger.packageArtifactMetadataLocked(tenantID, releaseID), ReadinessChecks: readinessChecks,
		VerificationMaterial: r.ledger.packageVerificationMaterialLocked(tenantID, releaseID),
		SBOMs:                r.ledger.packageSBOMMetadataLocked(tenantID, releaseID), VulnerabilityScans: r.ledger.packageVulnerabilityScanMetadataLocked(tenantID, releaseID),
		VEXDocuments: r.ledger.packageVEXMetadataLocked(tenantID, releaseID), APIContracts: r.ledger.packageAPIContractMetadataLocked(tenantID, releaseID),
		Decisions: r.ledger.packageDecisionSummariesLocked(tenantID, releaseID, permissiveProfile),
		Approvals: r.ledger.packageApprovalSummariesLocked(tenantID, productID, releaseID), Exceptions: r.ledger.packageExceptionSummariesLocked(tenantID, releaseID),
		Waivers: r.ledger.packageWaiverSummariesLocked(tenantID, productID, releaseID), AnswerLibrary: r.ledger.packageAnswerLibraryMetadataLocked(tenantID, productID, releaseID),
		ObjectLockProofs: r.ledger.packageObjectLockProofsLocked(tenantID), Provenance: r.ledger.packageProvenanceMetadataLocked(tenantID, releaseID, permissiveProfile),
	}
	for _, item := range r.ledger.evidence {
		if item.TenantID != tenantID {
			continue
		}
		if releaseID != "" {
			if item.ReleaseID != releaseID {
				continue
			}
		} else if item.ProductID != productID {
			continue
		}
		snapshot.Evidence = append(snapshot.Evidence, packageapp.EvidenceReference{ID: item.ID, Type: item.Type})
	}
	return snapshot, nil
}

func (r ledgerPackageReader) ReadCommittedReleaseBundleSnapshot(ctx context.Context, tenantID, releaseID string) (packageapp.ReleaseBundleSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return packageapp.ReleaseBundleSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	release, ok := r.ledger.releases[strings.TrimSpace(releaseID)]
	if !ok || release.TenantID != tenantID {
		return packageapp.ReleaseBundleSnapshot{}, packageapp.ErrNotFound
	}
	if err := r.ledger.ensureScopeLocked(tenantID, release.ProductID, "", release.ID); err != nil {
		return packageapp.ReleaseBundleSnapshot{}, toPackageContextError(err)
	}
	evidenceIDs := make([]string, 0)
	for _, item := range r.ledger.evidence {
		if item.TenantID == tenantID && item.ReleaseID == release.ID {
			evidenceIDs = append(evidenceIDs, item.ID)
		}
	}
	sort.Strings(evidenceIDs)
	entries := r.ledger.chain[tenantID]
	head := ""
	if len(entries) > 0 {
		head = entries[len(entries)-1].EntryHash
	}
	return packageapp.ReleaseBundleSnapshot{
		SnapshotVersion: packageapp.ReleaseBundleSnapshotVersion,
		TenantID:        tenantID, ProductID: release.ProductID, ReleaseID: release.ID,
		ReleaseVersion: release.Version, ReleaseState: release.State, EvidenceIDs: evidenceIDs,
		ChainSequence: len(entries), ChainHeadHash: head, ObjectLockProofs: r.ledger.packageObjectLockProofsLocked(tenantID),
	}, nil
}

func (r ledgerPackageReader) ReadCommittedEvidenceBundleSnapshot(ctx context.Context, tenantID, releaseID string) (packageapp.EvidenceBundleSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return packageapp.EvidenceBundleSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	productID := ""
	if releaseID != "" {
		release, ok := r.ledger.releases[releaseID]
		if !ok || release.TenantID != tenantID {
			return packageapp.EvidenceBundleSnapshot{}, packageapp.ErrNotFound
		}
		productID = release.ProductID
	}
	evidence := make([]packageapp.EvidenceBundleEvidence, 0)
	for _, item := range r.ledger.evidence {
		if item.TenantID != tenantID || (releaseID != "" && item.ReleaseID != releaseID) {
			continue
		}
		evidence = append(evidence, packageapp.EvidenceBundleEvidence{
			ID: item.ID,
			Resources: application.ResourceReferences{
				ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID,
				BuildID: item.BuildID, DeploymentID: item.DeploymentID,
			},
		})
	}
	head := ""
	if entries := r.ledger.chain[tenantID]; len(entries) > 0 {
		head = entries[len(entries)-1].EntryHash
	}
	return packageapp.EvidenceBundleSnapshot{
		SnapshotVersion: packageapp.EvidenceBundleSnapshotVersion, TenantID: tenantID, ProductID: productID,
		ReleaseID: releaseID, Evidence: evidence, AuditChainHead: head,
		ObjectLockProofs: r.ledger.packageObjectLockProofsLocked(tenantID),
	}, nil
}

// ReadCommittedReadinessReportSnapshot builds policy facts and presentation
// inputs while holding one compatibility read-model lock. This prevents a
// report from combining pre-commit and post-commit state. EVY-905 replaces the
// bridge with a database snapshot query without changing the application port.
func (r ledgerPackageReader) ReadCommittedReadinessReportSnapshot(ctx context.Context, tenantID, releaseID string) (packageapp.ReadinessReportSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return packageapp.ReadinessReportSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	riskSnapshot, err := buildRiskReadinessSnapshotLocked(r.ledger, tenantID, releaseID)
	if err != nil {
		return packageapp.ReadinessReportSnapshot{}, toPackageContextError(fromRiskContextError(err))
	}
	evaluation, err := riskapp.EvaluateReadinessSnapshot(riskSnapshot, r.ledger.now().UTC())
	if err != nil {
		return packageapp.ReadinessReportSnapshot{}, toPackageContextError(fromRiskContextError(err))
	}
	result := packageapp.ReadinessReportSnapshot{
		SnapshotVersion: packageapp.ReadinessReportSnapshotVersion,
		TenantID:        tenantID, ProductID: riskSnapshot.ProductID, ReleaseID: releaseID,
		Result: evaluation.Result, PolicySet: evaluation.PolicySet,
		Checks:                   packageRiskChecksToContext(evaluation.Checks),
		BlockingFindings:         packageBlockingFindingsToContext(r.ledger.unhandledCriticalFindingsLocked(tenantID, releaseID)),
		AcceptedExceptions:       packageExceptionsToContext(r.ledger.acceptedExceptionsForReleaseLocked(tenantID, releaseID)),
		ActiveDecisionCount:      r.ledger.activeDecisionCountForReleaseLocked(tenantID, releaseID),
		HasActiveCustomerPackage: r.ledger.hasActiveCustomerPackageLocked(tenantID, releaseID),
	}
	return result, nil
}

func (r ledgerPackageReader) ReadCommittedCRAReadinessHTMLSnapshot(ctx context.Context, tenantID, productID, releaseID string) (packageapp.CRAReadinessHTMLSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return packageapp.CRAReadinessHTMLSnapshot{}, err
	}
	r.ledger.mu.Lock()
	defer r.ledger.mu.Unlock()
	if err := r.ledger.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return packageapp.CRAReadinessHTMLSnapshot{}, toPackageContextError(err)
	}
	if err := r.ledger.ensureScopeLocked(tenantID, productID, "", releaseID); err != nil {
		return packageapp.CRAReadinessHTMLSnapshot{}, toPackageContextError(err)
	}
	report, err := r.ledger.craReadinessReportLocked(tenantID, productID, releaseID)
	if err != nil {
		return packageapp.CRAReadinessHTMLSnapshot{}, toPackageContextError(err)
	}
	return packageapp.CRAReadinessHTMLSnapshot{
		SnapshotVersion: packageapp.CRAReadinessHTMLSnapshotVersion,
		TenantID:        tenantID, ProductID: productID, ReleaseID: releaseID,
		Result: report.Result, Limitations: append([]string(nil), report.Limitations...),
	}, nil
}

type ledgerPackageTransactions struct{ ledger *Ledger }

func (r ledgerPackageTransactions) Execute(ctx context.Context, command packageapp.TransactionCommand) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l := r.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	tx := newLedgerPackageTransaction(l)
	if l.unitOfWork != nil {
		err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repositories Repositories) error {
			tx.repositories = &repositories
			return command(ctx, tx)
		})
		if err != nil {
			return toPackageContextError(err)
		}
		tx.publish()
		return nil
	}
	if err := command(ctx, tx); err != nil {
		return toPackageContextError(err)
	}
	return tx.commitCompatibility(ctx)
}

type ledgerPackageTransaction struct {
	ledger           *Ledger
	repositories     *Repositories
	redactions       map[string]domain.RedactionProfile
	customerPackages map[string]domain.CustomerSecurityPackage
	releaseBundles   map[string]domain.ReleaseBundle
	evidenceBundles  map[string]domain.EvidenceBundle
	bundleImports    map[string]domain.EvidenceBundleImport
	reportTemplates  map[string]domain.CustomReportTemplate
	renderedReports  map[string]domain.RenderedCustomReport
	htmlReports      map[string]domain.HTMLReportPackage
	signatures       map[string]domain.Signature
	audit            []domain.AuditChainEntry
	outbox           []OutboxJob
}

func newLedgerPackageTransaction(ledger *Ledger) *ledgerPackageTransaction {
	return &ledgerPackageTransaction{
		ledger: ledger, redactions: map[string]domain.RedactionProfile{}, customerPackages: map[string]domain.CustomerSecurityPackage{},
		releaseBundles: map[string]domain.ReleaseBundle{}, evidenceBundles: map[string]domain.EvidenceBundle{},
		bundleImports: map[string]domain.EvidenceBundleImport{}, reportTemplates: map[string]domain.CustomReportTemplate{},
		renderedReports: map[string]domain.RenderedCustomReport{}, htmlReports: map[string]domain.HTMLReportPackage{},
		signatures: map[string]domain.Signature{},
	}
}

func (t *ledgerPackageTransaction) Packages() packageapp.Repository                   { return t }
func (t *ledgerPackageTransaction) Signatures() packageapp.PackageSignatureRepository { return t }
func (t *ledgerPackageTransaction) Authorization() application.Authorizer {
	return ledgerLockedContextAuthorizer{ledger: t.ledger}
}
func (t *ledgerPackageTransaction) Audit() application.AuditAppender   { return t }
func (t *ledgerPackageTransaction) Outbox() application.OutboxEnqueuer { return t }

func (t *ledgerPackageTransaction) GetRedactionProfile(ctx context.Context, tenantID, id string) (packagedomain.RedactionProfile, error) {
	if err := ctx.Err(); err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	value, ok := t.redactions[id]
	if !ok {
		value, ok = t.ledger.redactions[id]
	}
	if !ok || value.TenantID != tenantID {
		return packagedomain.RedactionProfile{}, packageapp.ErrNotFound
	}
	return redactionProfileToPackageContext(value), nil
}

func (t *ledgerPackageTransaction) InsertRedactionProfile(ctx context.Context, profile packagedomain.RedactionProfile) error {
	legacy := redactionProfileFromPackageContext(profile)
	if _, exists := t.ledger.redactions[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.redactions[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertRedactionProfile(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.redactions[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertReleaseBundle(ctx context.Context, bundle packagedomain.ReleaseBundle) error {
	legacy := domain.ReleaseBundleFromContextModel(bundle)
	if _, exists := t.ledger.bundles[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.releaseBundles[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertReleaseBundle(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.releaseBundles[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertEvidenceBundle(ctx context.Context, bundle packagedomain.EvidenceBundle) error {
	legacy := evidenceBundleFromPackageContext(bundle)
	if _, exists := t.ledger.evidenceBundles[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.evidenceBundles[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertEvidenceBundle(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.evidenceBundles[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertEvidenceBundleImport(ctx context.Context, record packagedomain.EvidenceBundleImport) error {
	legacy := evidenceBundleImportFromPackageContext(record)
	if _, exists := t.ledger.bundleImports[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.bundleImports[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertEvidenceBundleImport(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.bundleImports[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) GetCustomReportTemplate(ctx context.Context, tenantID, id string) (packagedomain.CustomReportTemplate, error) {
	if err := ctx.Err(); err != nil {
		return packagedomain.CustomReportTemplate{}, err
	}
	if t.repositories != nil {
		value, err := t.repositories.Packages.GetCustomReportTemplate(ctx, tenantID, id)
		return customReportTemplateToPackageContext(value), toPackageContextError(err)
	}
	value, ok := t.reportTemplates[id]
	if !ok {
		value, ok = t.ledger.reportTemplates[id]
	}
	if !ok || value.TenantID != tenantID {
		return packagedomain.CustomReportTemplate{}, packageapp.ErrNotFound
	}
	return customReportTemplateToPackageContext(value), nil
}

func (t *ledgerPackageTransaction) InsertCustomReportTemplate(ctx context.Context, value packagedomain.CustomReportTemplate) error {
	legacy := customReportTemplateFromPackageContext(value)
	if _, exists := t.ledger.reportTemplates[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.reportTemplates[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertCustomReportTemplate(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.reportTemplates[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertRenderedCustomReport(ctx context.Context, value packagedomain.RenderedCustomReport) error {
	legacy := renderedCustomReportFromPackageContext(value)
	if _, exists := t.ledger.renderedReports[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.renderedReports[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertRenderedCustomReport(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.renderedReports[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertHTMLReportPackage(ctx context.Context, value packagedomain.HTMLReportPackage) error {
	legacy := htmlReportPackageFromPackageContext(value)
	if _, exists := t.ledger.htmlReports[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.htmlReports[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertHTMLReportPackage(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.htmlReports[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertPackageSignature(ctx context.Context, signature packageapp.PackageSignature) error {
	legacy := domain.Signature{
		ID: signature.ID, TenantID: signature.TenantID, SubjectType: signature.SubjectType, SubjectID: signature.SubjectID,
		KeyID: signature.KeyID, Algorithm: signature.Algorithm, Value: signature.Value, CreatedAt: signature.CreatedAt,
	}
	if _, exists := t.ledger.signatures[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.signatures[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Signatures.InsertSignature(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.signatures[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) InsertCustomerSecurityPackage(ctx context.Context, pkg packagedomain.CustomerSecurityPackage) error {
	legacy := customerSecurityPackageFromContext(pkg)
	if _, exists := t.ledger.customerPackages[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if _, exists := t.customerPackages[legacy.ID]; exists {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.InsertCustomerSecurityPackage(ctx, legacy); err != nil {
			return toPackageContextError(err)
		}
	}
	t.customerPackages[legacy.ID] = legacy
	return nil
}

func (t *ledgerPackageTransaction) GetCustomerSecurityPackageForUpdate(ctx context.Context, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	if err := ctx.Err(); err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	if t.repositories != nil {
		value, err := t.repositories.Packages.GetCustomerSecurityPackageForUpdate(ctx, tenantID, id)
		if err != nil {
			return packagedomain.CustomerSecurityPackage{}, toPackageContextError(err)
		}
		// Stage the current durable value for the existing CAS/publication
		// adapter. A focused access may have advanced its cached counter.
		t.customerPackages[id] = value
		return customerSecurityPackageToContext(value), nil
	}
	value, ok := t.customerPackages[id]
	if !ok {
		value, ok = t.ledger.customerPackages[id]
	}
	if !ok || value.TenantID != tenantID {
		return packagedomain.CustomerSecurityPackage{}, packageapp.ErrNotFound
	}
	return customerSecurityPackageToContext(value), nil
}

func (t *ledgerPackageTransaction) UpdateCustomerSecurityPackageAccess(ctx context.Context, previous, next packagedomain.CustomerSecurityPackage) error {
	current, ok := t.customerPackages[previous.ID]
	if !ok {
		current, ok = t.ledger.customerPackages[previous.ID]
	}
	legacyPrevious := customerSecurityPackageFromContext(previous)
	legacyNext := customerSecurityPackageFromContext(next)
	if !ok || current.TenantID != previous.TenantID || !reflect.DeepEqual(current, legacyPrevious) || legacyNext.ID != legacyPrevious.ID || legacyNext.TenantID != legacyPrevious.TenantID || legacyNext.AccessCount != legacyPrevious.AccessCount+1 {
		return packageapp.ErrConflict
	}
	if t.repositories != nil {
		if err := t.repositories.Packages.UpdateCustomerSecurityPackageAccess(ctx, legacyPrevious, legacyNext); err != nil {
			return toPackageContextError(err)
		}
	}
	t.customerPackages[legacyNext.ID] = legacyNext
	return nil
}

func (t *ledgerPackageTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	entry := domain.AuditChainEntry{
		ID: event.ID, TenantID: event.TenantID, EntryType: event.EntryType, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, ActorType: event.ActorType, ActorID: event.ActorID, OccurredAt: event.OccurredAt,
		PayloadHash: event.PayloadHash, SignatureRef: event.SignatureRef, SchemaVersion: domain.AuditChainEntrySchemaVersion,
	}
	if t.repositories != nil {
		committed, err := t.repositories.Audit.Append(ctx, entry)
		if err != nil {
			return application.AuditReceipt{}, toPackageContextError(err)
		}
		entry = committed
	} else if err := t.completeCompatibilityAudit(&entry); err != nil {
		return application.AuditReceipt{}, toPackageContextError(err)
	}
	t.audit = append(t.audit, entry)
	return application.AuditReceipt{ID: entry.ID}, nil
}

func (t *ledgerPackageTransaction) EnqueueOutbox(ctx context.Context, event application.OutboxEvent) error {
	job := OutboxJob{
		ID: event.ID, TenantID: event.TenantID, Kind: event.Kind, SubjectType: event.SubjectType,
		SubjectID: event.SubjectID, Payload: cloneMap(event.Payload), CreatedAt: event.CreatedAt,
	}
	if err := EnsureOutboxDeduplicationKey(&job); err != nil {
		return packageapp.ErrValidation
	}
	if t.repositories != nil {
		if err := t.repositories.Outbox.Enqueue(ctx, job); err != nil {
			return toPackageContextError(err)
		}
		return nil
	}
	t.outbox = append(t.outbox, job)
	return nil
}

func (t *ledgerPackageTransaction) completeCompatibilityAudit(entry *domain.AuditChainEntry) error {
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

func (t *ledgerPackageTransaction) publish() {
	for id, value := range t.redactions {
		t.ledger.redactions[id] = value
	}
	for id, value := range t.customerPackages {
		t.ledger.customerPackages[id] = value
	}
	for id, value := range t.releaseBundles {
		t.ledger.bundles[id] = value
	}
	for id, value := range t.evidenceBundles {
		t.ledger.evidenceBundles[id] = value
	}
	for id, value := range t.bundleImports {
		t.ledger.bundleImports[id] = value
	}
	for id, value := range t.reportTemplates {
		t.ledger.reportTemplates[id] = value
	}
	for id, value := range t.renderedReports {
		t.ledger.renderedReports[id] = value
	}
	for id, value := range t.htmlReports {
		t.ledger.htmlReports[id] = value
	}
	for id, value := range t.signatures {
		t.ledger.signatures[id] = value
	}
	for _, entry := range t.audit {
		t.ledger.publishCommittedAuditEntryLocked(entry)
	}
}

func (t *ledgerPackageTransaction) commitCompatibility(ctx context.Context) error {
	redactions := clonePackageRedactionMap(t.ledger.redactions)
	packages := cloneCustomerPackageMap(t.ledger.customerPackages)
	bundles := cloneReleaseBundleMap(t.ledger.bundles)
	evidenceBundles := cloneEvidenceBundleMap(t.ledger.evidenceBundles)
	bundleImports := cloneEvidenceBundleImportMap(t.ledger.bundleImports)
	reportTemplates := cloneCustomReportTemplateMap(t.ledger.reportTemplates)
	renderedReports := cloneRenderedCustomReportMap(t.ledger.renderedReports)
	htmlReports := cloneHTMLReportPackageMap(t.ledger.htmlReports)
	signatures := cloneSignatureMap(t.ledger.signatures)
	chain := cloneAuditChainMap(t.ledger.chain)
	t.publish()
	persist := t.ledger.persistLocked
	if len(t.outbox) > 0 {
		mutation, err := t.ledger.criticalMutationLocked()
		if err != nil {
			t.restore(redactions, packages, bundles, evidenceBundles, bundleImports, reportTemplates, renderedReports, htmlReports, signatures, chain)
			return toPackageContextError(err)
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
	}
	if err := persist(ctx); err != nil {
		t.restore(redactions, packages, bundles, evidenceBundles, bundleImports, reportTemplates, renderedReports, htmlReports, signatures, chain)
		return toPackageContextError(err)
	}
	return nil
}

func (t *ledgerPackageTransaction) restore(redactions map[string]domain.RedactionProfile, packages map[string]domain.CustomerSecurityPackage, bundles map[string]domain.ReleaseBundle, evidenceBundles map[string]domain.EvidenceBundle, bundleImports map[string]domain.EvidenceBundleImport, reportTemplates map[string]domain.CustomReportTemplate, renderedReports map[string]domain.RenderedCustomReport, htmlReports map[string]domain.HTMLReportPackage, signatures map[string]domain.Signature, chain map[string][]domain.AuditChainEntry) {
	t.ledger.redactions = redactions
	t.ledger.customerPackages = packages
	t.ledger.bundles = bundles
	t.ledger.evidenceBundles = evidenceBundles
	t.ledger.bundleImports = bundleImports
	t.ledger.reportTemplates = reportTemplates
	t.ledger.renderedReports = renderedReports
	t.ledger.htmlReports = htmlReports
	t.ledger.signatures = signatures
	t.ledger.chain = chain
}

func getPackageRedactionProfileLocked(ledger *Ledger, tenantID, id string) (packagedomain.RedactionProfile, error) {
	value, ok := ledger.redactions[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return packagedomain.RedactionProfile{}, packageapp.ErrNotFound
	}
	return redactionProfileToPackageContext(value), nil
}

func getCustomerSecurityPackageLocked(ledger *Ledger, tenantID, id string) (packagedomain.CustomerSecurityPackage, error) {
	value, ok := ledger.customerPackages[strings.TrimSpace(id)]
	if !ok || value.TenantID != tenantID {
		return packagedomain.CustomerSecurityPackage{}, packageapp.ErrNotFound
	}
	return customerSecurityPackageToContext(value), nil
}

func redactionProfileToPackageContext(value domain.RedactionProfile) packagedomain.RedactionProfile {
	return packagedomain.RedactionProfile{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Description: value.Description,
		AllowedTypes: append([]string(nil), value.AllowedTypes...), ExcludedFields: append([]string(nil), value.ExcludedFields...),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func redactionProfileFromPackageContext(value packagedomain.RedactionProfile) domain.RedactionProfile {
	return domain.RedactionProfile{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Description: value.Description,
		AllowedTypes: append([]string(nil), value.AllowedTypes...), ExcludedFields: append([]string(nil), value.ExcludedFields...),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func customerSecurityPackageFromContext(value packagedomain.CustomerSecurityPackage) domain.CustomerSecurityPackage {
	return domain.CustomerSecurityPackage{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID,
		RedactionProfileID: value.RedactionProfileID, Title: value.Title, State: value.State, Manifest: cloneMap(value.Manifest),
		ManifestHash: value.ManifestHash, DistributionWatermark: value.DistributionWatermark, ExpiresAt: value.ExpiresAt,
		AccessCount: value.AccessCount, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func customerSecurityPackageToContext(value domain.CustomerSecurityPackage) packagedomain.CustomerSecurityPackage {
	return packagedomain.CustomerSecurityPackage{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID,
		RedactionProfileID: value.RedactionProfileID, Title: value.Title, State: value.State, Manifest: cloneMap(value.Manifest),
		ManifestHash: value.ManifestHash, DistributionWatermark: value.DistributionWatermark, ExpiresAt: value.ExpiresAt,
		AccessCount: value.AccessCount, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func evidenceBundleFromPackageContext(value packagedomain.EvidenceBundle) domain.EvidenceBundle {
	return domain.EvidenceBundle{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID,
		EvidenceIDs: append([]string(nil), value.EvidenceIDs...), Manifest: cloneMap(value.Manifest),
		ManifestHash: value.ManifestHash, SignatureRefs: append([]string(nil), value.SignatureRefs...),
		VerificationText: value.VerificationText, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func evidenceBundleToPackageContext(value domain.EvidenceBundle) packagedomain.EvidenceBundle {
	return packagedomain.EvidenceBundle{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID,
		EvidenceIDs: append([]string(nil), value.EvidenceIDs...), Manifest: cloneMap(value.Manifest),
		ManifestHash: value.ManifestHash, SignatureRefs: append([]string(nil), value.SignatureRefs...),
		VerificationText: value.VerificationText, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func evidenceBundleImportFromPackageContext(value packagedomain.EvidenceBundleImport) domain.EvidenceBundleImport {
	return domain.EvidenceBundleImport{
		ID: value.ID, TenantID: value.TenantID, BundleHash: value.BundleHash, Result: value.Result,
		ImportedCount: value.ImportedCount, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func customReportTemplateToPackageContext(value domain.CustomReportTemplate) packagedomain.CustomReportTemplate {
	return packagedomain.CustomReportTemplate{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Version: value.Version, ReportType: value.ReportType,
		AllowedFields: append([]string(nil), value.AllowedFields...), Template: value.Template,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func customReportTemplateFromPackageContext(value packagedomain.CustomReportTemplate) domain.CustomReportTemplate {
	return domain.CustomReportTemplate{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Version: value.Version, ReportType: value.ReportType,
		AllowedFields: append([]string(nil), value.AllowedFields...), Template: value.Template,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func renderedCustomReportFromPackageContext(value packagedomain.RenderedCustomReport) domain.RenderedCustomReport {
	return domain.RenderedCustomReport{
		ID: value.ID, TenantID: value.TenantID, TemplateID: value.TemplateID, SubjectType: value.SubjectType,
		SubjectID: value.SubjectID, Output: cloneMap(value.Output), Hash: value.Hash,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func renderedCustomReportToPackageContext(value domain.RenderedCustomReport) packagedomain.RenderedCustomReport {
	return packagedomain.RenderedCustomReport{
		ID: value.ID, TenantID: value.TenantID, TemplateID: value.TemplateID, SubjectType: value.SubjectType,
		SubjectID: value.SubjectID, Output: cloneMap(value.Output), Hash: value.Hash,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func cloneCustomReportTemplateMap(values map[string]domain.CustomReportTemplate) map[string]domain.CustomReportTemplate {
	result := make(map[string]domain.CustomReportTemplate, len(values))
	for id, value := range values {
		result[id] = customReportTemplateFromPackageContext(customReportTemplateToPackageContext(value))
	}
	return result
}

func cloneRenderedCustomReportMap(values map[string]domain.RenderedCustomReport) map[string]domain.RenderedCustomReport {
	result := make(map[string]domain.RenderedCustomReport, len(values))
	for id, value := range values {
		result[id] = renderedCustomReportFromPackageContext(renderedCustomReportToPackageContext(value))
	}
	return result
}

func htmlReportPackageFromPackageContext(value packagedomain.HTMLReportPackage) domain.HTMLReportPackage {
	return domain.HTMLReportPackage{
		ID: value.ID, TenantID: value.TenantID, ReportType: value.ReportType, ProductID: value.ProductID,
		ReleaseID: value.ReleaseID, HTML: value.HTML, Hash: value.Hash,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func cloneHTMLReportPackageMap(values map[string]domain.HTMLReportPackage) map[string]domain.HTMLReportPackage {
	result := make(map[string]domain.HTMLReportPackage, len(values))
	for id, value := range values {
		result[id] = value
	}
	return result
}

func cloneEvidenceBundleMap(values map[string]domain.EvidenceBundle) map[string]domain.EvidenceBundle {
	result := make(map[string]domain.EvidenceBundle, len(values))
	for id, value := range values {
		result[id] = evidenceBundleFromPackageContext(evidenceBundleToPackageContext(value))
	}
	return result
}

func cloneEvidenceBundleImportMap(values map[string]domain.EvidenceBundleImport) map[string]domain.EvidenceBundleImport {
	result := make(map[string]domain.EvidenceBundleImport, len(values))
	for id, value := range values {
		result[id] = value
	}
	return result
}

func packageRiskChecksToContext(values []riskdomain.PolicyCheck) []packagedomain.PolicyCheckSnapshot {
	result := make([]packagedomain.PolicyCheckSnapshot, 0, len(values))
	for _, value := range values {
		result = append(result, packagedomain.PolicyCheckSnapshot{
			Name: value.Name, Result: value.Result, Severity: value.Severity, Missing: append([]string(nil), value.Missing...),
			Explanation: value.Explanation, Remediation: value.Remediation,
		})
	}
	return result
}

func packageBlockingFindingsToContext(values []domain.BlockingFinding) []packagedomain.BlockingFinding {
	result := make([]packagedomain.BlockingFinding, 0, len(values))
	for _, value := range values {
		result = append(result, packagedomain.BlockingFinding{
			FindingID: value.FindingID, ScanID: value.ScanID, ReleaseID: value.ReleaseID,
			Vulnerability: value.Vulnerability, Component: value.Component, Severity: value.Severity, State: value.State,
		})
	}
	return result
}

func packageExceptionsToContext(values []domain.Exception) []packagedomain.AcceptedExceptionSnapshot {
	result := make([]packagedomain.AcceptedExceptionSnapshot, 0, len(values))
	for _, value := range values {
		result = append(result, packagedomain.AcceptedExceptionSnapshot{
			ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, FindingID: value.FindingID, ControlID: value.ControlID,
			Reason: value.Reason, Owner: value.Owner, ExpiresAt: value.ExpiresAt, Approved: value.Approved,
			ApprovedBy: value.ApprovedBy, ApprovedAt: cloneTimePtr(value.ApprovedAt), CreatedAt: value.CreatedAt,
		})
	}
	return result
}

func releaseReadinessReportFromPackageContext(value packagedomain.ReleaseReadinessReport) domain.ReleaseReadinessReport {
	return domain.ReleaseReadinessReport{
		ReportType: value.ReportType, TemplateVersion: value.TemplateVersion, ReleaseID: value.ReleaseID,
		Result: value.Result, PolicySet: value.PolicySet,
		Summary: domain.ReadinessSummary{
			Headline: value.Summary.Headline, Result: value.Summary.Result,
			HumanSummary: value.Summary.HumanSummary, PolicySet: value.Summary.PolicySet,
		},
		Checks: packagePolicyChecksToLegacy(value.Checks), Sections: packageReadinessSectionsToLegacy(value.Sections),
		BlockingFindings:   packageBlockingFindingsToLegacy(value.BlockingFindings),
		AcceptedExceptions: packageExceptionsToLegacy(value.AcceptedExceptions),
		Gaps:               append([]string(nil), value.Gaps...), MissingEvidence: append([]string(nil), value.MissingEvidence...),
		FailedPolicies: append([]string(nil), value.FailedPolicies...), KnownLimitations: append([]string(nil), value.KnownLimitations...),
		NonClaims: append([]string(nil), value.NonClaims...), Assumptions: append([]string(nil), value.Assumptions...),
		Limitations: append([]string(nil), value.Limitations...), Metadata: cloneMap(value.Metadata), GeneratedAt: value.GeneratedAt,
	}
}

func packagePolicyChecksToLegacy(values []packagedomain.PolicyCheckSnapshot) []domain.PolicyCheck {
	result := make([]domain.PolicyCheck, 0, len(values))
	for _, value := range values {
		result = append(result, domain.PolicyCheck{
			Name: value.Name, Result: value.Result, Severity: value.Severity, Missing: append([]string(nil), value.Missing...),
			Explanation: value.Explanation, Remediation: value.Remediation,
		})
	}
	return result
}

func packageReadinessSectionsToLegacy(values []packagedomain.ReadinessSection) []domain.ReadinessSection {
	result := make([]domain.ReadinessSection, 0, len(values))
	for _, value := range values {
		questions := make([]domain.ReadinessQuestion, 0, len(value.Questions))
		for _, question := range value.Questions {
			questions = append(questions, domain.ReadinessQuestion{
				ID: question.ID, Question: question.Question, Answer: question.Answer, Status: question.Status,
				Evidence: append([]string(nil), question.Evidence...), Checks: append([]string(nil), question.Checks...),
				MissingEvidence: append([]string(nil), question.MissingEvidence...), FailedPolicies: append([]string(nil), question.FailedPolicies...),
				KnownLimitations: append([]string(nil), question.KnownLimitations...),
			})
		}
		result = append(result, domain.ReadinessSection{ID: value.ID, Title: value.Title, Status: value.Status, Summary: value.Summary, Questions: questions})
	}
	return result
}

func packageBlockingFindingsToLegacy(values []packagedomain.BlockingFinding) []domain.BlockingFinding {
	result := make([]domain.BlockingFinding, 0, len(values))
	for _, value := range values {
		result = append(result, domain.BlockingFinding{
			FindingID: value.FindingID, ScanID: value.ScanID, ReleaseID: value.ReleaseID,
			Vulnerability: value.Vulnerability, Component: value.Component, Severity: value.Severity, State: value.State,
		})
	}
	return result
}

func packageExceptionsToLegacy(values []packagedomain.AcceptedExceptionSnapshot) []domain.Exception {
	result := make([]domain.Exception, 0, len(values))
	for _, value := range values {
		result = append(result, domain.Exception{
			ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, FindingID: value.FindingID, ControlID: value.ControlID,
			Reason: value.Reason, Owner: value.Owner, ExpiresAt: value.ExpiresAt, Approved: value.Approved,
			ApprovedBy: value.ApprovedBy, ApprovedAt: cloneTimePtr(value.ApprovedAt), CreatedAt: value.CreatedAt,
		})
	}
	return result
}

func clonePackageRedactionMap(values map[string]domain.RedactionProfile) map[string]domain.RedactionProfile {
	result := make(map[string]domain.RedactionProfile, len(values))
	for key, value := range values {
		value.AllowedTypes = append([]string(nil), value.AllowedTypes...)
		value.ExcludedFields = append([]string(nil), value.ExcludedFields...)
		result[key] = value
	}
	return result
}

func cloneCustomerPackageMap(values map[string]domain.CustomerSecurityPackage) map[string]domain.CustomerSecurityPackage {
	result := make(map[string]domain.CustomerSecurityPackage, len(values))
	for key, value := range values {
		value.Manifest = cloneMap(value.Manifest)
		result[key] = value
	}
	return result
}

func cloneReleaseBundleMap(values map[string]domain.ReleaseBundle) map[string]domain.ReleaseBundle {
	result := make(map[string]domain.ReleaseBundle, len(values))
	for key, value := range values {
		value.Manifest = cloneMap(value.Manifest)
		value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
		value.PublishedAt = cloneTimePtr(value.PublishedAt)
		value.RevokedAt = cloneTimePtr(value.RevokedAt)
		result[key] = value
	}
	return result
}

func cloneSignatureMap(values map[string]domain.Signature) map[string]domain.Signature {
	result := make(map[string]domain.Signature, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func toPackageContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrValidation):
		return packageapp.ErrValidation
	case errors.Is(err, ErrForbidden):
		return packageapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return packageapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return packageapp.ErrConflict
	default:
		return err
	}
}

func fromPackageContextError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, packageapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, packageapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, packageapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, packageapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}
