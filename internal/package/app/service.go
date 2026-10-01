// Package app owns customer-package and report-generation orchestration.
package app

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	ScopePackageWrite                = "package:write"
	ScopePackageRead                 = "package:read"
	ScopeReadinessRead               = "verify:read"
	ScopeReportRead                  = "report:read"
	ReportTemplateRequestLimit int64 = 1 << 20
	MaxGeneratedReportBytes          = 4 << 20

	CustomerDecisionExportFile    = "vulnerability-decisions.json"
	CustomerDecisionExportVersion = "customer-vulnerability-decisions.v1.0.0"
)

var (
	ErrValidation = errors.New("validation failed")
	ErrForbidden  = application.ErrForbidden
	ErrNotFound   = errors.New("not found")
	ErrConflict   = errors.New("conflict")
)

// EvidenceReference is the immutable package-selection view of evidence.
type EvidenceReference struct {
	ID   string
	Type string
}

// PackageSnapshot is one committed, tenant-scoped read view. Adapters must
// populate the complete value from a single database snapshot or a read model
// that publishes only after commit. The application service never reaches
// back into another context while assembling a manifest.
type PackageSnapshot struct {
	SnapshotVersion      string
	TenantID             string
	ProductID            string
	ReleaseID            string
	Tenant               map[string]any
	Organization         map[string]any
	Product              map[string]any
	Release              map[string]any
	Evidence             []EvidenceReference
	Artifacts            []map[string]any
	ReadinessChecks      []packagedomain.PolicyCheckSnapshot
	VerificationMaterial map[string]any
	SBOMs                []map[string]any
	VulnerabilityScans   []map[string]any
	VEXDocuments         []map[string]any
	APIContracts         map[string]any
	Decisions            []map[string]any
	Approvals            []map[string]any
	Exceptions           []map[string]any
	Waivers              []map[string]any
	AnswerLibrary        []map[string]any
	ObjectLockProofs     []map[string]any
	Provenance           map[string]any
}

type Reader interface {
	GetRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
	GetCustomerSecurityPackage(context.Context, string, string) (packagedomain.CustomerSecurityPackage, error)
	GetCustomReportTemplate(context.Context, string, string) (packagedomain.CustomReportTemplate, error)
	ReadCommittedPackageSnapshot(context.Context, string, string, string) (PackageSnapshot, error)
	ReadCommittedReleaseBundleSnapshot(context.Context, string, string) (ReleaseBundleSnapshot, error)
	ReadCommittedEvidenceBundleSnapshot(context.Context, string, string) (EvidenceBundleSnapshot, error)
	ReadCommittedReadinessReportSnapshot(context.Context, string, string) (ReadinessReportSnapshot, error)
	ReadCommittedCRAReadinessHTMLSnapshot(context.Context, string, string, string) (CRAReadinessHTMLSnapshot, error)
}

type Repository interface {
	GetRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
	InsertRedactionProfile(context.Context, packagedomain.RedactionProfile) error
	InsertReleaseBundle(context.Context, packagedomain.ReleaseBundle) error
	InsertEvidenceBundle(context.Context, packagedomain.EvidenceBundle) error
	InsertEvidenceBundleImport(context.Context, packagedomain.EvidenceBundleImport) error
	InsertCustomReportTemplate(context.Context, packagedomain.CustomReportTemplate) error
	InsertRenderedCustomReport(context.Context, packagedomain.RenderedCustomReport) error
	InsertHTMLReportPackage(context.Context, packagedomain.HTMLReportPackage) error
	InsertCustomerSecurityPackage(context.Context, packagedomain.CustomerSecurityPackage) error
	GetCustomerSecurityPackageForUpdate(context.Context, string, string) (packagedomain.CustomerSecurityPackage, error)
	UpdateCustomerSecurityPackageAccess(context.Context, packagedomain.CustomerSecurityPackage, packagedomain.CustomerSecurityPackage) error
}

type Transaction interface {
	Packages() Repository
	Signatures() PackageSignatureRepository
	Authorization() application.Authorizer
	Audit() application.AuditAppender
	Outbox() application.OutboxEnqueuer
}

type TransactionCommand func(context.Context, Transaction) error

type TransactionRunner interface {
	Execute(context.Context, TransactionCommand) error
}

type ManifestCanonicalizer interface {
	HashPackageManifest(context.Context, map[string]any) (string, error)
	HashPackageBytes(context.Context, []byte) (string, error)
}

type ProjectionRefresher interface {
	RefreshPackageProjection(context.Context, string) error
}

type Config struct {
	Reader              Reader
	Transactions        TransactionRunner
	Authorizer          application.Authorizer
	Canonicalizer       ManifestCanonicalizer
	Signer              PackageSigner
	ProjectionRefresher ProjectionRefresher
	Clock               application.Clock
	IDs                 application.IDGenerator
}

type Service struct {
	reader              Reader
	transactions        TransactionRunner
	authorizer          application.Authorizer
	canonicalizer       ManifestCanonicalizer
	signer              PackageSigner
	projectionRefresher ProjectionRefresher
	clock               application.Clock
	ids                 application.IDGenerator
}

func NewService(config Config) (*Service, error) {
	if config.Reader == nil || config.Transactions == nil || config.Authorizer == nil || config.Canonicalizer == nil || config.Signer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &Service{
		reader: config.Reader, transactions: config.Transactions, authorizer: config.Authorizer,
		canonicalizer: config.Canonicalizer, signer: config.Signer, projectionRefresher: config.ProjectionRefresher,
		clock: config.Clock, ids: config.IDs,
	}, nil
}

type CreateRedactionProfileInput struct {
	Name           string
	Description    string
	Preset         string
	AllowedTypes   []string
	ExcludedFields []string
}

type redactionProfilePreset struct {
	name           string
	description    string
	allowedTypes   []string
	excludedFields []string
}

var redactionProfilePresets = map[string]redactionProfilePreset{
	"customer_safe": {
		name: "customer_safe", description: "Customer-safe package profile for release evidence summaries without raw payloads, secrets, internal notes, or internal-only provenance fields.",
		allowedTypes:   []string{"artifact", "answer_library", "sbom", "vulnerability_scan", "vex", "vulnerability_decision", "release_bundle", "approval", "exception", "object_lock_proof", "waiver"},
		excludedFields: []string{"action_internal_url", "environment_hash", "internal_notes", "internal_url", "object_key", "oidc_subject", "parameters_hash", "payload", "payload_bytes", "payload_ref", "private_key", "repository", "secret", "source_identity", "token", "workflow_ref"},
	},
	"security_review": {
		name: "security_review", description: "Security-review package profile for broader technical evidence review while still excluding raw payloads, secrets, token material, and private keys.",
		allowedTypes:   []string{"api_security", "approval", "answer_library", "artifact", "build", "build_attestation", "dast", "exception", "license_scan", "manual_security_document", "object_lock_proof", "openapi_contract", "pen_test_report", "release_bundle", "sast", "sbom", "secret_scan", "security_review", "threat_model", "vex", "vulnerability_decision", "vulnerability_scan", "waiver"},
		excludedFields: []string{"internal_notes", "object_key", "payload", "payload_bytes", "payload_ref", "private_key", "secret", "token"},
	},
}

func (s *Service) CreateRedactionProfile(ctx context.Context, actor identitydomain.Actor, input CreateRedactionProfileInput) (packagedomain.RedactionProfile, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	if err := s.authorize(ctx, actor, ScopePackageWrite, application.ResourceReferences{}, true); err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	normalized, err := normalizeRedactionProfileInput(input)
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	now := s.clock.Now().UTC()
	profile := packagedomain.RedactionProfile{
		ID: s.ids.NewID("rp"), TenantID: actor.TenantID, Name: normalized.Name, Description: normalized.Description,
		AllowedTypes: normalized.AllowedTypes, ExcludedFields: normalized.ExcludedFields,
		SchemaVersion: packagedomain.RedactionProfileSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Packages().InsertRedactionProfile(ctx, profile); err != nil {
			return err
		}
		_, err := tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "redaction_profile.created", "redaction_profile", profile.ID, ""))
		return err
	})
	if err != nil {
		return packagedomain.RedactionProfile{}, err
	}
	return cloneRedactionProfile(profile), nil
}

type CreateCustomerPackageInput struct {
	ProductID          string
	ReleaseID          string
	RedactionProfileID string
	Title              string
	ExpiresAt          time.Time
}

func (s *Service) CreateCustomerSecurityPackage(ctx context.Context, actor identitydomain.Actor, input CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	if err := s.authorize(ctx, actor, ScopePackageWrite, application.ResourceReferences{}, true); err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	input.ProductID = strings.TrimSpace(input.ProductID)
	input.ReleaseID = strings.TrimSpace(input.ReleaseID)
	input.RedactionProfileID = strings.TrimSpace(input.RedactionProfileID)
	input.Title = strings.TrimSpace(input.Title)
	now := s.clock.Now().UTC()
	if input.ProductID == "" || input.RedactionProfileID == "" || input.Title == "" || !input.ExpiresAt.After(now) {
		return packagedomain.CustomerSecurityPackage{}, ErrValidation
	}
	if s.projectionRefresher != nil {
		if err := s.projectionRefresher.RefreshPackageProjection(ctx, actor.TenantID); err != nil {
			return packagedomain.CustomerSecurityPackage{}, err
		}
	}
	profile, err := s.reader.GetRedactionProfile(ctx, actor.TenantID, input.RedactionProfileID)
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	if !validRedactionProfile(profile, actor.TenantID, input.RedactionProfileID) {
		return packagedomain.CustomerSecurityPackage{}, ErrNotFound
	}
	resources := application.ResourceReferences{ProductID: input.ProductID, ReleaseID: input.ReleaseID}
	if err := s.authorize(ctx, actor, ScopePackageWrite, resources, false); err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	snapshot, err := s.reader.ReadCommittedPackageSnapshot(ctx, actor.TenantID, input.ProductID, input.ReleaseID)
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	if !validPackageSnapshot(snapshot, actor.TenantID, input.ProductID, input.ReleaseID) {
		return packagedomain.CustomerSecurityPackage{}, ErrConflict
	}

	packageID := s.ids.NewID("csp")
	manifest := buildCustomerPackageManifest(packageID, now, input.Title, profile, snapshot)
	manifest = sanitizeManifestMap(manifest, profile.ExcludedFields)
	hash, err := s.canonicalizer.HashPackageManifest(ctx, manifest)
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	if strings.TrimSpace(hash) == "" {
		return packagedomain.CustomerSecurityPackage{}, ErrValidation
	}
	pkg := packagedomain.CustomerSecurityPackage{
		ID: packageID, TenantID: actor.TenantID, ProductID: input.ProductID, ReleaseID: input.ReleaseID,
		RedactionProfileID: profile.ID, Title: input.Title, State: "generated", Manifest: manifest, ManifestHash: hash,
		ExpiresAt: input.ExpiresAt.UTC(), SchemaVersion: packagedomain.CustomerPackageSchemaVersion, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		current, err := tx.Packages().GetRedactionProfile(ctx, actor.TenantID, profile.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(current, profile) {
			return ErrConflict
		}
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: resources}); err != nil {
			return err
		}
		if err := tx.Packages().InsertCustomerSecurityPackage(ctx, pkg); err != nil {
			return err
		}
		_, err = tx.Audit().AppendAudit(ctx, s.auditEvent(actor, now, "customer_package.generated", "customer_security_package", pkg.ID, hash))
		return err
	})
	if err != nil {
		return packagedomain.CustomerSecurityPackage{}, err
	}
	return cloneCustomerSecurityPackage(pkg), nil
}

func (s *Service) AccessCustomerSecurityPackage(ctx context.Context, actor identitydomain.Actor, id string) (packagedomain.CustomerSecurityPackage, error) {
	return s.accessCommands().AccessCustomerSecurityPackage(ctx, actor, id)
}

func normalizeRedactionProfileInput(input CreateRedactionProfileInput) (CreateRedactionProfileInput, error) {
	input.Preset = strings.TrimSpace(input.Preset)
	if input.Preset != "" {
		preset, ok := redactionProfilePresets[input.Preset]
		if !ok || len(input.AllowedTypes) > 0 || len(input.ExcludedFields) > 0 {
			return CreateRedactionProfileInput{}, ErrValidation
		}
		input.Name, input.Description = preset.name, preset.description
		input.AllowedTypes = append([]string(nil), preset.allowedTypes...)
		input.ExcludedFields = append([]string(nil), preset.excludedFields...)
	}
	input.Name = strings.TrimSpace(input.Name)
	input.Description = strings.TrimSpace(input.Description)
	if input.Name == "" {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	var err error
	input.AllowedTypes, err = normalizedNonEmptyStrings(input.AllowedTypes, true)
	if err != nil || len(input.AllowedTypes) == 0 {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	input.ExcludedFields, err = normalizedNonEmptyStrings(input.ExcludedFields, false)
	if err != nil {
		return CreateRedactionProfileInput{}, ErrValidation
	}
	return input, nil
}

func buildCustomerPackageManifest(packageID string, generatedAt time.Time, title string, profile packagedomain.RedactionProfile, snapshot PackageSnapshot) map[string]any {
	evidenceIDs := make([]string, 0)
	for _, evidence := range snapshot.Evidence {
		if profileAllowsType(profile, evidence.Type) && strings.TrimSpace(evidence.ID) != "" {
			evidenceIDs = append(evidenceIDs, strings.TrimSpace(evidence.ID))
		}
	}
	evidenceIDs, _ = normalizedNonEmptyStrings(evidenceIDs, false)
	result := "not_applicable"
	gaps := []string{}
	if snapshot.ReleaseID != "" {
		result = "passed"
		for _, check := range snapshot.ReadinessChecks {
			gaps = append(gaps, check.Missing...)
			if check.Result == "failed" {
				result = "failed"
			}
		}
		gaps, _ = normalizedNonEmptyStrings(gaps, false)
	}
	manifest := map[string]any{
		"schema_version": packagedomain.CustomerPackageSchemaVersion, "package_version": packagedomain.CustomerPackageSchemaVersion,
		"snapshot_version": snapshot.SnapshotVersion, "package_id": packageID, "id": packageID, "title": title,
		"generated_at": generatedAt.UTC().Format(time.RFC3339Nano), "tenant": snapshot.Tenant, "organization": snapshot.Organization,
		"product": snapshot.Product, "product_id": snapshot.ProductID, "release": snapshot.Release, "release_id": snapshot.ReleaseID,
		"redaction_profile_id": profile.ID, "redaction_profile": redactionProfileMetadata(profile),
		"evidence_ids": evidenceIDs, "artifact_digests": snapshot.Artifacts,
		"readiness_summary": readinessSummary(result, snapshot.ReadinessChecks, gaps), "verification_material": snapshot.VerificationMaterial,
		"limitations": []string{
			"Package contents are scoped by product, release, redaction profile, and package expiry.",
			"Raw tenant evidence payload bytes, object-store payload references, bearer tokens, private keys, API key hashes, SSO/session token hashes, and internal decision notes are not included.",
			"Package data reflects one committed snapshot from this Evydence instance at generation time.",
		},
		"non_claims": []string{
			"This package supports technical evidence review and compliance readiness only.",
			"It is not legal compliance proof, certification, complete SBOM proof, an authoritative vulnerability result, regulator acceptance, or a secure-release guarantee.",
		},
	}
	if visible := customerSafeGaps(snapshot.ReadinessChecks, profile); len(visible) > 0 {
		manifest["customer_safe_gaps"] = visible
	}
	if profileAllowsType(profile, "sbom") {
		manifest["sboms"] = snapshot.SBOMs
	}
	if profileAllowsType(profile, "vulnerability_scan") {
		manifest["vulnerability_scans"] = snapshot.VulnerabilityScans
	}
	if profileAllowsType(profile, "vex") {
		manifest["vex_documents"] = snapshot.VEXDocuments
	}
	if profileAllowsType(profile, "openapi_contract") {
		manifest["api_contracts"] = snapshot.APIContracts
	}
	if profileAllowsType(profile, "vulnerability_decision") && len(snapshot.Decisions) > 0 {
		manifest["vulnerability_decisions"] = snapshot.Decisions
		manifest["customer_decision_export"] = map[string]any{"file": CustomerDecisionExportFile, "schema_version": CustomerDecisionExportVersion, "decision_count": len(snapshot.Decisions), "scope": "package"}
	}
	if profileAllowsType(profile, "approval") {
		manifest["approvals"] = snapshot.Approvals
	}
	if profileAllowsType(profile, "exception") {
		manifest["exceptions"] = snapshot.Exceptions
	}
	if profileAllowsType(profile, "waiver") {
		manifest["waivers"] = snapshot.Waivers
	}
	if profileAllowsType(profile, "answer_library") {
		manifest["answer_library"] = snapshot.AnswerLibrary
	}
	if profileAllowsType(profile, "object_lock_proof") {
		manifest["object_lock_proofs"] = snapshot.ObjectLockProofs
	}
	if profileAllowsType(profile, "build") || profileAllowsType(profile, "build_attestation") {
		manifest["provenance"] = snapshot.Provenance
	}
	return manifest
}

func readinessSummary(result string, checks []packagedomain.PolicyCheckSnapshot, gaps []string) map[string]any {
	values := make([]map[string]any, 0, len(checks))
	for _, check := range checks {
		values = append(values, map[string]any{
			"name": check.Name, "result": check.Result, "severity": check.Severity,
			"missing": append([]string(nil), check.Missing...), "explanation": check.Explanation, "remediation": check.Remediation,
		})
	}
	return map[string]any{
		"result": result, "checks": values, "gaps": append([]string(nil), gaps...),
		"limitations": []string{"Readiness is derived from recorded package-scope evidence only.", "Readiness output is not a compliance, certification, or secure-release conclusion."},
	}
}

func customerSafeGaps(checks []packagedomain.PolicyCheckSnapshot, profile packagedomain.RedactionProfile) []map[string]any {
	result := []map[string]any{}
	for _, check := range checks {
		if check.Result == "passed" {
			continue
		}
		for _, missing := range check.Missing {
			if !gapVisibleForProfile(missing, profile) {
				continue
			}
			result = append(result, map[string]any{
				"id": "gap_" + check.Name + "_" + missing, "category": "missing_evidence", "evidence_type": missing,
				"source_check": check.Name, "severity": check.Severity, "summary": check.Explanation,
				"remediation": check.Remediation, "customer_visible": true,
				"limitations": []string{"Gap is based only on evidence metadata included by this package redaction profile."},
			})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["id"].(string) < result[j]["id"].(string) })
	return result
}

func gapVisibleForProfile(missing string, profile packagedomain.RedactionProfile) bool {
	switch strings.TrimSpace(missing) {
	case "artifact", "artifact_digest":
		return profileAllowsType(profile, "artifact")
	case "sbom":
		return profileAllowsType(profile, "sbom")
	case "vulnerability_scan":
		return profileAllowsType(profile, "vulnerability_scan")
	case "vulnerability_decision":
		return profileAllowsType(profile, "vulnerability_decision")
	case "signed_release_bundle":
		return profileAllowsType(profile, "release_bundle")
	case "passed_build":
		return profileAllowsType(profile, "build")
	case "build_attestation":
		return profileAllowsType(profile, "build_attestation")
	default:
		return false
	}
}

var hardExcludedPackageFields = map[string]bool{
	"api_key": true, "api_key_hash": true, "authorization": true, "bearer_token": true, "client_secret": true,
	"credential": true, "environment": true, "internal_notes": true, "object_key": true, "oidc_subject": true,
	"password": true, "payload": true, "payload_bytes": true, "payload_ref": true, "private": true, "private_key": true,
	"secret": true, "session_hash": true, "session_token": true, "source_identity": true, "token": true, "webhook_secret": true,
}

func sanitizeManifestMap(value map[string]any, excludedFields []string) map[string]any {
	excluded := make(map[string]bool, len(excludedFields)+len(hardExcludedPackageFields))
	for key := range hardExcludedPackageFields {
		excluded[key] = true
	}
	for _, key := range excludedFields {
		excluded[strings.ToLower(strings.TrimSpace(key))] = true
	}
	result, _ := sanitizeManifestValue(value, excluded).(map[string]any)
	return result
}

func sanitizeManifestValue(value any, excluded map[string]bool) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, child := range typed {
			if excluded[strings.ToLower(strings.TrimSpace(key))] {
				continue
			}
			result[key] = sanitizeManifestValue(child, excluded)
		}
		return result
	case []map[string]any:
		result := make([]map[string]any, 0, len(typed))
		for _, child := range typed {
			result = append(result, sanitizeManifestValue(child, excluded).(map[string]any))
		}
		return result
	case []any:
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			result = append(result, sanitizeManifestValue(child, excluded))
		}
		return result
	case []string:
		return append([]string(nil), typed...)
	case map[string]int:
		result := make(map[string]int, len(typed))
		for key, child := range typed {
			result[key] = child
		}
		return result
	default:
		return typed
	}
}

func validPackageSnapshot(snapshot PackageSnapshot, tenantID, productID, releaseID string) bool {
	if strings.TrimSpace(snapshot.SnapshotVersion) == "" || snapshot.TenantID != tenantID || snapshot.ProductID != productID || snapshot.ReleaseID != releaseID {
		return false
	}
	if id, _ := snapshot.Product["id"].(string); id != productID {
		return false
	}
	if releaseID != "" {
		if id, _ := snapshot.Release["id"].(string); id != releaseID {
			return false
		}
	}
	return true
}

func validRedactionProfile(profile packagedomain.RedactionProfile, tenantID, id string) bool {
	return profile.ID == id && profile.TenantID == tenantID && profile.Name != "" && len(profile.AllowedTypes) > 0 && profile.SchemaVersion != ""
}

func validCustomerSecurityPackage(value packagedomain.CustomerSecurityPackage, tenantID, id string) bool {
	return value.ID == id && value.TenantID == tenantID && value.ProductID != "" && value.State != "" && value.SchemaVersion != ""
}

func profileAllowsType(profile packagedomain.RedactionProfile, value string) bool {
	for _, allowed := range profile.AllowedTypes {
		if strings.TrimSpace(allowed) == value {
			return true
		}
	}
	return false
}

func redactionProfileMetadata(profile packagedomain.RedactionProfile) map[string]any {
	return map[string]any{
		"id": profile.ID, "name": profile.Name, "description": profile.Description,
		"allowed_types": append([]string(nil), profile.AllowedTypes...), "excluded_fields": append([]string(nil), profile.ExcludedFields...),
		"schema_version": profile.SchemaVersion,
	}
}

func normalizedNonEmptyStrings(values []string, rejectEmpty bool) ([]string, error) {
	set := map[string]struct{}{}
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			if rejectEmpty {
				return nil, ErrValidation
			}
			continue
		}
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func (s *Service) authorize(ctx context.Context, actor identitydomain.Actor, scope string, resources application.ResourceReferences, scopeOnly bool) error {
	return s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scope, Resources: resources, ScopeOnly: scopeOnly})
}

func (s *Service) auditEvent(actor identitydomain.Actor, at time.Time, entryType, subjectType, subjectID, payloadHash string) application.AuditEvent {
	return application.AuditEvent{
		ID: s.ids.NewID("ace"), TenantID: actor.TenantID, EntryType: entryType, SubjectType: subjectType, SubjectID: subjectID,
		ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: at.UTC(), PayloadHash: payloadHash,
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

func cloneRedactionProfile(value packagedomain.RedactionProfile) packagedomain.RedactionProfile {
	value.AllowedTypes = append([]string(nil), value.AllowedTypes...)
	value.ExcludedFields = append([]string(nil), value.ExcludedFields...)
	return value
}

func cloneCustomerSecurityPackage(value packagedomain.CustomerSecurityPackage) packagedomain.CustomerSecurityPackage {
	value.Manifest = sanitizeManifestMap(value.Manifest, nil)
	return value
}

func clonePackageSnapshot(value PackageSnapshot) PackageSnapshot {
	value.Tenant = cloneMap(value.Tenant)
	value.Organization = cloneMap(value.Organization)
	value.Product = cloneMap(value.Product)
	value.Release = cloneMap(value.Release)
	value.Evidence = append([]EvidenceReference(nil), value.Evidence...)
	value.Artifacts = cloneMapSlice(value.Artifacts)
	value.ReadinessChecks = append([]packagedomain.PolicyCheckSnapshot(nil), value.ReadinessChecks...)
	for index := range value.ReadinessChecks {
		value.ReadinessChecks[index].Missing = append([]string(nil), value.ReadinessChecks[index].Missing...)
	}
	value.VerificationMaterial = cloneMap(value.VerificationMaterial)
	value.SBOMs = cloneMapSlice(value.SBOMs)
	value.VulnerabilityScans = cloneMapSlice(value.VulnerabilityScans)
	value.VEXDocuments = cloneMapSlice(value.VEXDocuments)
	value.APIContracts = cloneMap(value.APIContracts)
	value.Decisions = cloneMapSlice(value.Decisions)
	value.Approvals = cloneMapSlice(value.Approvals)
	value.Exceptions = cloneMapSlice(value.Exceptions)
	value.Waivers = cloneMapSlice(value.Waivers)
	value.AnswerLibrary = cloneMapSlice(value.AnswerLibrary)
	value.ObjectLockProofs = cloneMapSlice(value.ObjectLockProofs)
	value.Provenance = cloneMap(value.Provenance)
	return value
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	result, _ := sanitizeManifestValue(value, map[string]bool{}).(map[string]any)
	return result
}

func cloneMapSlice(values []map[string]any) []map[string]any {
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, cloneMap(value))
	}
	return result
}
