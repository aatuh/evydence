package app

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

const (
	collectorTypeGitHubActions = "github_actions"
	collectorTypeGitLabCI      = "gitlab_ci"
	collectorTypeGenericCI     = "generic_ci"
	collectorTypeImportBundle  = "import_bundle"
	collectorStatusActive      = "active"

	buildStatusPassed = "passed"
)

type CreateCollectorInput struct {
	Name    string
	Type    string
	Version string
	Scopes  []string
}

type CreateBuildRunInput struct {
	ProjectID        string
	ReleaseID        string
	Provider         string
	CommitSHA        string
	Repository       string
	WorkflowRef      string
	RunID            string
	RunAttempt       int
	JobID            string
	GitHubActor      string
	Ref              string
	OIDCSubject      string
	Status           string
	StartedAt        time.Time
	FinishedAt       *time.Time
	ParametersHash   string
	EnvironmentHash  string
	ProviderMetadata map[string]any
	Outputs          []domain.BuildOutput
}

type RecordCollectorReleaseInput struct {
	CollectorID    string
	Version        string
	ArtifactDigest string
	SignatureID    string
	SBOMID         string
	ScanID         string
	Pinned         bool
}

func (l *Ledger) CreateCollector(ctx context.Context, actor domain.Actor, in CreateCollectorInput) (domain.Collector, domain.APIKey, string, error) {
	if err := ctx.Err(); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Type = strings.TrimSpace(in.Type)
	in.Version = strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" || !validCollectorType(in.Type) {
		return domain.Collector{}, domain.APIKey{}, "", ErrValidation
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = []string{ScopeBuildWrite, ScopeEvidenceWrite}
	}
	if !validCollectorScopes(scopes) {
		return domain.Collector{}, domain.APIKey{}, "", ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.collectors {
		if existing.TenantID == actor.TenantID && existing.Name == in.Name {
			return domain.Collector{}, domain.APIKey{}, "", ErrConflict
		}
	}
	var key domain.APIKey
	var secret string
	if l.unitOfWork != nil {
		key, secret = l.newAPIKey(actor.TenantID, "collector:"+in.Name, scopes, nil)
	} else {
		var err error
		key, secret, err = l.createAPIKeyLocked(actor.TenantID, "collector:"+in.Name, scopes, nil)
		if err != nil {
			return domain.Collector{}, domain.APIKey{}, "", err
		}
	}
	collector := domain.Collector{
		ID:            newID("col"),
		TenantID:      actor.TenantID,
		Name:          in.Name,
		Type:          in.Type,
		Version:       in.Version,
		APIKeyID:      key.ID,
		Status:        collectorStatusActive,
		AllowedScopes: sortedStrings(scopes),
		SchemaVersion: domain.CollectorSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Identity.InsertAPIKey(ctx, key); err != nil {
				return err
			}
			if err := repos.Builds.InsertCollector(ctx, collector); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(collector.CreatedAt, actor.TenantID, "collector.created", "collector", collector.ID, "api_key", actor.KeyID, "", ""))
			return err
		}); err != nil {
			return domain.Collector{}, domain.APIKey{}, "", err
		}
		l.apiKeys[key.ID] = key
		l.collectors[collector.ID] = collector
		l.publishCommittedAuditEntryLocked(entry)
		public := key
		public.Hash = ""
		return collector, public, secret, nil
	}
	l.collectors[collector.ID] = collector
	_, _ = l.appendChainLocked(actor.TenantID, "collector.created", "collector", collector.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
	key.Hash = ""
	return collector, key, secret, nil
}

func (l *Ledger) ListCollectors(ctx context.Context, actor domain.Actor) ([]domain.Collector, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeCollectorRead, resourceRefs{}); err != nil {
		return nil, err
	}
	out := []domain.Collector{}
	for _, collector := range l.collectors {
		if collector.TenantID == actor.TenantID {
			out = append(out, collector)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (l *Ledger) RecordCollectorRelease(ctx context.Context, actor domain.Actor, in RecordCollectorReleaseInput) (domain.CollectorRelease, error) {
	if err := ctx.Err(); err != nil {
		return domain.CollectorRelease{}, err
	}
	if err := require(actor, ScopeCollectorAdmin); err != nil {
		return domain.CollectorRelease{}, err
	}
	in.CollectorID = strings.TrimSpace(in.CollectorID)
	in.Version = strings.TrimSpace(in.Version)
	in.ArtifactDigest = strings.TrimSpace(in.ArtifactDigest)
	if in.CollectorID == "" || in.Version == "" || !validDigest(in.ArtifactDigest) {
		return domain.CollectorRelease{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	collector, ok := l.collectors[in.CollectorID]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.CollectorRelease{}, ErrNotFound
	}
	if in.SignatureID != "" {
		sig, ok := l.artifactSigs[strings.TrimSpace(in.SignatureID)]
		if !ok || sig.TenantID != actor.TenantID || sig.SubjectDigest != in.ArtifactDigest {
			return domain.CollectorRelease{}, ErrNotFound
		}
	}
	if in.SBOMID != "" {
		sbom, ok := l.sboms[strings.TrimSpace(in.SBOMID)]
		if !ok || sbom.TenantID != actor.TenantID {
			return domain.CollectorRelease{}, ErrNotFound
		}
	}
	if in.ScanID != "" {
		scan, ok := l.scans[strings.TrimSpace(in.ScanID)]
		if !ok || scan.TenantID != actor.TenantID {
			return domain.CollectorRelease{}, ErrNotFound
		}
	}
	status := "recorded"
	health := "needs_evidence"
	if in.SignatureID != "" && in.SBOMID != "" && in.ScanID != "" {
		status = "evidence_complete"
		health = "healthy"
	}
	release := domain.CollectorRelease{
		ID:                 newID("colrel"),
		TenantID:           actor.TenantID,
		CollectorID:        collector.ID,
		Version:            in.Version,
		ArtifactDigest:     in.ArtifactDigest,
		SignatureID:        strings.TrimSpace(in.SignatureID),
		SBOMID:             strings.TrimSpace(in.SBOMID),
		ScanID:             strings.TrimSpace(in.ScanID),
		Pinned:             in.Pinned,
		VerificationStatus: status,
		HealthStatus:       health,
		Limitations:        []string{"Collector supply-chain status reflects evidence recorded in Evydence and does not prove collector runtime safety."},
		SchemaVersion:      domain.CollectorReleaseSchemaVersion,
		CreatedAt:          l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Builds.InsertCollectorRelease(ctx, release); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(release.CreatedAt, actor.TenantID, "collector_release.recorded", "collector", collector.ID, actorType(actor), actorID(actor), release.ArtifactDigest, ""))
			return err
		}); err != nil {
			return domain.CollectorRelease{}, err
		}
		if release.Pinned {
			for id, existing := range l.collectorReleases {
				if existing.TenantID == actor.TenantID && existing.CollectorID == collector.ID && existing.Pinned {
					existing.Pinned = false
					l.collectorReleases[id] = existing
				}
			}
		}
		l.collectorReleases[release.ID] = release
		l.publishCommittedAuditEntryLocked(entry)
		return release, nil
	}
	if in.Pinned {
		for id, existing := range l.collectorReleases {
			if existing.TenantID == actor.TenantID && existing.CollectorID == collector.ID && existing.Pinned {
				existing.Pinned = false
				l.collectorReleases[id] = existing
			}
		}
	}
	l.collectorReleases[release.ID] = release
	_, _ = l.appendChainLocked(actor.TenantID, "collector_release.recorded", "collector", collector.ID, actorType(actor), actorID(actor), release.ArtifactDigest, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.CollectorRelease{}, err
	}
	return release, nil
}

func (l *Ledger) CollectorHealthReport(ctx context.Context, actor domain.Actor, collectorID string) (domain.CollectorHealthReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.CollectorHealthReport{}, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return domain.CollectorHealthReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeResourceLocked(actor, ScopeCollectorRead, resourceRefs{}); err != nil {
		return domain.CollectorHealthReport{}, err
	}
	collector, ok := l.collectors[strings.TrimSpace(collectorID)]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.CollectorHealthReport{}, ErrNotFound
	}
	var latest *domain.CollectorRelease
	var pinned *domain.CollectorRelease
	for _, release := range l.collectorReleases {
		if release.TenantID != actor.TenantID || release.CollectorID != collector.ID {
			continue
		}
		copy := release
		if latest == nil || release.CreatedAt.After(latest.CreatedAt) {
			latest = &copy
		}
		if release.Pinned {
			pinned = &copy
		}
	}
	checks := []domain.VerifyCheck{{Name: "collector_status", Result: "passed", Detail: collector.Status}}
	supplyStatus := "missing_release_evidence"
	if latest == nil {
		checks = append(checks, domain.VerifyCheck{Name: "collector_release", Result: "failed"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "collector_release", Result: "passed", Detail: latest.Version})
		supplyStatus = latest.HealthStatus
		if latest.SignatureID == "" {
			checks = append(checks, domain.VerifyCheck{Name: "collector_signature", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "collector_signature", Result: "passed"})
		}
		if latest.SBOMID == "" {
			checks = append(checks, domain.VerifyCheck{Name: "collector_sbom", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "collector_sbom", Result: "passed"})
		}
		if latest.ScanID == "" {
			checks = append(checks, domain.VerifyCheck{Name: "collector_scan", Result: "failed"})
		} else {
			checks = append(checks, domain.VerifyCheck{Name: "collector_scan", Result: "passed"})
		}
	}
	pinnedID := ""
	if pinned != nil {
		pinnedID = pinned.ID
		checks = append(checks, domain.VerifyCheck{Name: "collector_version_pinned", Result: "passed", Detail: pinned.Version})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "collector_version_pinned", Result: "failed"})
	}
	return domain.CollectorHealthReport{
		ReportType:        "collector_health",
		CollectorID:       collector.ID,
		CollectorStatus:   collector.Status,
		Version:           collector.Version,
		PinnedReleaseID:   pinnedID,
		SupplyChainStatus: supplyStatus,
		Checks:            checks,
		LatestRelease:     latest,
		Assumptions:       []string{"Collector health is based on metadata and evidence recorded in this tenant."},
		Limitations:       []string{"This report does not prove collector runtime integrity or absence of vulnerabilities."},
		GeneratedAt:       l.now(),
	}, nil
}

func (l *Ledger) CreateBuildRun(ctx context.Context, actor domain.Actor, in CreateBuildRunInput) (domain.BuildRun, error) {
	outputs := make([]releasedomain.BuildOutput, 0, len(in.Outputs))
	for _, output := range in.Outputs {
		outputs = append(outputs, releasedomain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	value, err := l.releaseCommands.CreateBuildRun(ctx, actor, releaseapp.CreateBuildRunInput{
		ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, Provider: in.Provider, CommitSHA: in.CommitSHA,
		Repository: in.Repository, WorkflowRef: in.WorkflowRef, RunID: in.RunID, RunAttempt: in.RunAttempt,
		JobID: in.JobID, GitHubActor: in.GitHubActor, Ref: in.Ref, OIDCSubject: in.OIDCSubject,
		Status: in.Status, StartedAt: in.StartedAt, FinishedAt: cloneTimePtr(in.FinishedAt),
		ParametersHash: in.ParametersHash, EnvironmentHash: in.EnvironmentHash,
		ProviderMetadata: cloneIdentityAnyMap(in.ProviderMetadata), Outputs: outputs,
	})
	return buildRunFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) GetBuildRun(ctx context.Context, actor domain.Actor, id string) (domain.BuildRun, error) {
	value, err := l.releaseCommands.GetBuildRun(ctx, actor, id)
	return buildRunFromReleaseContext(value), fromReleaseContextError(err)
}

// UploadBuildAttestation is retained as an HTTP compatibility facade.
// Deprecated: use the focused release application service.
func (l *Ledger) UploadBuildAttestation(ctx context.Context, actor domain.Actor, buildID string, raw []byte) (domain.BuildAttestation, error) {
	value, err := l.releaseCommands.UploadBuildAttestation(ctx, actor, buildID, raw)
	return buildAttestationFromReleaseContext(value), fromReleaseContextError(err)
}

// UploadBuildAttestationPayload is retained for streamed compatibility callers.
// Deprecated: use the focused release application service.
func (l *Ledger) UploadBuildAttestationPayload(ctx context.Context, actor domain.Actor, buildID string, source PayloadSource) (domain.BuildAttestation, error) {
	value, err := l.releaseCommands.UploadBuildAttestationPayload(ctx, actor, buildID, releaseapp.BuildAttestationPayloadSource{
		Digest: source.Digest, Size: source.Size, Open: source.Open,
	})
	return buildAttestationFromReleaseContext(value), fromReleaseContextError(err)
}

func validCollectorScopes(scopes []string) bool {
	_, err := integrationapp.NormalizeCollectorScopes(scopes)
	return err == nil
}

func validCollectorType(typ string) bool {
	return integrationapp.ValidCollectorType(typ)
}

func actorType(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	if actor.UserID != "" {
		return "human_user"
	}
	return "api_key"
}

func actorID(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return actor.CollectorID
	}
	if actor.UserID != "" {
		return actor.UserID
	}
	return actor.KeyID
}

func (l *Ledger) checkReleaseHasPassedBuildLocked(tenantID, releaseID string) domain.PolicyCheck {
	releaseDigests := l.releaseArtifactDigestsLocked(tenantID, releaseID)
	for _, build := range l.buildRuns {
		if build.TenantID != tenantID || build.ReleaseID != releaseID || build.Status != buildStatusPassed {
			continue
		}
		for _, output := range build.Outputs {
			if _, ok := releaseDigests[output.Digest]; ok {
				return domain.PolicyCheck{Name: "release_requires_passed_build", Result: "passed", Severity: "high", Explanation: "passed build is linked to a release artifact digest"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_passed_build", Result: "failed", Severity: "high", Missing: []string{"passed_build"}, Explanation: "no passed build with output digest linked to the release was found", Remediation: "Upload a passed build run whose output digest matches a release artifact digest."}
}

func (l *Ledger) checkReleaseHasBuildAttestationLocked(tenantID, releaseID string) domain.PolicyCheck {
	releaseDigests := l.releaseArtifactDigestsLocked(tenantID, releaseID)
	for _, attestation := range l.attestations {
		if attestation.TenantID != tenantID {
			continue
		}
		build, ok := l.buildRuns[attestation.BuildID]
		if !ok || build.TenantID != tenantID || build.ReleaseID != releaseID {
			continue
		}
		if !l.hasPassedDSSEAttestationReceiptLocked(tenantID, attestation.ID) {
			continue
		}
		for _, digest := range attestation.SubjectDigests {
			if _, ok := releaseDigests[digest]; ok {
				return domain.PolicyCheck{Name: "release_requires_build_attestation", Result: "passed", Severity: "high", Explanation: "verified build attestation receipt and subject match a release artifact digest"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_build_attestation", Result: "failed", Severity: "high", Missing: []string{"build_attestation"}, Explanation: "no attestation has a passed DSSE/in-toto receipt and a subject matching a release artifact digest", Remediation: "Upload a supported DSSE/in-toto attestation, verify it with a configured root policy, and ensure its subject digest matches a release artifact digest."}
}

func (l *Ledger) hasPassedDSSEAttestationReceiptLocked(tenantID, attestationID string) bool {
	for _, verification := range l.verifications {
		if verification.TenantID != tenantID || verification.SubjectType != "build_attestation" || verification.SubjectID != attestationID || verification.Result != string(domain.VerificationStatePassed) {
			continue
		}
		if verification.Profile.ID == domain.VerificationProfileDSSEAttestationSignature && verification.SchemaVersion == domain.VerificationResultSchemaVersion {
			return true
		}
	}
	return false
}

func (l *Ledger) releaseArtifactDigestsLocked(tenantID, releaseID string) map[string]struct{} {
	digests := map[string]struct{}{}
	for _, item := range l.evidence {
		if item.TenantID != tenantID || item.ReleaseID != releaseID {
			continue
		}
		for _, ref := range item.SubjectRefs {
			if ref.Type != "artifact" {
				continue
			}
			// SubjectRef.Digest remains an opaque compatibility field. Only a
			// tenant-owned registered artifact can contribute a trusted digest.
			if ref.ID != "" {
				if artifact, ok := l.artifacts[ref.ID]; ok && artifact.TenantID == tenantID && validDigest(artifact.Digest) {
					digests[artifact.Digest] = struct{}{}
				}
			}
		}
	}
	return digests
}
