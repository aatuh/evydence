package app

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) snapshotLocked() PersistedState {
	apiKeys := make(map[string]domain.APIKey, len(l.apiKeys))
	for id, key := range l.apiKeys {
		apiKeys[id] = key
	}
	signingKeys := make(map[string]domain.SigningKey, len(l.signingKeys))
	for id, key := range l.signingKeys {
		signingKeys[id] = key
	}
	state := PersistedState{
		Tenants:                 l.tenants,
		APIKeys:                 apiKeys,
		APIKeyHashes:            map[string]string{},
		Collectors:              l.collectors,
		Products:                l.products,
		Projects:                l.projects,
		Releases:                l.releases,
		Artifacts:               l.artifacts,
		BuildRuns:               l.buildRuns,
		BuildAttestations:       l.attestations,
		Evidence:                l.evidence,
		EvidenceLifecycle:       l.lifecycle,
		ReleaseCandidates:       l.candidates,
		ContainerImages:         l.images,
		ArtifactSignatures:      l.artifactSigs,
		Repositories:            l.repositories,
		Commits:                 l.commits,
		Branches:                l.branches,
		PullRequests:            l.pullRequests,
		Environments:            l.environments,
		Deployments:             l.deployments,
		Incidents:               l.incidents,
		TimelineEvents:          l.timeline,
		RemediationTasks:        l.tasks,
		SecurityScans:           l.securityScans,
		ManualSecurityDocs:      l.manualDocs,
		SBOMDiffs:               l.sbomDiffs,
		DependencyChanges:       l.depChanges,
		VulnerabilityWorkflow:   l.vulnWorkflow,
		ContractDiffs:           l.contractDiffs,
		CustomPolicies:          l.customPolicies,
		CustomPolicyEvaluations: l.customPolicyEvals,
		Waivers:                 l.waivers,
		Approvals:               l.approvals,
		RedactionProfiles:       l.redactions,
		CustomerPackages:        l.customerPackages,
		HTMLReports:             l.htmlReports,
		ReportTemplates:         l.reportTemplates,
		RenderedReports:         l.renderedReports,
		EvidenceBundles:         l.evidenceBundles,
		BundleImports:           l.bundleImports,
		DSSETrustRoots:          l.dsseTrustRoots,
		CosignVerifications:     l.cosignVerifs,
		SigningProviders:        l.signingProviders,
		MerkleBatches:           l.merkleBatches,
		TransparencyCheckpoints: l.transparency,
		ObjectRetentionPolicies: l.retentionPolicies,
		BackupManifests:         l.backupManifests,
		ControlFrameworks:       l.frameworks,
		SecurityControls:        l.controls,
		ControlEvidence:         l.controlLinks,
		SBOMs:                   l.sboms,
		Scans:                   l.scans,
		VEXDocuments:            l.vexDocuments,
		Decisions:               l.decisions,
		Contracts:               l.contracts,
		Policies:                l.policies,
		Exceptions:              l.exceptions,
		Bundles:                 l.bundles,
		SigningKeys:             signingKeys,
		SigningKeyPrivate:       map[string][]byte{},
		Signatures:              l.signatures,
		Verifications:           l.verifications,
		Chain:                   l.chain,
		Idempotency:             l.idempotency,
	}
	for id, key := range state.APIKeys {
		if key.Hash != "" {
			state.APIKeyHashes[id] = key.Hash
			key.Hash = ""
			state.APIKeys[id] = key
		}
	}
	for id, key := range state.SigningKeys {
		if len(key.Private) > 0 {
			state.SigningKeyPrivate[id] = append([]byte(nil), key.Private...)
			key.Private = nil
			state.SigningKeys[id] = key
		}
	}
	return cloneState(state)
}

func (l *Ledger) applyState(state PersistedState) {
	state = normalizeState(cloneState(state))
	for id, hash := range state.APIKeyHashes {
		key, ok := state.APIKeys[id]
		if !ok {
			continue
		}
		key.Hash = hash
		state.APIKeys[id] = key
	}
	for id, private := range state.SigningKeyPrivate {
		key, ok := state.SigningKeys[id]
		if !ok {
			continue
		}
		key.Private = append([]byte(nil), private...)
		state.SigningKeys[id] = key
	}
	l.tenants = state.Tenants
	l.apiKeys = state.APIKeys
	l.collectors = state.Collectors
	l.products = state.Products
	l.projects = state.Projects
	l.releases = state.Releases
	l.artifacts = state.Artifacts
	l.buildRuns = state.BuildRuns
	l.attestations = state.BuildAttestations
	l.evidence = state.Evidence
	l.lifecycle = state.EvidenceLifecycle
	l.candidates = state.ReleaseCandidates
	l.images = state.ContainerImages
	l.artifactSigs = state.ArtifactSignatures
	l.repositories = state.Repositories
	l.commits = state.Commits
	l.branches = state.Branches
	l.pullRequests = state.PullRequests
	l.environments = state.Environments
	l.deployments = state.Deployments
	l.incidents = state.Incidents
	l.timeline = state.TimelineEvents
	l.tasks = state.RemediationTasks
	l.securityScans = state.SecurityScans
	l.manualDocs = state.ManualSecurityDocs
	l.sbomDiffs = state.SBOMDiffs
	l.depChanges = state.DependencyChanges
	l.vulnWorkflow = state.VulnerabilityWorkflow
	l.contractDiffs = state.ContractDiffs
	l.customPolicies = state.CustomPolicies
	l.customPolicyEvals = state.CustomPolicyEvaluations
	l.waivers = state.Waivers
	l.approvals = state.Approvals
	l.redactions = state.RedactionProfiles
	l.customerPackages = state.CustomerPackages
	l.htmlReports = state.HTMLReports
	l.reportTemplates = state.ReportTemplates
	l.renderedReports = state.RenderedReports
	l.evidenceBundles = state.EvidenceBundles
	l.bundleImports = state.BundleImports
	l.dsseTrustRoots = state.DSSETrustRoots
	l.cosignVerifs = state.CosignVerifications
	l.signingProviders = state.SigningProviders
	l.merkleBatches = state.MerkleBatches
	l.transparency = state.TransparencyCheckpoints
	l.retentionPolicies = state.ObjectRetentionPolicies
	l.backupManifests = state.BackupManifests
	l.frameworks = state.ControlFrameworks
	l.controls = state.SecurityControls
	l.controlLinks = state.ControlEvidence
	l.sboms = state.SBOMs
	l.scans = state.Scans
	l.vexDocuments = state.VEXDocuments
	l.decisions = state.Decisions
	l.contracts = state.Contracts
	l.policies = state.Policies
	l.exceptions = state.Exceptions
	l.bundles = state.Bundles
	l.signingKeys = state.SigningKeys
	l.signatures = state.Signatures
	l.verifications = state.Verifications
	l.chain = state.Chain
	l.idempotency = state.Idempotency
}

func (l *Ledger) persistLocked(ctx context.Context) error {
	if l.store == nil {
		return nil
	}
	return l.store.SaveState(ctx, l.snapshotLocked())
}

func (l *Ledger) storePayload(ctx context.Context, tenantID, kind, mediaType, digest string, raw []byte) (string, error) {
	if l.objects == nil {
		return "", nil
	}
	if tenantID == "" || !validDigest(digest) {
		return "", ErrValidation
	}
	digestPart := strings.TrimPrefix(digest, "sha256:")
	key := "tenants/" + tenantID + "/payloads/" + strings.TrimSpace(kind) + "/" + digestPart
	object := Object{
		Key:       key,
		TenantID:  tenantID,
		MediaType: mediaType,
		Digest:    digest,
		Bytes:     append([]byte(nil), raw...),
		CreatedAt: l.now(),
	}
	if err := l.objects.Put(ctx, object); err != nil {
		return "", err
	}
	return "object://" + key, nil
}

func (l *Ledger) enqueue(ctx context.Context, tenantID, kind, subjectType, subjectID string, payload map[string]any) error {
	if l.outbox == nil {
		return nil
	}
	job := OutboxJob{
		ID:          newID("job"),
		TenantID:    tenantID,
		Kind:        kind,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Payload:     cloneMap(payload),
		CreatedAt:   l.now(),
	}
	return l.outbox.Enqueue(ctx, job)
}

func cloneState(state PersistedState) PersistedState {
	body, err := json.Marshal(state)
	if err != nil {
		return normalizeState(PersistedState{})
	}
	var out PersistedState
	if err := json.Unmarshal(body, &out); err != nil {
		return normalizeState(PersistedState{})
	}
	return normalizeState(out)
}

func normalizeState(state PersistedState) PersistedState {
	if state.Tenants == nil {
		state.Tenants = map[string]domain.Tenant{}
	}
	if state.APIKeys == nil {
		state.APIKeys = map[string]domain.APIKey{}
	}
	if state.APIKeyHashes == nil {
		state.APIKeyHashes = map[string]string{}
	}
	if state.Collectors == nil {
		state.Collectors = map[string]domain.Collector{}
	}
	if state.Products == nil {
		state.Products = map[string]domain.Product{}
	}
	if state.Projects == nil {
		state.Projects = map[string]domain.Project{}
	}
	if state.Releases == nil {
		state.Releases = map[string]domain.Release{}
	}
	if state.Artifacts == nil {
		state.Artifacts = map[string]domain.Artifact{}
	}
	if state.BuildRuns == nil {
		state.BuildRuns = map[string]domain.BuildRun{}
	}
	if state.BuildAttestations == nil {
		state.BuildAttestations = map[string]domain.BuildAttestation{}
	}
	if state.Evidence == nil {
		state.Evidence = map[string]domain.EvidenceItem{}
	}
	if state.EvidenceLifecycle == nil {
		state.EvidenceLifecycle = map[string]domain.EvidenceLifecycleEvent{}
	}
	if state.ReleaseCandidates == nil {
		state.ReleaseCandidates = map[string]domain.ReleaseCandidate{}
	}
	if state.ContainerImages == nil {
		state.ContainerImages = map[string]domain.ContainerImage{}
	}
	if state.ArtifactSignatures == nil {
		state.ArtifactSignatures = map[string]domain.ArtifactSignature{}
	}
	if state.Repositories == nil {
		state.Repositories = map[string]domain.SourceRepository{}
	}
	if state.Commits == nil {
		state.Commits = map[string]domain.SourceCommit{}
	}
	if state.Branches == nil {
		state.Branches = map[string]domain.SourceBranch{}
	}
	if state.PullRequests == nil {
		state.PullRequests = map[string]domain.PullRequest{}
	}
	if state.Environments == nil {
		state.Environments = map[string]domain.DeploymentEnvironment{}
	}
	if state.Deployments == nil {
		state.Deployments = map[string]domain.DeploymentEvent{}
	}
	if state.Incidents == nil {
		state.Incidents = map[string]domain.Incident{}
	}
	if state.TimelineEvents == nil {
		state.TimelineEvents = map[string]domain.IncidentTimelineEvent{}
	}
	if state.RemediationTasks == nil {
		state.RemediationTasks = map[string]domain.RemediationTask{}
	}
	if state.SecurityScans == nil {
		state.SecurityScans = map[string]domain.SecurityScan{}
	}
	if state.ManualSecurityDocs == nil {
		state.ManualSecurityDocs = map[string]domain.ManualSecurityDocument{}
	}
	if state.SBOMDiffs == nil {
		state.SBOMDiffs = map[string]domain.SBOMDiff{}
	}
	if state.DependencyChanges == nil {
		state.DependencyChanges = map[string]domain.DependencyChange{}
	}
	if state.VulnerabilityWorkflow == nil {
		state.VulnerabilityWorkflow = map[string]domain.VulnerabilityWorkflowRecord{}
	}
	if state.ContractDiffs == nil {
		state.ContractDiffs = map[string]domain.ContractDiff{}
	}
	if state.CustomPolicies == nil {
		state.CustomPolicies = map[string]domain.CustomPolicy{}
	}
	if state.CustomPolicyEvaluations == nil {
		state.CustomPolicyEvaluations = map[string]domain.CustomPolicyEvaluation{}
	}
	if state.Waivers == nil {
		state.Waivers = map[string]domain.Waiver{}
	}
	if state.Approvals == nil {
		state.Approvals = map[string]domain.ApprovalRecord{}
	}
	if state.RedactionProfiles == nil {
		state.RedactionProfiles = map[string]domain.RedactionProfile{}
	}
	if state.CustomerPackages == nil {
		state.CustomerPackages = map[string]domain.CustomerSecurityPackage{}
	}
	if state.HTMLReports == nil {
		state.HTMLReports = map[string]domain.HTMLReportPackage{}
	}
	if state.ReportTemplates == nil {
		state.ReportTemplates = map[string]domain.CustomReportTemplate{}
	}
	if state.RenderedReports == nil {
		state.RenderedReports = map[string]domain.RenderedCustomReport{}
	}
	if state.EvidenceBundles == nil {
		state.EvidenceBundles = map[string]domain.EvidenceBundle{}
	}
	if state.BundleImports == nil {
		state.BundleImports = map[string]domain.EvidenceBundleImport{}
	}
	if state.DSSETrustRoots == nil {
		state.DSSETrustRoots = map[string]domain.DSSETrustRoot{}
	}
	if state.CosignVerifications == nil {
		state.CosignVerifications = map[string]domain.CosignVerification{}
	}
	if state.SigningProviders == nil {
		state.SigningProviders = map[string]domain.SigningProvider{}
	}
	if state.MerkleBatches == nil {
		state.MerkleBatches = map[string]domain.MerkleBatch{}
	}
	if state.TransparencyCheckpoints == nil {
		state.TransparencyCheckpoints = map[string]domain.TransparencyCheckpoint{}
	}
	if state.ObjectRetentionPolicies == nil {
		state.ObjectRetentionPolicies = map[string]domain.ObjectRetentionPolicy{}
	}
	if state.BackupManifests == nil {
		state.BackupManifests = map[string]domain.BackupManifest{}
	}
	if state.ControlFrameworks == nil {
		state.ControlFrameworks = map[string]domain.ControlFramework{}
	}
	if state.SecurityControls == nil {
		state.SecurityControls = map[string]domain.SecurityControl{}
	}
	if state.ControlEvidence == nil {
		state.ControlEvidence = map[string]domain.ControlEvidence{}
	}
	if state.SBOMs == nil {
		state.SBOMs = map[string]domain.SBOM{}
	}
	if state.Scans == nil {
		state.Scans = map[string]domain.VulnerabilityScan{}
	}
	if state.VEXDocuments == nil {
		state.VEXDocuments = map[string]domain.VEXDocument{}
	}
	if state.Decisions == nil {
		state.Decisions = map[string]domain.VulnerabilityDecision{}
	}
	if state.Contracts == nil {
		state.Contracts = map[string]domain.OpenAPIContract{}
	}
	if state.Policies == nil {
		state.Policies = map[string]domain.PolicyEvaluation{}
	}
	if state.Exceptions == nil {
		state.Exceptions = map[string]domain.Exception{}
	}
	if state.Bundles == nil {
		state.Bundles = map[string]domain.ReleaseBundle{}
	}
	if state.SigningKeys == nil {
		state.SigningKeys = map[string]domain.SigningKey{}
	}
	if state.SigningKeyPrivate == nil {
		state.SigningKeyPrivate = map[string][]byte{}
	}
	if state.Signatures == nil {
		state.Signatures = map[string]domain.Signature{}
	}
	if state.Verifications == nil {
		state.Verifications = map[string]domain.VerificationResult{}
	}
	if state.Chain == nil {
		state.Chain = map[string][]domain.AuditChainEntry{}
	}
	if state.Idempotency == nil {
		state.Idempotency = map[string]IdempotencyRecord{}
	}
	return state
}
