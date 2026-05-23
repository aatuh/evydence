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
		Tenants:            l.tenants,
		APIKeys:            apiKeys,
		APIKeyHashes:       map[string]string{},
		Collectors:         l.collectors,
		Products:           l.products,
		Projects:           l.projects,
		Releases:           l.releases,
		Artifacts:          l.artifacts,
		BuildRuns:          l.buildRuns,
		BuildAttestations:  l.attestations,
		Evidence:           l.evidence,
		EvidenceLifecycle:  l.lifecycle,
		ReleaseCandidates:  l.candidates,
		ContainerImages:    l.images,
		ArtifactSignatures: l.artifactSigs,
		Repositories:       l.repositories,
		Commits:            l.commits,
		Branches:           l.branches,
		PullRequests:       l.pullRequests,
		Environments:       l.environments,
		Deployments:        l.deployments,
		ControlFrameworks:  l.frameworks,
		SecurityControls:   l.controls,
		ControlEvidence:    l.controlLinks,
		SBOMs:              l.sboms,
		Scans:              l.scans,
		VEXDocuments:       l.vexDocuments,
		Decisions:          l.decisions,
		Contracts:          l.contracts,
		Policies:           l.policies,
		Exceptions:         l.exceptions,
		Bundles:            l.bundles,
		SigningKeys:        signingKeys,
		SigningKeyPrivate:  map[string][]byte{},
		Signatures:         l.signatures,
		Verifications:      l.verifications,
		Chain:              l.chain,
		Idempotency:        l.idempotency,
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
