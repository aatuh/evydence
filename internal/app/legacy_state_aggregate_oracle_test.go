package app

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
)

func (l *Ledger) snapshotLocked() (PersistedState, error) {
	apiKeys := make(map[string]domain.APIKey, len(l.apiKeys))
	for id, key := range l.apiKeys {
		apiKeys[id] = key
	}
	ssoSessions := make(map[string]domain.SSOSession, len(l.ssoSessions))
	for id, session := range l.ssoSessions {
		ssoSessions[id] = session
	}
	portalAccess := make(map[string]domain.CustomerPortalAccess, len(l.portalAccess))
	for id, access := range l.portalAccess {
		portalAccess[id] = access
	}
	signingKeys := make(map[string]domain.SigningKey, len(l.signingKeys))
	for id, key := range l.signingKeys {
		signingKeys[id] = key
	}
	state := PersistedState{
		Tenants:                    l.tenants,
		Organizations:              l.organizations,
		Users:                      l.users,
		RoleBindings:               l.roleBindings,
		SSOProviders:               l.ssoProviders,
		IdentityLinks:              l.identityLinks,
		SSOSessions:                ssoSessions,
		SSOSessionHashes:           map[string]string{},
		APIKeys:                    apiKeys,
		APIKeyHashes:               map[string]string{},
		Collectors:                 l.collectors,
		CollectorReleases:          l.collectorReleases,
		Products:                   l.products,
		Projects:                   l.projects,
		Releases:                   l.releases,
		Artifacts:                  l.artifacts,
		BuildRuns:                  l.buildRuns,
		BuildAttestations:          l.attestations,
		Evidence:                   l.evidence,
		EvidenceLifecycle:          l.lifecycle,
		ReleaseCandidates:          l.candidates,
		ContainerImages:            l.images,
		ArtifactSignatures:         l.artifactSigs,
		Repositories:               l.repositories,
		Commits:                    l.commits,
		Branches:                   l.branches,
		PullRequests:               l.pullRequests,
		Environments:               l.environments,
		Deployments:                l.deployments,
		Incidents:                  l.incidents,
		TimelineEvents:             l.timeline,
		IncidentWebhookReceivers:   l.webhookReceivers,
		IncidentWebhookEvents:      l.webhookEvents,
		RemediationTasks:           l.tasks,
		SecurityScans:              l.securityScans,
		ManualSecurityDocs:         l.manualDocs,
		SBOMDiffs:                  l.sbomDiffs,
		DependencyChanges:          l.depChanges,
		VulnerabilityWorkflow:      l.vulnWorkflow,
		ContractDiffs:              l.contractDiffs,
		CustomPolicies:             l.customPolicies,
		CustomPolicyEvaluations:    l.customPolicyEvals,
		Waivers:                    l.waivers,
		Approvals:                  l.approvals,
		RedactionProfiles:          l.redactions,
		CustomerPackages:           l.customerPackages,
		HTMLReports:                l.htmlReports,
		ReportTemplates:            l.reportTemplates,
		RenderedReports:            l.renderedReports,
		EvidenceBundles:            l.evidenceBundles,
		BundleImports:              l.bundleImports,
		DSSETrustRoots:             l.dsseTrustRoots,
		CosignVerifications:        l.cosignVerifs,
		SigningProviders:           l.signingProviders,
		MerkleBatches:              l.merkleBatches,
		TransparencyCheckpoints:    l.transparency,
		ObjectRetentionPolicies:    l.retentionPolicies,
		BackupManifests:            l.backupManifests,
		LegalHolds:                 l.legalHolds,
		RetentionOverrides:         l.retentionOverrides,
		CustomerPortalAccess:       portalAccess,
		CustomerPortalHashes:       map[string]string{},
		QuestionnaireTemplates:     l.questionTemplates,
		QuestionnairePackages:      l.questionPackages,
		QuestionnaireAnswerLibrary: l.answerLibrary,
		CommercialCollectors:       l.commercialCollectors,
		EvidenceSummaries:          l.evidenceSummaries,
		QuestionnaireDrafts:        l.questionDrafts,
		GraphSnapshots:             l.graphSnapshots,
		SaaSProfiles:               l.saasProfiles,
		PublicTransparencyLogs:     l.publicLogs,
		PublicTransparencyItems:    l.publicLogEntries,
		MarketplaceCollectors:      l.marketplaceCollectors,
		PDFReports:                 l.pdfReports,
		AnomalyReports:             l.anomalyReports,
		ProviderVerifications:      l.providerVerifications,
		SigningOperations:          l.signingOperations,
		ControlFrameworks:          l.frameworks,
		SecurityControls:           l.controls,
		ControlEvidence:            l.controlLinks,
		SBOMs:                      l.sboms,
		Scans:                      l.scans,
		VEXDocuments:               l.vexDocuments,
		VEXImportReports:           l.vexImportReports,
		Decisions:                  l.decisions,
		Contracts:                  l.contracts,
		Policies:                   l.policies,
		Exceptions:                 l.exceptions,
		Bundles:                    l.bundles,
		SigningKeys:                signingKeys,
		SigningKeyPrivate:          map[string][]byte{},
		Signatures:                 l.signatures,
		Verifications:              l.verifications,
		Chain:                      l.chain,
		Idempotency:                l.idempotency,
	}
	for id, key := range state.APIKeys {
		if key.Hash != "" {
			state.APIKeyHashes[id] = key.Hash
			key.Hash = ""
			state.APIKeys[id] = key
		}
	}
	for id, session := range state.SSOSessions {
		if session.Hash != "" {
			state.SSOSessionHashes[id] = session.Hash
			session.Hash = ""
			state.SSOSessions[id] = session
		}
	}
	for id, access := range state.CustomerPortalAccess {
		if access.Hash != "" {
			state.CustomerPortalHashes[id] = access.Hash
			access.Hash = ""
			state.CustomerPortalAccess[id] = access
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

func releaseLedgerMutationFromState(state PersistedState) ReleaseLedgerMutation {
	mutation := ReleaseLedgerMutation{}
	for _, product := range state.Products {
		mutation.Products = append(mutation.Products, product)
	}
	for _, project := range state.Projects {
		mutation.Projects = append(mutation.Projects, project)
	}
	for _, release := range state.Releases {
		mutation.Releases = append(mutation.Releases, release)
	}
	for _, artifact := range state.Artifacts {
		mutation.Artifacts = append(mutation.Artifacts, artifact)
	}
	for _, evidence := range state.Evidence {
		mutation.Evidence = append(mutation.Evidence, evidence)
	}
	for _, event := range state.EvidenceLifecycle {
		mutation.EvidenceLifecycle = append(mutation.EvidenceLifecycle, event)
	}
	for _, sbom := range state.SBOMs {
		mutation.SBOMs = append(mutation.SBOMs, sbom)
	}
	for _, scan := range state.Scans {
		mutation.Scans = append(mutation.Scans, scan)
	}
	for _, contract := range state.Contracts {
		mutation.Contracts = append(mutation.Contracts, contract)
	}
	for _, vex := range state.VEXDocuments {
		mutation.VEXDocuments = append(mutation.VEXDocuments, vex)
	}
	for _, report := range state.VEXImportReports {
		mutation.VEXImportReports = append(mutation.VEXImportReports, report)
	}
	for _, attestation := range state.BuildAttestations {
		mutation.BuildAttestations = append(mutation.BuildAttestations, attestation)
	}
	for _, decision := range state.Decisions {
		mutation.VulnerabilityDecisions = append(mutation.VulnerabilityDecisions, decision)
	}
	for _, tenantChain := range state.Chain {
		mutation.AuditChainEntries = append(mutation.AuditChainEntries, tenantChain...)
	}
	return mutation
}

func criticalMutationFromState(state PersistedState) CriticalMutation {
	mutation := CriticalMutation{
		APIKeyHashes:         map[string]string{},
		SSOSessionHashes:     map[string]string{},
		CustomerPortalHashes: map[string]string{},
		Idempotency:          map[string]IdempotencyRecord{},
		SigningKeyPrivate:    map[string][]byte{},
	}
	for _, tenant := range state.Tenants {
		mutation.Tenants = append(mutation.Tenants, tenant)
	}
	for id, key := range state.APIKeys {
		mutation.APIKeys = append(mutation.APIKeys, key)
		if hash := state.APIKeyHashes[id]; hash != "" {
			mutation.APIKeyHashes[id] = hash
		}
	}
	for _, collector := range state.Collectors {
		mutation.Collectors = append(mutation.Collectors, collector)
	}
	for id, session := range state.SSOSessions {
		mutation.SSOSessions = append(mutation.SSOSessions, session)
		if hash := state.SSOSessionHashes[id]; hash != "" {
			mutation.SSOSessionHashes[id] = hash
		}
	}
	for id, access := range state.CustomerPortalAccess {
		mutation.CustomerPortalAccess = append(mutation.CustomerPortalAccess, access)
		if hash := state.CustomerPortalHashes[id]; hash != "" {
			mutation.CustomerPortalHashes[id] = hash
		}
	}
	for key, record := range state.Idempotency {
		mutation.Idempotency[key] = record
	}
	for id, key := range state.SigningKeys {
		mutation.SigningKeys = append(mutation.SigningKeys, key)
		if private := state.SigningKeyPrivate[id]; len(private) > 0 {
			mutation.SigningKeyPrivate[id] = append([]byte(nil), private...)
		}
	}
	for _, signature := range state.Signatures {
		mutation.Signatures = append(mutation.Signatures, signature)
	}
	for _, bundle := range state.Bundles {
		mutation.ReleaseBundles = append(mutation.ReleaseBundles, bundle)
	}
	for _, verification := range state.Verifications {
		mutation.VerificationResults = append(mutation.VerificationResults, verification)
	}
	for _, verification := range state.ProviderVerifications {
		mutation.ProviderVerifications = append(mutation.ProviderVerifications, verification)
	}
	for _, decision := range state.Decisions {
		mutation.VulnerabilityDecisions = append(mutation.VulnerabilityDecisions, decision)
	}
	for _, entries := range state.Chain {
		mutation.AuditChainEntries = append(mutation.AuditChainEntries, entries...)
	}
	return mutation
}

func (l *Ledger) applyState(state PersistedState) error {
	cloned, err := cloneState(state)
	if err != nil {
		return err
	}
	state = normalizeState(cloned)
	for id, hash := range state.APIKeyHashes {
		key, ok := state.APIKeys[id]
		if !ok {
			continue
		}
		key.Hash = hash
		state.APIKeys[id] = key
	}
	for id, hash := range state.SSOSessionHashes {
		session, ok := state.SSOSessions[id]
		if !ok {
			continue
		}
		session.Hash = hash
		state.SSOSessions[id] = session
	}
	for id, hash := range state.CustomerPortalHashes {
		access, ok := state.CustomerPortalAccess[id]
		if !ok {
			continue
		}
		access.Hash = hash
		state.CustomerPortalAccess[id] = access
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
	l.organizations = state.Organizations
	l.users = state.Users
	l.roleBindings = state.RoleBindings
	l.ssoProviders = state.SSOProviders
	l.identityLinks = state.IdentityLinks
	l.ssoSessions = state.SSOSessions
	l.apiKeys = state.APIKeys
	l.collectors = state.Collectors
	l.collectorReleases = state.CollectorReleases
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
	l.webhookReceivers = state.IncidentWebhookReceivers
	l.webhookEvents = state.IncidentWebhookEvents
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
	l.legalHolds = state.LegalHolds
	l.retentionOverrides = state.RetentionOverrides
	l.portalAccess = state.CustomerPortalAccess
	l.questionTemplates = state.QuestionnaireTemplates
	l.questionPackages = state.QuestionnairePackages
	l.answerLibrary = state.QuestionnaireAnswerLibrary
	l.commercialCollectors = state.CommercialCollectors
	l.evidenceSummaries = state.EvidenceSummaries
	l.questionDrafts = state.QuestionnaireDrafts
	l.graphSnapshots = state.GraphSnapshots
	l.saasProfiles = state.SaaSProfiles
	l.publicLogs = state.PublicTransparencyLogs
	l.publicLogEntries = state.PublicTransparencyItems
	l.marketplaceCollectors = state.MarketplaceCollectors
	l.pdfReports = state.PDFReports
	l.anomalyReports = state.AnomalyReports
	l.providerVerifications = state.ProviderVerifications
	l.signingOperations = state.SigningOperations
	l.frameworks = state.ControlFrameworks
	l.controls = state.SecurityControls
	l.controlLinks = state.ControlEvidence
	l.sboms = state.SBOMs
	l.scans = state.Scans
	l.vexDocuments = state.VEXDocuments
	l.vexImportReports = state.VEXImportReports
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
	return nil
}

func (l *Ledger) persistLocked(ctx context.Context) error {
	if l.store == nil {
		return nil
	}
	state, err := l.snapshotLocked()
	if err != nil {
		return err
	}
	if reconciled, ok := l.store.(AuditChainRelationalStateStore); ok {
		chain, err := reconciled.SaveRelationalStateWithAuditChain(ctx, state)
		if err == nil {
			cloned, cloneErr := cloneAuditChain(chain)
			if cloneErr != nil {
				return cloneErr
			}
			l.chain = cloned
		}
		return err
	}
	if relational, ok := l.store.(RelationalStateStore); ok {
		return relational.SaveRelationalState(ctx, state)
	}
	return l.store.SaveState(ctx, state)
}

func (l *Ledger) persistCriticalLocked(ctx context.Context, mutation CriticalMutation) error {
	if l.store == nil {
		return nil
	}
	if _, err := l.snapshotLocked(); err != nil {
		return err
	}
	if reconciled, ok := l.store.(AuditChainCriticalMutationStore); ok {
		chain, err := reconciled.ApplyCriticalMutationWithAuditChain(ctx, mutation)
		if err == nil {
			cloned, cloneErr := cloneAuditChain(chain)
			if cloneErr != nil {
				return cloneErr
			}
			l.chain = cloned
		}
		return err
	}
	focused, ok := l.store.(CriticalMutationStore)
	if !ok {
		return l.persistLocked(ctx)
	}
	return focused.ApplyCriticalMutation(ctx, mutation)
}

func (l *Ledger) persistReleaseLedgerLocked(ctx context.Context, mutation ReleaseLedgerMutation) error {
	if l.store == nil {
		return nil
	}
	if _, err := l.snapshotLocked(); err != nil {
		return err
	}
	if reconciled, ok := l.store.(AuditChainReleaseLedgerMutationStore); ok {
		chain, err := reconciled.ApplyReleaseLedgerMutationWithAuditChain(ctx, mutation)
		if err == nil {
			cloned, cloneErr := cloneAuditChain(chain)
			if cloneErr != nil {
				return cloneErr
			}
			l.chain = cloned
		}
		return err
	}
	focused, ok := l.store.(ReleaseLedgerMutationStore)
	if !ok {
		return l.persistLocked(ctx)
	}
	return focused.ApplyReleaseLedgerMutation(ctx, mutation)
}

func (l *Ledger) criticalMutationLocked() (CriticalMutation, error) {
	state, err := l.snapshotLocked()
	if err != nil {
		return CriticalMutation{}, err
	}
	return criticalMutationFromState(state), nil
}

func (l *Ledger) releaseLedgerMutationLocked() (ReleaseLedgerMutation, error) {
	state, err := l.snapshotLocked()
	if err != nil {
		return ReleaseLedgerMutation{}, err
	}
	return releaseLedgerMutationFromState(state), nil
}

func (l *Ledger) persistCriticalStateLocked(ctx context.Context) error {
	mutation, err := l.criticalMutationLocked()
	if err != nil {
		return err
	}
	return l.persistCriticalLocked(ctx, mutation)
}

func (l *Ledger) persistReleaseLedgerStateLocked(ctx context.Context) error {
	mutation, err := l.releaseLedgerMutationLocked()
	if err != nil {
		return err
	}
	return l.persistReleaseLedgerLocked(ctx, mutation)
}

func (l *Ledger) newOutboxJob(tenantID, kind, subjectType, subjectID string, payload map[string]any) OutboxJob {
	job := OutboxJob{
		ID:          newID("job"),
		TenantID:    tenantID,
		Kind:        kind,
		SubjectType: subjectType,
		SubjectID:   subjectID,
		Payload:     cloneMap(payload),
		CreatedAt:   l.now(),
	}
	_ = EnsureOutboxDeduplicationKey(&job)
	return job
}

func (l *Ledger) enqueueJob(ctx context.Context, job OutboxJob) error {
	if l.outbox == nil {
		return nil
	}
	return l.outbox.Enqueue(ctx, job)
}
