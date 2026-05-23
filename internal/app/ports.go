package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type Store interface {
	LoadState(context.Context) (PersistedState, bool, error)
	SaveState(context.Context, PersistedState) error
}

type ObjectStore interface {
	Put(context.Context, Object) error
	Get(context.Context, string) (Object, error)
}

type Outbox interface {
	Enqueue(context.Context, OutboxJob) error
}

type PersistedState struct {
	Tenants                 map[string]domain.Tenant                      `json:"tenants"`
	APIKeys                 map[string]domain.APIKey                      `json:"api_keys"`
	APIKeyHashes            map[string]string                             `json:"api_key_hashes,omitempty"`
	Collectors              map[string]domain.Collector                   `json:"collectors"`
	Products                map[string]domain.Product                     `json:"products"`
	Projects                map[string]domain.Project                     `json:"projects"`
	Releases                map[string]domain.Release                     `json:"releases"`
	Artifacts               map[string]domain.Artifact                    `json:"artifacts"`
	BuildRuns               map[string]domain.BuildRun                    `json:"build_runs"`
	BuildAttestations       map[string]domain.BuildAttestation            `json:"build_attestations"`
	Evidence                map[string]domain.EvidenceItem                `json:"evidence"`
	EvidenceLifecycle       map[string]domain.EvidenceLifecycleEvent      `json:"evidence_lifecycle"`
	ReleaseCandidates       map[string]domain.ReleaseCandidate            `json:"release_candidates"`
	ContainerImages         map[string]domain.ContainerImage              `json:"container_images"`
	ArtifactSignatures      map[string]domain.ArtifactSignature           `json:"artifact_signatures"`
	Repositories            map[string]domain.SourceRepository            `json:"repositories"`
	Commits                 map[string]domain.SourceCommit                `json:"commits"`
	Branches                map[string]domain.SourceBranch                `json:"branches"`
	PullRequests            map[string]domain.PullRequest                 `json:"pull_requests"`
	Environments            map[string]domain.DeploymentEnvironment       `json:"environments"`
	Deployments             map[string]domain.DeploymentEvent             `json:"deployments"`
	Incidents               map[string]domain.Incident                    `json:"incidents"`
	TimelineEvents          map[string]domain.IncidentTimelineEvent       `json:"timeline_events"`
	RemediationTasks        map[string]domain.RemediationTask             `json:"remediation_tasks"`
	SecurityScans           map[string]domain.SecurityScan                `json:"security_scans"`
	ManualSecurityDocs      map[string]domain.ManualSecurityDocument      `json:"manual_security_docs"`
	SBOMDiffs               map[string]domain.SBOMDiff                    `json:"sbom_diffs"`
	DependencyChanges       map[string]domain.DependencyChange            `json:"dependency_changes"`
	VulnerabilityWorkflow   map[string]domain.VulnerabilityWorkflowRecord `json:"vulnerability_workflow"`
	ContractDiffs           map[string]domain.ContractDiff                `json:"contract_diffs"`
	CustomPolicies          map[string]domain.CustomPolicy                `json:"custom_policies"`
	CustomPolicyEvaluations map[string]domain.CustomPolicyEvaluation      `json:"custom_policy_evaluations"`
	Waivers                 map[string]domain.Waiver                      `json:"waivers"`
	Approvals               map[string]domain.ApprovalRecord              `json:"approvals"`
	RedactionProfiles       map[string]domain.RedactionProfile            `json:"redaction_profiles"`
	CustomerPackages        map[string]domain.CustomerSecurityPackage     `json:"customer_packages"`
	HTMLReports             map[string]domain.HTMLReportPackage           `json:"html_reports"`
	ReportTemplates         map[string]domain.CustomReportTemplate        `json:"report_templates"`
	RenderedReports         map[string]domain.RenderedCustomReport        `json:"rendered_reports"`
	EvidenceBundles         map[string]domain.EvidenceBundle              `json:"evidence_bundles"`
	BundleImports           map[string]domain.EvidenceBundleImport        `json:"bundle_imports"`
	DSSETrustRoots          map[string]domain.DSSETrustRoot               `json:"dsse_trust_roots"`
	ControlFrameworks       map[string]domain.ControlFramework            `json:"control_frameworks"`
	SecurityControls        map[string]domain.SecurityControl             `json:"security_controls"`
	ControlEvidence         map[string]domain.ControlEvidence             `json:"control_evidence"`
	SBOMs                   map[string]domain.SBOM                        `json:"sboms"`
	Scans                   map[string]domain.VulnerabilityScan           `json:"scans"`
	VEXDocuments            map[string]domain.VEXDocument                 `json:"vex_documents"`
	Decisions               map[string]domain.VulnerabilityDecision       `json:"vulnerability_decisions"`
	Contracts               map[string]domain.OpenAPIContract             `json:"contracts"`
	Policies                map[string]domain.PolicyEvaluation            `json:"policies"`
	Exceptions              map[string]domain.Exception                   `json:"exceptions"`
	Bundles                 map[string]domain.ReleaseBundle               `json:"bundles"`
	SigningKeys             map[string]domain.SigningKey                  `json:"signing_keys"`
	SigningKeyPrivate       map[string][]byte                             `json:"signing_key_private,omitempty"`
	Signatures              map[string]domain.Signature                   `json:"signatures"`
	Verifications           map[string]domain.VerificationResult          `json:"verifications"`
	Chain                   map[string][]domain.AuditChainEntry           `json:"chain"`
	Idempotency             map[string]IdempotencyRecord                  `json:"idempotency"`
}

type IdempotencyRecord struct {
	RequestHash string    `json:"request_hash"`
	Status      int       `json:"status"`
	Response    any       `json:"response"`
	CreatedAt   time.Time `json:"created_at"`
}

type Object struct {
	Key       string
	TenantID  string
	MediaType string
	Digest    string
	Bytes     []byte
	CreatedAt time.Time
}

type OutboxJob struct {
	ID          string         `json:"id"`
	TenantID    string         `json:"tenant_id"`
	Kind        string         `json:"kind"`
	SubjectType string         `json:"subject_type"`
	SubjectID   string         `json:"subject_id"`
	Payload     map[string]any `json:"payload,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

type nopOutbox struct{}

func (nopOutbox) Enqueue(context.Context, OutboxJob) error { return nil }
