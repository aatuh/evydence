package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

const (
	collectorTypeGitHubActions = "github_actions"
	collectorTypeGitLabCI      = "gitlab_ci"
	collectorTypeGenericCI     = "generic_ci"
	collectorTypeImportBundle  = "import_bundle"
	collectorStatusActive      = "active"

	buildStatusQueued    = "queued"
	buildStatusRunning   = "running"
	buildStatusPassed    = "passed"
	buildStatusFailed    = "failed"
	buildStatusCancelled = "cancelled"
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
	key, secret, err := l.createAPIKeyLocked(actor.TenantID, "collector:"+in.Name, scopes, nil)
	if err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
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
	l.collectors[collector.ID] = collector
	_, _ = l.appendChainLocked(actor.TenantID, "collector.created", "collector", collector.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.Collector{}, domain.APIKey{}, "", err
	}
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
	if in.Pinned {
		for id, existing := range l.collectorReleases {
			if existing.TenantID == actor.TenantID && existing.CollectorID == collector.ID && existing.Pinned {
				existing.Pinned = false
				l.collectorReleases[id] = existing
			}
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
	if err := ctx.Err(); err != nil {
		return domain.BuildRun{}, err
	}
	if err := require(actor, ScopeBuildWrite); err != nil {
		return domain.BuildRun{}, err
	}
	build, err := normalizeBuildInput(in)
	if err != nil {
		return domain.BuildRun{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	project, ok := l.projects[build.ProjectID]
	if !ok || project.TenantID != actor.TenantID {
		return domain.BuildRun{}, ErrNotFound
	}
	release, ok := l.releases[build.ReleaseID]
	if !ok || release.TenantID != actor.TenantID {
		return domain.BuildRun{}, ErrNotFound
	}
	if project.ProductID != release.ProductID {
		return domain.BuildRun{}, ErrValidation
	}
	for _, output := range build.Outputs {
		if !validDigest(output.Digest) {
			return domain.BuildRun{}, ErrValidation
		}
		if output.ArtifactID == "" {
			continue
		}
		artifact, ok := l.artifacts[output.ArtifactID]
		if !ok || artifact.TenantID != actor.TenantID {
			return domain.BuildRun{}, ErrNotFound
		}
		if artifact.Digest != output.Digest {
			return domain.BuildRun{}, ErrValidation
		}
	}
	build.ID = newID("build")
	build.TenantID = actor.TenantID
	build.CollectorID = actor.CollectorID
	build.SchemaVersion = domain.BuildRunSchemaVersion
	build.CreatedAt = l.now()
	build.SourceIdentity = buildSourceIdentity(build, actor)
	l.buildRuns[build.ID] = build
	_, _ = l.appendChainLocked(actor.TenantID, "build.created", "build_run", build.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.BuildRun{}, err
	}
	return build, nil
}

func (l *Ledger) GetBuildRun(ctx context.Context, actor domain.Actor, id string) (domain.BuildRun, error) {
	if err := ctx.Err(); err != nil {
		return domain.BuildRun{}, err
	}
	if err := require(actor, ScopeBuildRead); err != nil {
		return domain.BuildRun{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	build, ok := l.buildRuns[strings.TrimSpace(id)]
	if !ok || build.TenantID != actor.TenantID {
		return domain.BuildRun{}, ErrNotFound
	}
	return build, nil
}

func (l *Ledger) UploadBuildAttestation(ctx context.Context, actor domain.Actor, buildID string, raw []byte) (domain.BuildAttestation, error) {
	if err := ctx.Err(); err != nil {
		return domain.BuildAttestation{}, err
	}
	if err := require(actor, ScopeBuildWrite); err != nil {
		return domain.BuildAttestation{}, err
	}
	if len(raw) == 0 || len(raw) > 20<<20 {
		return domain.BuildAttestation{}, ErrValidation
	}
	parsed, err := parseDSSEAttestation(raw)
	if err != nil {
		return domain.BuildAttestation{}, err
	}
	buildID = strings.TrimSpace(buildID)
	l.mu.Lock()
	build, ok := l.buildRuns[buildID]
	if !ok || build.TenantID != actor.TenantID {
		l.mu.Unlock()
		return domain.BuildAttestation{}, ErrNotFound
	}
	if !subjectsMatchBuildOutputs(parsed.SubjectDigests, build.Outputs) {
		l.mu.Unlock()
		return domain.BuildAttestation{}, ErrValidation
	}
	l.mu.Unlock()

	payloadHash := hashBytes(raw)
	payloadRef, err := l.storePayload(ctx, actor.TenantID, "build-attestation", "application/vnd.dsse.envelope+json", payloadHash, raw)
	if err != nil {
		return domain.BuildAttestation{}, err
	}
	item, err := l.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProjectID:        build.ProjectID,
		ReleaseID:        build.ReleaseID,
		BuildID:          build.ID,
		Type:             "build_attestation",
		Subtype:          "dsse_in_toto",
		Title:            "DSSE in-toto build attestation",
		SourceSystem:     build.Provider,
		SourceIdentity:   build.SourceIdentity,
		CollectorID:      actor.CollectorID,
		ObservedAt:       l.now(),
		PayloadRef:       payloadRef,
		PayloadHash:      payloadHash,
		PayloadMediaType: "application/vnd.dsse.envelope+json",
		PayloadSize:      int64(len(raw)),
		SubjectRefs:      buildOutputSubjects(build.Outputs),
		Metadata: map[string]any{
			"payload_type":    parsed.PayloadType,
			"predicate_type":  parsed.PredicateType,
			"signature_count": parsed.SignatureCount,
		},
		Limitations: []string{"DSSE and in-toto structure was parsed; cryptographic trust-root verification is not performed in this slice."},
	})
	if err != nil {
		return domain.BuildAttestation{}, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	attestation := domain.BuildAttestation{
		ID:                 newID("att"),
		TenantID:           actor.TenantID,
		BuildID:            build.ID,
		EvidenceID:         item.ID,
		PayloadRef:         payloadRef,
		PayloadHash:        payloadHash,
		PayloadSize:        int64(len(raw)),
		PayloadType:        parsed.PayloadType,
		PredicateType:      parsed.PredicateType,
		SubjectDigests:     append([]string(nil), parsed.SubjectDigests...),
		BuilderID:          parsed.BuilderID,
		BuildType:          parsed.BuildType,
		MaterialsCount:     parsed.MaterialsCount,
		SignatureCount:     parsed.SignatureCount,
		VerificationStatus: "structurally_valid",
		SchemaVersion:      domain.BuildAttestationSchemaVersion,
		CreatedAt:          l.now(),
	}
	l.attestations[attestation.ID] = attestation
	_, _ = l.appendChainLocked(actor.TenantID, "build_attestation.created", "build_attestation", attestation.ID, actorType(actor), actorID(actor), payloadHash, "")
	if err := l.enqueue(ctx, actor.TenantID, "verify_attestation", "build_attestation", attestation.ID, map[string]any{"payload_ref": payloadRef, "payload_hash": payloadHash}); err != nil {
		return domain.BuildAttestation{}, err
	}
	if err := l.persistLocked(ctx); err != nil {
		return domain.BuildAttestation{}, err
	}
	return attestation, nil
}

func validCollectorScopes(scopes []string) bool {
	for _, scope := range scopes {
		switch strings.TrimSpace(scope) {
		case ScopeBuildWrite, ScopeBuildRead, ScopeEvidenceWrite, ScopeEvidenceRead, ScopeSourceWrite, ScopeSourceRead, ScopeBundleWrite, ScopeBundleRead:
		default:
			return false
		}
	}
	return len(scopes) > 0
}

func validCollectorType(typ string) bool {
	switch strings.TrimSpace(typ) {
	case collectorTypeGitHubActions, collectorTypeGitLabCI, collectorTypeGenericCI, collectorTypeImportBundle:
		return true
	default:
		return false
	}
}

func normalizeBuildInput(in CreateBuildRunInput) (domain.BuildRun, error) {
	build := domain.BuildRun{
		ProjectID:       strings.TrimSpace(in.ProjectID),
		ReleaseID:       strings.TrimSpace(in.ReleaseID),
		Provider:        strings.TrimSpace(in.Provider),
		CommitSHA:       strings.TrimSpace(in.CommitSHA),
		Repository:      strings.TrimSpace(in.Repository),
		WorkflowRef:     strings.TrimSpace(in.WorkflowRef),
		RunID:           strings.TrimSpace(in.RunID),
		RunAttempt:      in.RunAttempt,
		JobID:           strings.TrimSpace(in.JobID),
		Actor:           strings.TrimSpace(in.GitHubActor),
		Ref:             strings.TrimSpace(in.Ref),
		OIDCSubject:     strings.TrimSpace(in.OIDCSubject),
		Status:          strings.TrimSpace(in.Status),
		StartedAt:       in.StartedAt.UTC(),
		FinishedAt:      in.FinishedAt,
		ParametersHash:  strings.TrimSpace(in.ParametersHash),
		EnvironmentHash: strings.TrimSpace(in.EnvironmentHash),
		SourceIdentity:  cloneMap(in.ProviderMetadata),
		Outputs:         normalizeBuildOutputs(in.Outputs),
	}
	if build.ProjectID == "" || build.ReleaseID == "" || build.Provider == "" || build.CommitSHA == "" || build.Status == "" || build.StartedAt.IsZero() {
		return domain.BuildRun{}, ErrValidation
	}
	if !validCommitSHA(build.CommitSHA) || !validBuildStatus(build.Status) {
		return domain.BuildRun{}, ErrValidation
	}
	if build.ParametersHash != "" && !validDigest(build.ParametersHash) {
		return domain.BuildRun{}, ErrValidation
	}
	if build.EnvironmentHash != "" && !validDigest(build.EnvironmentHash) {
		return domain.BuildRun{}, ErrValidation
	}
	if build.Provider == collectorTypeGitHubActions {
		if build.Repository == "" || build.WorkflowRef == "" || build.RunID == "" || build.RunAttempt <= 0 {
			return domain.BuildRun{}, ErrValidation
		}
	}
	if build.Provider == collectorTypeGitLabCI {
		if build.Repository == "" || build.RunID == "" {
			return domain.BuildRun{}, ErrValidation
		}
	}
	for _, output := range build.Outputs {
		if !validDigest(output.Digest) {
			return domain.BuildRun{}, ErrValidation
		}
	}
	return build, nil
}

func normalizeBuildOutputs(outputs []domain.BuildOutput) []domain.BuildOutput {
	out := make([]domain.BuildOutput, 0, len(outputs))
	for _, output := range outputs {
		out = append(out, domain.BuildOutput{
			ArtifactID: strings.TrimSpace(output.ArtifactID),
			Digest:     strings.TrimSpace(output.Digest),
		})
	}
	return out
}

func validBuildStatus(status string) bool {
	switch strings.TrimSpace(status) {
	case buildStatusQueued, buildStatusRunning, buildStatusPassed, buildStatusFailed, buildStatusCancelled:
		return true
	default:
		return false
	}
}

func validCommitSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func actorType(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return "collector"
	}
	return "api_key"
}

func actorID(actor domain.Actor) string {
	if actor.CollectorID != "" {
		return actor.CollectorID
	}
	return actor.KeyID
}

func buildSourceIdentity(build domain.BuildRun, actor domain.Actor) map[string]any {
	source := "api"
	if actor.CollectorID != "" {
		source = "collector"
	}
	identity := map[string]any{
		"source":        source,
		"provider":      build.Provider,
		"commit_sha":    build.CommitSHA,
		"oidc_verified": false,
	}
	if actor.CollectorID != "" {
		identity["collector_id"] = actor.CollectorID
	}
	if build.Repository != "" {
		identity["repository"] = build.Repository
	}
	if build.WorkflowRef != "" {
		identity["workflow_ref"] = build.WorkflowRef
	}
	if build.RunID != "" {
		identity["run_id"] = build.RunID
	}
	if build.RunAttempt > 0 {
		identity["run_attempt"] = build.RunAttempt
	}
	if build.JobID != "" {
		identity["job_id"] = build.JobID
	}
	if build.Actor != "" {
		identity["actor"] = build.Actor
	}
	if build.Ref != "" {
		identity["ref"] = build.Ref
	}
	if build.OIDCSubject != "" {
		identity["oidc_subject"] = build.OIDCSubject
	}
	for key, value := range build.SourceIdentity {
		if _, exists := identity[key]; !exists {
			identity[key] = value
		}
	}
	return identity
}

type parsedAttestation struct {
	PayloadType    string
	PredicateType  string
	SubjectDigests []string
	BuilderID      string
	BuildType      string
	MaterialsCount int
	SignatureCount int
}

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

type inTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []inTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     slsaPredicate   `json:"predicate"`
}

type inTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type slsaPredicate struct {
	Builder   slsaBuilder       `json:"builder"`
	BuildType string            `json:"buildType"`
	Materials []json.RawMessage `json:"materials"`
}

type slsaBuilder struct {
	ID string `json:"id"`
}

func parseDSSEAttestation(raw []byte) (parsedAttestation, error) {
	var envelope dsseEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return parsedAttestation{}, ErrValidation
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return parsedAttestation{}, ErrValidation
	}
	if strings.TrimSpace(envelope.PayloadType) == "" || strings.TrimSpace(envelope.Payload) == "" || len(envelope.Signatures) == 0 {
		return parsedAttestation{}, ErrValidation
	}
	for _, sig := range envelope.Signatures {
		if strings.TrimSpace(sig.Sig) == "" {
			return parsedAttestation{}, ErrValidation
		}
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return parsedAttestation{}, ErrValidation
	}
	var statement inTotoStatement
	if err := json.Unmarshal(payload, &statement); err != nil {
		return parsedAttestation{}, ErrValidation
	}
	if strings.TrimSpace(statement.Type) == "" || strings.TrimSpace(statement.PredicateType) == "" || len(statement.Subject) == 0 {
		return parsedAttestation{}, ErrValidation
	}
	digests := []string{}
	for _, subject := range statement.Subject {
		digest := strings.TrimSpace(subject.Digest["sha256"])
		if digest == "" {
			return parsedAttestation{}, ErrValidation
		}
		full := "sha256:" + strings.ToLower(digest)
		if !validDigest(full) {
			return parsedAttestation{}, ErrValidation
		}
		digests = append(digests, full)
	}
	sort.Strings(digests)
	return parsedAttestation{
		PayloadType:    strings.TrimSpace(envelope.PayloadType),
		PredicateType:  strings.TrimSpace(statement.PredicateType),
		SubjectDigests: digests,
		BuilderID:      strings.TrimSpace(statement.Predicate.Builder.ID),
		BuildType:      strings.TrimSpace(statement.Predicate.BuildType),
		MaterialsCount: len(statement.Predicate.Materials),
		SignatureCount: len(envelope.Signatures),
	}, nil
}

func subjectsMatchBuildOutputs(subjectDigests []string, outputs []domain.BuildOutput) bool {
	outputSet := map[string]struct{}{}
	for _, output := range outputs {
		if output.Digest != "" {
			outputSet[output.Digest] = struct{}{}
		}
	}
	for _, digest := range subjectDigests {
		if _, ok := outputSet[digest]; ok {
			return true
		}
	}
	return false
}

func buildOutputSubjects(outputs []domain.BuildOutput) []domain.SubjectRef {
	refs := []domain.SubjectRef{}
	for _, output := range outputs {
		refs = append(refs, domain.SubjectRef{Type: "artifact", ID: output.ArtifactID, Digest: output.Digest})
	}
	return refs
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
	return domain.PolicyCheck{Name: "release_requires_passed_build", Result: "failed", Severity: "high", Missing: []string{"passed_build"}, Explanation: "no passed build with output digest linked to the release was found"}
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
		for _, digest := range attestation.SubjectDigests {
			if _, ok := releaseDigests[digest]; ok {
				return domain.PolicyCheck{Name: "release_requires_build_attestation", Result: "passed", Severity: "high", Explanation: "build attestation subject matches a release artifact digest"}
			}
		}
	}
	return domain.PolicyCheck{Name: "release_requires_build_attestation", Result: "failed", Severity: "high", Missing: []string{"build_attestation"}, Explanation: "no build attestation subject matches a release artifact digest"}
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
			if validDigest(ref.Digest) {
				digests[ref.Digest] = struct{}{}
			}
			if ref.ID != "" {
				if artifact, ok := l.artifacts[ref.ID]; ok && artifact.TenantID == tenantID && validDigest(artifact.Digest) {
					digests[artifact.Digest] = struct{}{}
				}
			}
		}
	}
	return digests
}
