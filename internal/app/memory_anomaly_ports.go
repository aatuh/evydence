package app

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
)

// Test-backend projections read the active repository transaction, never
// Ledger caches, raw payloads, private provider diagnostics or a readiness
// snapshot. The fixed-size facts characterize existing SQL trust predicates;
// memory transactions are not SQL locking or durability evidence.
func (r memoryFutureExtensionsRepository) ReadAnomalyScope(ctx context.Context, tenant, kind, id string) (experimentalapp.AnomalyScope, error) {
	s, err := r.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	return experimentalapp.AnomalyScope{TenantID: s.TenantID, SubjectType: s.SubjectType, SubjectID: s.SubjectID, Resources: s.Resources}, err
}

func memoryAnomalyEvidence(state *MemoryUnitOfWorkSnapshot, tenant, product, release, id string) (domain.EvidenceItem, bool) {
	e, ok := state.Evidence[id]
	if !ok || e.ID != id || e.TenantID != tenant || e.ReleaseID != release {
		return domain.EvidenceItem{}, false
	}
	refs, err := memoryOperationsCoordinates(state, tenant, application.ResourceReferences{ProductID: e.ProductID, ProjectID: e.ProjectID, ReleaseID: e.ReleaseID, BuildID: e.BuildID, DeploymentID: e.DeploymentID})
	return e, err == nil && refs.ProductID == product
}

func memoryAnomalyBuild(state *MemoryUnitOfWorkSnapshot, tenant, product, release, id string) (domain.BuildRun, bool) {
	b, ok := state.BuildRuns[id]
	if !ok || b.ID != id || b.TenantID != tenant || b.ReleaseID != release || b.ProjectID == "" || len(b.Outputs) > 4096 {
		return domain.BuildRun{}, false
	}
	refs, err := memoryOperationsCoordinates(state, tenant, application.ResourceReferences{ProjectID: b.ProjectID, ReleaseID: b.ReleaseID})
	if err != nil || refs.ProductID != product {
		return domain.BuildRun{}, false
	}
	if b.CollectorID != "" {
		c, ok := state.Collectors[b.CollectorID]
		if !ok || c.ID != b.CollectorID || c.TenantID != tenant {
			return domain.BuildRun{}, false
		}
	}
	// Match the existing SQL output-array budget without serializing private
	// source identity or the rest of the build. Bound before allocating JSON.
	bytes := 0
	for _, o := range b.Outputs {
		bytes += len(o.ArtifactID) + len(o.Digest)
		if !memoryMembershipText(o.ArtifactID, 1024) || bytes > 8<<20 {
			return domain.BuildRun{}, false
		}
		if o.ArtifactID != "" {
			a, ok := state.Artifacts[o.ArtifactID]
			if !ok || a.ID != o.ArtifactID || a.TenantID != tenant || a.Digest != o.Digest {
				return domain.BuildRun{}, false
			}
		}
	}
	raw, err := json.Marshal(b.Outputs)
	if err != nil || len(raw) > 8<<20 {
		return domain.BuildRun{}, false
	}
	return b, true
}

func (r memoryFutureExtensionsRepository) ReadAnomalyReleaseFacts(ctx context.Context, tenant, release string, at time.Time) (experimentalapp.AnomalyReleaseFacts, error) {
	if at.IsZero() || !memoryMembershipQueryText(release, 1024) {
		return experimentalapp.AnomalyReleaseFacts{}, ErrValidation
	}
	var out experimentalapp.AnomalyReleaseFacts
	err := memoryIdentityRepository(r).membershipRead(ctx, tenant, func(state *MemoryUnitOfWorkSnapshot) error {
		scope, err := memorySummaryScope(state, tenant, "release", release)
		if err != nil {
			return err
		}
		product := scope.Resources.ProductID
		digests := map[string]bool{}
		for id := range state.Evidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			e, ok := memoryAnomalyEvidence(state, tenant, product, release, id)
			if !ok {
				continue
			}
			for _, ref := range e.SubjectRefs {
				if ref.Type != "artifact" {
					continue
				}
				a, ok := state.Artifacts[ref.ID]
				if ok && a.ID == ref.ID && a.TenantID == tenant && validDigest(a.Digest) {
					digests[a.Digest] = true
				}
			}
		}
		out = experimentalapp.AnomalyReleaseFacts{TenantID: tenant, ReleaseID: release}
		for id := range state.BuildRuns {
			if err := ctx.Err(); err != nil {
				return err
			}
			b, ok := memoryAnomalyBuild(state, tenant, product, release, id)
			if !ok || b.Status != "passed" {
				continue
			}
			for _, output := range b.Outputs {
				if digests[output.Digest] {
					out.HasPassedBuild = true
				}
			}
		}
		for id, a := range state.BuildAttestations {
			if err := ctx.Err(); err != nil {
				return err
			}
			if a.ID != id || a.TenantID != tenant || len(a.SubjectDigests) > 4096 {
				continue
			}
			b, ok := memoryAnomalyBuild(state, tenant, product, release, a.BuildID)
			if !ok {
				continue
			}
			e, ok := memoryAnomalyEvidence(state, tenant, product, release, a.EvidenceID)
			if !ok || e.Type != "build_attestation" || e.ProductID != product || e.ProjectID != b.ProjectID || e.BuildID != b.ID || e.DeploymentID != "" || e.PayloadHash != a.PayloadHash || e.PayloadSize != a.PayloadSize || e.PayloadRef != a.PayloadRef {
				continue
			}
			linked := false
			for _, digest := range a.SubjectDigests {
				linked = linked || digests[digest]
			}
			if !linked {
				continue
			}
			for key, v := range state.VerificationResults {
				if v.ID == key && v.TenantID == tenant && v.SubjectType == "build_attestation" && v.SubjectID == a.ID && v.Result == "passed" && v.Profile.ID == domain.VerificationProfileDSSEAttestationSignature && v.SchemaVersion == domain.VerificationResultSchemaVersion {
					out.HasVerifiedBuildAttestation = true
					break
				}
			}
		}
		scans := map[string][]domain.VulnerabilityFinding{}
		for id, v := range state.VulnerabilityScans {
			if err := ctx.Err(); err != nil {
				return err
			}
			if v.ID != id || v.TenantID != tenant || v.ReleaseID != release {
				continue
			}
			e, ok := memoryAnomalyEvidence(state, tenant, product, release, v.EvidenceID)
			if !ok || e.Type != "vulnerability_scan" {
				continue
			}
			if v.Findings == nil {
				return ErrValidation
			}
			for _, f := range v.Findings {
				if strings.TrimSpace(f.ID) == "" || strings.TrimSpace(f.Severity) == "" {
					return ErrValidation
				}
			}
			scans[id] = v.Findings
		}
		for scan, findings := range scans {
			counts := map[string]int{}
			for _, f := range findings {
				counts[f.ID]++
			}
			for _, f := range findings {
				if err := ctx.Err(); err != nil {
					return err
				}
				status := strings.ToLower(f.State)
				if strings.ToLower(f.Severity) != "critical" || status != "" && status != "open" {
					continue
				}
				handled := false
				for key, d := range state.Decisions {
					if d.ID == key && d.TenantID == tenant && d.ReleaseID == release && d.ScanID == scan && d.FindingID == f.ID && d.Vulnerability == f.Vulnerability && d.Component == f.Component && d.SupersededBy == "" && counts[f.ID] == 1 && (d.Status == "fixed" || d.Status == "not_affected") {
						handled = true
						break
					}
				}
				if !handled {
					handled = memoryAnomalyException(state, tenant, release, f.ID, at, scans)
				}
				out.UnhandledCritical = out.UnhandledCritical || !handled
			}
		}
		return ctx.Err()
	})
	if err != nil {
		return experimentalapp.AnomalyReleaseFacts{}, err
	}
	return out, nil
}

func memoryAnomalyException(state *MemoryUnitOfWorkSnapshot, tenant, release, finding string, at time.Time, scans map[string][]domain.VulnerabilityFinding) bool {
	for id, x := range state.Exceptions {
		if x.ID != id || x.TenantID != tenant || x.ReleaseID != release || !x.Approved || !x.ExpiresAt.After(at) || x.FindingID != "" && x.FindingID != finding {
			continue
		}
		if x.ControlID != "" {
			c, ok := state.SecurityControls[x.ControlID]
			if !ok || c.ID != x.ControlID || c.TenantID != tenant {
				continue
			}
			f, ok := state.ControlFrameworks[c.FrameworkID]
			if !ok || f.ID != c.FrameworkID || f.TenantID != tenant {
				continue
			}
		}
		if x.FindingID != "" {
			found := false
			for _, findings := range scans {
				for _, f := range findings {
					found = found || f.ID == x.FindingID
				}
			}
			if !found {
				continue
			}
		}
		return true
	}
	return false
}

func (r memoryFutureExtensionsRepository) InsertFocusedAnomalyReport(ctx context.Context, v experimentaldomain.AnomalyReport) error {
	if !memoryMembershipQueryText(v.ID, 1024) || v.SchemaVersion != experimentaldomain.AnomalyReportVersion || v.CreatedAt.IsZero() || v.CreatedAt.Year() < 1 || v.CreatedAt.Year() > 9999 || v.Signals == nil || len(v.Signals) > 3 || !memoryExperimentalLimitations(v.Assumptions) || !memoryExperimentalLimitations(v.Limitations) || (v.Result != "clear" && v.Result != "attention_required") {
		return ErrValidation
	}
	in, err := experimentalapp.NormalizeAnomalyInput(experimentalapp.AnomalyReportInput{SubjectType: v.SubjectType, SubjectID: v.SubjectID})
	if err != nil || in.SubjectType != v.SubjectType || in.SubjectID != v.SubjectID {
		return ErrValidation
	}
	if _, err := r.ReadAnomalyScope(ctx, v.TenantID, v.SubjectType, v.SubjectID); err != nil {
		return err
	}
	signals := make([]domain.AnomalySignal, len(v.Signals))
	for i, s := range v.Signals {
		if !memoryMembershipQueryText(s.Name, 128) || !memoryMembershipQueryText(s.Severity, 128) || !memoryMembershipText(s.Detail, 4096) {
			return ErrValidation
		}
		signals[i] = domain.AnomalySignal{Name: s.Name, Severity: s.Severity, Detail: s.Detail}
	}
	return r.InsertAnomalyReport(ctx, domain.AnomalyReport{ID: v.ID, TenantID: v.TenantID, SubjectType: v.SubjectType, SubjectID: v.SubjectID, Result: v.Result, Signals: signals, Assumptions: slices.Clone(v.Assumptions), Limitations: slices.Clone(v.Limitations), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt})
}

var _ experimentalapp.AnomalyScopeReader = memoryFutureExtensionsRepository{}
var _ experimentalapp.AnomalyReleaseFactsReader = memoryFutureExtensionsRepository{}
