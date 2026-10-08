package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

// Shared memory-only trust predicates use the current transaction rows;
// they neither read Ledger nor establish SQL work/locking guarantees.
type memoryReadinessFacts struct {
	HasArtifact, HasSBOM, HasVulnerabilityScan, HasArtifactDigest                 bool
	HasPassedBuild, HasVerifiedBuildAttestation, UnhandledCritical, UnhandledHigh bool
	scans                                                                         map[string][]domain.VulnerabilityFinding
}

func readMemoryReadinessFacts(ctx context.Context, state *MemoryUnitOfWorkSnapshot, tenant, product, release string, at time.Time) (memoryReadinessFacts, error) {
	var out memoryReadinessFacts
	run := func() error {
		digests := map[string]bool{}
		for id := range state.Evidence {
			if err := ctx.Err(); err != nil {
				return err
			}
			e, ok := memoryAnomalyEvidence(state, tenant, product, release, id)
			if !ok {
				continue
			}
			out.HasSBOM = out.HasSBOM || e.Type == "sbom"
			out.HasVulnerabilityScan = out.HasVulnerabilityScan || e.Type == "vulnerability_scan"
			for _, ref := range e.SubjectRefs {
				if ref.Type != "artifact" {
					continue
				}
				out.HasArtifact = out.HasArtifact || ref.ID != ""
				a, ok := state.Artifacts[ref.ID]
				if ok && a.ID == ref.ID && a.TenantID == tenant && validDigest(a.Digest) {
					digests[a.Digest] = true
					out.HasArtifactDigest = true
				}
			}
		}
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
		out.scans = scans
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
				severity := strings.ToLower(f.Severity)
				if severity != "critical" && severity != "high" || status != "" && status != "open" {
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
				if severity == "critical" {
					out.UnhandledCritical = out.UnhandledCritical || !handled
				} else {
					out.UnhandledHigh = out.UnhandledHigh || !handled
				}
			}
		}
		return ctx.Err()
	}
	if err := run(); err != nil {
		return memoryReadinessFacts{}, err
	}
	return out, nil
}
