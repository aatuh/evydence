package app

import (
	"context"
	"slices"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Public recorded provenance is a private component of the complete fixture
// snapshot. It is not an attestation/signature verification result. Explicit
// profile exclusions are applied by the owning manifest command, as for SQL.
func readMemoryCustomerPackageProvenance(ctx context.Context, s *MemoryUnitOfWorkSnapshot, tenant, product, release string, profile packagedomain.RedactionProfile, budget *memoryCustomerSnapshotBudget) (map[string]any, error) {
	if err := validateMemoryCustomerSnapshotRead(ctx, s, tenant, product, release, budget); err != nil {
		return nil, err
	}
	if profile.TenantID != tenant {
		return nil, ErrValidation
	}
	working := *budget
	builds, attestations := []map[string]any{}, []map[string]any{}
	selected := map[string]bool{}
	// Preserve format selection: allowing attestations alone does not select
	// their build inventory or bypass the build's current ownership checks.
	if packageapp.CustomerPackageIncludesType(profile, "build") {
		for key, b := range s.BuildRuns {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			owned, err := memoryCustomerProvenanceBuildOwned(ctx, s, key, b, tenant, product, release)
			if err != nil {
				return nil, err
			}
			if !owned {
				continue
			}
			if b.RunAttempt < 0 {
				return nil, ErrConflict
			}
			outputs := make([]map[string]any, 0, len(b.Outputs))
			for _, output := range b.Outputs {
				outputs = append(outputs, map[string]any{"artifact_id": output.ArtifactID, "digest": output.Digest})
			}
			row := map[string]any{"id": b.ID, "project_id": b.ProjectID, "collector_id": b.CollectorID, "provider": b.Provider, "commit_sha": b.CommitSHA, "repository": b.Repository, "workflow_ref": b.WorkflowRef, "run_id": b.RunID, "run_attempt": b.RunAttempt, "status": b.Status, "parameters_hash": b.ParametersHash, "environment_hash": b.EnvironmentHash, "finished_at": "", "schema_version": b.SchemaVersion, "outputs": outputs}
			if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"started_at": b.StartedAt, "created_at": b.CreatedAt}, map[string]*time.Time{"finished_at": b.FinishedAt}); err != nil {
				return nil, err
			}
			if err := appendMemoryCustomerMetadata(&builds, row, &working); err != nil {
				return nil, err
			}
			values := make([]packageapp.CustomerPackageBuildOutput, 0, len(b.Outputs))
			for _, output := range b.Outputs {
				values = append(values, packageapp.CustomerPackageBuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
			}
			row["outputs"] = packageapp.CustomerPackageBuildOutputSummaries(values)
			selected[b.ID] = true
		}
		if packageapp.CustomerPackageIncludesType(profile, "build_attestation") {
			for key, a := range s.BuildAttestations {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if a.ID != key || a.TenantID != tenant || !selected[a.BuildID] || !memoryCustomerAttestationSourceOwned(s, a, tenant, product, release) {
					continue
				}
				if a.PayloadSize < 0 || a.SignatureCount < 0 || len(a.SubjectDigests) > packageapp.MaxSecurityReviewEvidenceIDs {
					return nil, ErrConflict
				}
				row := map[string]any{"id": a.ID, "build_id": a.BuildID, "evidence_id": a.EvidenceID, "payload_hash": a.PayloadHash, "payload_size": a.PayloadSize, "payload_type": a.PayloadType, "predicate_type": a.PredicateType, "subject_digests": a.SubjectDigests, "signature_count": a.SignatureCount, "verification_status": a.VerificationStatus, "schema_version": a.SchemaVersion}
				if err := memoryCustomerMetadataTimes(row, map[string]time.Time{"created_at": a.CreatedAt}, nil); err != nil {
					return nil, err
				}
				if err := appendMemoryCustomerMetadata(&attestations, row, &working); err != nil {
					return nil, err
				}
				row["subject_digests"] = slices.Clone(a.SubjectDigests)
			}
		}
	}
	sortMemoryCustomerMetadata(builds)
	sortMemoryCustomerMetadata(attestations)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	*budget = working
	return map[string]any{"builds": builds, "build_attestations": attestations}, nil
}

func memoryCustomerProvenanceBuildOwned(ctx context.Context, s *MemoryUnitOfWorkSnapshot, key string, b domain.BuildRun, tenant, product, release string) (bool, error) {
	if b.ID != key || b.TenantID != tenant || b.ReleaseID != release {
		return false, nil
	}
	p, ok := s.Projects[b.ProjectID]
	if !ok || p.ID != b.ProjectID || p.TenantID != tenant || p.ProductID != product {
		return false, nil
	}
	if release != "" {
		r, ok := s.Releases[release]
		if !ok || r.ID != release || r.TenantID != tenant || r.ProductID != product {
			return false, nil
		}
	}
	if b.CollectorID != "" {
		c, ok := s.Collectors[b.CollectorID]
		if !ok || c.ID != b.CollectorID || c.TenantID != tenant {
			return false, nil
		}
	}
	if len(b.Outputs) > packageapp.MaxSecurityReviewEvidenceIDs {
		return false, ErrConflict
	}
	remaining := packageapp.MaxCustomerPackageManifestBytes
	for _, output := range b.Outputs {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if !memoryCustomerSnapshotID(output.ArtifactID, true) || !memoryGovernanceText(output.ArtifactID, remaining) {
			return false, ErrConflict
		}
		remaining -= len(output.ArtifactID)
		if !memoryGovernanceText(output.Digest, remaining) {
			return false, ErrConflict
		}
		remaining -= len(output.Digest)
		if output.ArtifactID != "" {
			a, ok := s.Artifacts[output.ArtifactID]
			if !ok || a.ID != output.ArtifactID || a.TenantID != tenant || a.Digest != output.Digest {
				return false, nil
			}
		}
	}
	return true, nil
}

func memoryCustomerAttestationSourceOwned(s *MemoryUnitOfWorkSnapshot, a domain.BuildAttestation, tenant, product, release string) bool {
	b, ok := s.BuildRuns[a.BuildID]
	if !ok || b.ID != a.BuildID || b.TenantID != tenant {
		return false
	}
	e, ok := s.Evidence[a.EvidenceID]
	return ok && e.ID == a.EvidenceID && e.TenantID == tenant && e.Type == "build_attestation" && e.ProductID == product && e.ProjectID == b.ProjectID && e.ReleaseID == b.ReleaseID && e.BuildID == b.ID && e.DeploymentID == "" && e.PayloadHash == a.PayloadHash && e.PayloadSize == a.PayloadSize && e.PayloadRef == a.PayloadRef && memoryCustomerEvidenceInScope(s, a.EvidenceID, e, tenant, product, release)
}
