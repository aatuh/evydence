package app

import (
	"errors"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// Pure DTO copying and error translation confer no aggregate mutation authority.
func productToReleaseContext(value domain.Product) releasedomain.Product {
	return releasedomain.Product{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug, CreatedAt: value.CreatedAt}
}

func productFromReleaseContext(value releasedomain.Product) domain.Product {
	return domain.Product{ID: value.ID, TenantID: value.TenantID, Name: value.Name, Slug: value.Slug, CreatedAt: value.CreatedAt}
}

func projectToReleaseContext(value domain.Project) releasedomain.Project {
	return releasedomain.Project{ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, Name: value.Name, CreatedAt: value.CreatedAt}
}

func projectFromReleaseContext(value releasedomain.Project) domain.Project {
	return domain.Project{ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, Name: value.Name, CreatedAt: value.CreatedAt}
}

func artifactToReleaseContext(value domain.Artifact) releasedomain.Artifact {
	return releasedomain.Artifact{ID: value.ID, TenantID: value.TenantID, Name: value.Name, MediaType: value.MediaType, Size: value.Size, Digest: value.Digest, CreatedAt: value.CreatedAt}
}

func artifactFromReleaseContext(value releasedomain.Artifact) domain.Artifact {
	return domain.Artifact{ID: value.ID, TenantID: value.TenantID, Name: value.Name, MediaType: value.MediaType, Size: value.Size, Digest: value.Digest, CreatedAt: value.CreatedAt}
}

func buildRunToReleaseContext(value domain.BuildRun) releasedomain.BuildRun {
	outputs := make([]releasedomain.BuildOutput, 0, len(value.Outputs))
	for _, output := range value.Outputs {
		outputs = append(outputs, releasedomain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return releasedomain.BuildRun{
		ID: value.ID, TenantID: value.TenantID, ProjectID: value.ProjectID, ReleaseID: value.ReleaseID,
		CollectorID: value.CollectorID, Provider: value.Provider, CommitSHA: value.CommitSHA,
		Repository: value.Repository, WorkflowRef: value.WorkflowRef, RunID: value.RunID, RunAttempt: value.RunAttempt,
		JobID: value.JobID, Actor: value.Actor, Ref: value.Ref, OIDCSubject: value.OIDCSubject, Status: value.Status,
		StartedAt: value.StartedAt, FinishedAt: cloneTimePtr(value.FinishedAt), ParametersHash: value.ParametersHash,
		EnvironmentHash: value.EnvironmentHash, SourceIdentity: cloneIdentityAnyMap(value.SourceIdentity), Outputs: outputs,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func buildRunFromReleaseContext(value releasedomain.BuildRun) domain.BuildRun {
	outputs := make([]domain.BuildOutput, 0, len(value.Outputs))
	for _, output := range value.Outputs {
		outputs = append(outputs, domain.BuildOutput{ArtifactID: output.ArtifactID, Digest: output.Digest})
	}
	return domain.BuildRun{
		ID: value.ID, TenantID: value.TenantID, ProjectID: value.ProjectID, ReleaseID: value.ReleaseID,
		CollectorID: value.CollectorID, Provider: value.Provider, CommitSHA: value.CommitSHA,
		Repository: value.Repository, WorkflowRef: value.WorkflowRef, RunID: value.RunID, RunAttempt: value.RunAttempt,
		JobID: value.JobID, Actor: value.Actor, Ref: value.Ref, OIDCSubject: value.OIDCSubject, Status: value.Status,
		StartedAt: value.StartedAt, FinishedAt: cloneTimePtr(value.FinishedAt), ParametersHash: value.ParametersHash,
		EnvironmentHash: value.EnvironmentHash, SourceIdentity: cloneIdentityAnyMap(value.SourceIdentity), Outputs: outputs,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func buildAttestationToReleaseContext(value domain.BuildAttestation) releasedomain.BuildAttestation {
	return releasedomain.BuildAttestation{
		ID: value.ID, TenantID: value.TenantID, BuildID: value.BuildID, EvidenceID: value.EvidenceID,
		PayloadRef: value.PayloadRef, PayloadHash: value.PayloadHash, PayloadSize: value.PayloadSize,
		PayloadType: value.PayloadType, PredicateType: value.PredicateType,
		SubjectDigests: append([]string(nil), value.SubjectDigests...), BuilderID: value.BuilderID,
		BuildType: value.BuildType, MaterialsCount: value.MaterialsCount, SignatureCount: value.SignatureCount,
		VerificationStatus: value.VerificationStatus, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func buildAttestationFromReleaseContext(value releasedomain.BuildAttestation) domain.BuildAttestation {
	return domain.BuildAttestation{
		ID: value.ID, TenantID: value.TenantID, BuildID: value.BuildID, EvidenceID: value.EvidenceID,
		PayloadRef: value.PayloadRef, PayloadHash: value.PayloadHash, PayloadSize: value.PayloadSize,
		PayloadType: value.PayloadType, PredicateType: value.PredicateType,
		SubjectDigests: append([]string(nil), value.SubjectDigests...), BuilderID: value.BuilderID,
		BuildType: value.BuildType, MaterialsCount: value.MaterialsCount, SignatureCount: value.SignatureCount,
		VerificationStatus: value.VerificationStatus, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func stagedBuildAttestationPayloadToReleaseContext(value ObjectPayload) releaseapp.StagedBuildAttestationPayload {
	return releaseapp.StagedBuildAttestationPayload{
		TenantID: value.TenantID, Digest: value.Digest, Size: value.Size, MediaType: value.MediaType,
		Reference: value.Reference(), StagingKey: value.StagingKey, FinalKey: value.FinalKey,
		Status: string(value.Status), FailureCode: value.FailureCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		FinalizedAt: cloneTimePtr(value.FinalizedAt), FailedAt: cloneTimePtr(value.FailedAt),
		OrphanedAt: cloneTimePtr(value.OrphanedAt),
	}
}

func stagedBuildAttestationPayloadFromReleaseContext(value releaseapp.StagedBuildAttestationPayload) ObjectPayload {
	return ObjectPayload{
		TenantID: value.TenantID, Digest: value.Digest, Size: value.Size, MediaType: value.MediaType,
		StagingKey: value.StagingKey, FinalKey: value.FinalKey, Status: ObjectPayloadStatus(value.Status),
		FailureCode: value.FailureCode, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
		FinalizedAt: cloneTimePtr(value.FinalizedAt), FailedAt: cloneTimePtr(value.FailedAt),
		OrphanedAt: cloneTimePtr(value.OrphanedAt),
	}
}

func releaseCandidateToReleaseContext(value domain.ReleaseCandidate) (releasedomain.ReleaseCandidate, error) {
	state, err := releasedomain.ParseReleaseCandidateState(value.State)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, releaseapp.ErrValidation
	}
	return releasedomain.ReleaseCandidate{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Name: value.Name, Revision: value.Revision,
		State: state, BuildIDs: append([]string(nil), value.BuildIDs...), ArtifactIDs: append([]string(nil), value.ArtifactIDs...),
		SBOMIDs: append([]string(nil), value.SBOMIDs...), ScanIDs: append([]string(nil), value.ScanIDs...),
		VEXIDs: append([]string(nil), value.VEXIDs...), ContractIDs: append([]string(nil), value.ContractIDs...),
		BundleIDs: append([]string(nil), value.BundleIDs...), SnapshotHash: value.SnapshotHash,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt, PromotedAt: cloneTimePtr(value.PromotedAt),
		RejectedAt: cloneTimePtr(value.RejectedAt),
	}, nil
}

func releaseCandidateFromReleaseContext(value releasedomain.ReleaseCandidate) domain.ReleaseCandidate {
	return domain.ReleaseCandidate{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, Name: value.Name, Revision: value.Revision,
		State: value.State.String(), BuildIDs: append([]string(nil), value.BuildIDs...), ArtifactIDs: append([]string(nil), value.ArtifactIDs...),
		SBOMIDs: append([]string(nil), value.SBOMIDs...), ScanIDs: append([]string(nil), value.ScanIDs...),
		VEXIDs: append([]string(nil), value.VEXIDs...), ContractIDs: append([]string(nil), value.ContractIDs...),
		BundleIDs: append([]string(nil), value.BundleIDs...), SnapshotHash: value.SnapshotHash,
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt, PromotedAt: cloneTimePtr(value.PromotedAt),
		RejectedAt: cloneTimePtr(value.RejectedAt),
	}
}

func containerImageToReleaseContext(value domain.ContainerImage) releasedomain.ContainerImage {
	return releasedomain.ContainerImage{
		ID: value.ID, TenantID: value.TenantID, ArtifactID: value.ArtifactID, Repository: value.Repository,
		Tag: value.Tag, Digest: value.Digest, Platform: value.Platform, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func containerImageFromReleaseContext(value releasedomain.ContainerImage) domain.ContainerImage {
	return domain.ContainerImage{
		ID: value.ID, TenantID: value.TenantID, ArtifactID: value.ArtifactID, Repository: value.Repository,
		Tag: value.Tag, Digest: value.Digest, Platform: value.Platform, SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func legacyReleaseToContext(value domain.Release) (releasedomain.Release, error) {
	result, err := domain.ReleaseToContextModel(value)
	if err != nil {
		return releasedomain.Release{}, releaseapp.ErrValidation
	}
	return result, nil
}

func toReleaseContextError(err error) error {
	if err == nil {
		return nil
	}
	if revision, ok := CurrentRevision(err); ok {
		return releaseapp.NewVersionConflict(revision)
	}
	switch {
	case errors.Is(err, ErrValidation):
		return releaseapp.ErrValidation
	case errors.Is(err, ErrForbidden):
		return releaseapp.ErrForbidden
	case errors.Is(err, ErrNotFound):
		return releaseapp.ErrNotFound
	case errors.Is(err, ErrConflict):
		return releaseapp.ErrConflict
	default:
		return err
	}
}

func fromReleaseContextError(err error) error {
	if err == nil {
		return nil
	}
	if revision, ok := releaseapp.CurrentRevision(err); ok {
		return NewVersionConflict(revision)
	}
	switch {
	case errors.Is(err, releaseapp.ErrValidation):
		return ErrValidation
	case errors.Is(err, releaseapp.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, releaseapp.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, releaseapp.ErrConflict):
		return ErrConflict
	default:
		return err
	}
}

func cloneReleaseBuildAttestationMap(values map[string]domain.BuildAttestation) map[string]domain.BuildAttestation {
	result := make(map[string]domain.BuildAttestation, len(values))
	for key, value := range values {
		result[key] = buildAttestationFromReleaseContext(buildAttestationToReleaseContext(value))
	}
	return result
}

func cloneAuditChainMap(values map[string][]domain.AuditChainEntry) map[string][]domain.AuditChainEntry {
	result := make(map[string][]domain.AuditChainEntry, len(values))
	for key, entries := range values {
		result[key] = append([]domain.AuditChainEntry(nil), entries...)
	}
	return result
}
