package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

const (
	lifecycleAmendment       = "amendment"
	lifecycleRedaction       = "redaction"
	lifecycleTombstone       = "tombstone"
	lifecycleRetentionMarker = "retention_marker"

	candidateOpen     = "open"
	candidatePromoted = "promoted"
	candidateRejected = "rejected"
)

type EvidenceSearchInput struct {
	ProductID          string
	ProjectID          string
	ReleaseID          string
	BuildID            string
	DeploymentID       string
	Type               string
	Subtype            string
	SourceSystem       string
	CollectorID        string
	VerificationStatus string
	SubjectType        string
	SubjectID          string
	Tag                string
	CreatedAfter       time.Time
	CreatedBefore      time.Time
	Limit              int
}

type RecordEvidenceLifecycleInput struct {
	Action        string
	Reason        string
	Details       map[string]any
	ReplacementID string
}

type CreateReleaseCandidateInput struct {
	ReleaseID   string
	Name        string
	BuildIDs    []string
	ArtifactIDs []string
	SBOMIDs     []string
	ScanIDs     []string
	VEXIDs      []string
	ContractIDs []string
	BundleIDs   []string
}

type RegisterContainerImageInput struct {
	ArtifactID string
	Repository string
	Tag        string
	Digest     string
	Platform   string
}

func (l *Ledger) RecordEvidenceLifecycleEvent(ctx context.Context, actor domain.Actor, evidenceID string, in RecordEvidenceLifecycleInput) (domain.EvidenceLifecycleEvent, error) {
	event, err := l.evidenceCommands.RecordLifecycleEvent(ctx, actor, evidenceID, evidenceapp.RecordLifecycleInput{
		Action: in.Action, Reason: in.Reason, Details: cloneMap(in.Details), ReplacementID: in.ReplacementID,
	})
	return lifecycleFromEvidenceContext(event), fromEvidenceContextError(err)
}

func (l *Ledger) CreateReleaseCandidate(ctx context.Context, actor domain.Actor, in CreateReleaseCandidateInput) (domain.ReleaseCandidate, error) {
	value, err := l.releaseCommands.CreateReleaseCandidate(ctx, actor, releaseapp.CreateReleaseCandidateInput{
		ReleaseID: in.ReleaseID, Name: in.Name, BuildIDs: append([]string(nil), in.BuildIDs...),
		ArtifactIDs: append([]string(nil), in.ArtifactIDs...), SBOMIDs: append([]string(nil), in.SBOMIDs...),
		ScanIDs: append([]string(nil), in.ScanIDs...), VEXIDs: append([]string(nil), in.VEXIDs...),
		ContractIDs: append([]string(nil), in.ContractIDs...), BundleIDs: append([]string(nil), in.BundleIDs...),
	})
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) UpdateReleaseCandidateState(ctx context.Context, actor domain.Actor, id, state, reason string, expectedRevision int64) (domain.ReleaseCandidate, error) {
	value, err := l.releaseCommands.UpdateReleaseCandidateState(ctx, actor, id, state, reason, expectedRevision)
	return releaseCandidateFromReleaseContext(value), fromReleaseContextError(err)
}

func (l *Ledger) RegisterContainerImage(ctx context.Context, actor domain.Actor, in RegisterContainerImageInput) (domain.ContainerImage, error) {
	value, err := l.releaseCommands.RegisterContainerImage(ctx, actor, releaseapp.RegisterContainerImageInput{
		ArtifactID: in.ArtifactID, Repository: in.Repository, Tag: in.Tag, Digest: in.Digest, Platform: in.Platform,
	})
	return containerImageFromReleaseContext(value), fromReleaseContextError(err)
}

func matchesEvidenceSearch(item domain.EvidenceItem, in EvidenceSearchInput) bool {
	if in.ProductID != "" && item.ProductID != in.ProductID {
		return false
	}
	if in.ProjectID != "" && item.ProjectID != in.ProjectID {
		return false
	}
	if in.ReleaseID != "" && item.ReleaseID != in.ReleaseID {
		return false
	}
	if in.BuildID != "" && item.BuildID != in.BuildID {
		return false
	}
	if in.DeploymentID != "" && item.DeploymentID != in.DeploymentID {
		return false
	}
	if in.Type != "" && item.Type != in.Type {
		return false
	}
	if in.Subtype != "" && item.Subtype != in.Subtype {
		return false
	}
	if in.SourceSystem != "" && item.SourceSystem != in.SourceSystem {
		return false
	}
	if in.CollectorID != "" && item.CollectorID != in.CollectorID {
		return false
	}
	if in.VerificationStatus != "" && item.VerificationStatus != in.VerificationStatus {
		return false
	}
	if !in.CreatedAfter.IsZero() && item.CreatedAt.Before(in.CreatedAfter) {
		return false
	}
	if !in.CreatedBefore.IsZero() && item.CreatedAt.After(in.CreatedBefore) {
		return false
	}
	if in.Tag != "" && !containsString(item.Tags, in.Tag) {
		return false
	}
	if in.SubjectType != "" || in.SubjectID != "" {
		matched := false
		for _, ref := range item.SubjectRefs {
			if in.SubjectType != "" && ref.Type != in.SubjectType {
				continue
			}
			if in.SubjectID != "" && ref.ID != in.SubjectID && ref.Digest != in.SubjectID {
				continue
			}
			matched = true
			break
		}
		if !matched {
			return false
		}
	}
	return true
}

func validLifecycleAction(action string) bool {
	switch action {
	case lifecycleAmendment, lifecycleRedaction, lifecycleTombstone, lifecycleRetentionMarker:
		return true
	default:
		return false
	}
}

func (l *Ledger) validateCandidateRefsLocked(tenantID, releaseID string, in CreateReleaseCandidateInput) error {
	for _, id := range in.BuildIDs {
		item, ok := l.buildRuns[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.ArtifactIDs {
		item, ok := l.artifacts[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	}
	for _, id := range in.SBOMIDs {
		item, ok := l.sboms[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.ScanIDs {
		item, ok := l.scans[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.VEXIDs {
		item, ok := l.vexDocuments[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.ContractIDs {
		item, ok := l.contracts[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	for _, id := range in.BundleIDs {
		item, ok := l.bundles[strings.TrimSpace(id)]
		if !ok || item.TenantID != tenantID || item.ReleaseID != releaseID {
			return ErrNotFound
		}
	}
	return nil
}

func validPullRequestState(state string) bool {
	switch state {
	case "open", "closed", "merged":
		return true
	default:
		return false
	}
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
