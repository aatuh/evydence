package app

import (
	"time"

	"github.com/aatuh/evydence/internal/domain"
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
