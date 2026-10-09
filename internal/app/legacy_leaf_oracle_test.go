package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
)

// Historical leaf facades retained unchanged for package-local regression
// assertions during aggregate retirement. They have no production or other
// package's test callers and are excluded from normal application builds.
// Supported API/worker paths use focused services, not these legacy oracles.

func (l *Ledger) HasTenants(ctx context.Context) bool {
	hasTenants, _ := l.identityCommands.HasTenants(ctx)
	return hasTenants
}

func (l *Ledger) MissingEvidenceReport(ctx context.Context, actor domain.Actor, releaseID string) (map[string]any, error) {
	eval, err := l.EvaluateRelease(ctx, actor, releaseID)
	if err != nil && !errors.Is(err, ErrVerificationFailed) {
		return nil, err
	}
	missing := []string{}
	for _, check := range eval.Checks {
		missing = append(missing, check.Missing...)
	}
	sort.Strings(missing)
	return map[string]any{
		"report_type":      "missing_evidence",
		"template_version": "missing-evidence.v1.0.0",
		"release_id":       releaseID,
		"result":           eval.Result,
		"missing":          missing,
		"assumptions":      []string{"This report supports compliance readiness and is not a legal compliance conclusion."},
		"limitations":      []string{"Missing evidence is based only on evidence recorded in this Evydence instance."},
	}, nil
}

func (l *Ledger) RevokeSigningKey(ctx context.Context, actor domain.Actor, keyID, reason string) (domain.SigningKey, error) {
	return l.RevokeSigningKeyWithPolicy(ctx, actor, keyID, SigningKeyRevocationInput{
		Reason:                   reason,
		Semantics:                domain.SigningKeyRevocationOrdinary,
		HistoricalValidityPolicy: domain.SigningKeyHistoricalValidityPreserve,
	})
}

func (l *Ledger) SearchEvidence(ctx context.Context, actor domain.Actor, in EvidenceSearchInput) ([]domain.EvidenceItem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return nil, err
	}
	if in.Limit <= 0 || in.Limit > 500 {
		in.Limit = 500
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.EvidenceItem{}
	for _, item := range l.evidence {
		if item.TenantID != actor.TenantID || !matchesEvidenceSearch(item, in) {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeEvidenceRead, refsForEvidence(item)) {
			continue
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > in.Limit {
		out = out[:in.Limit]
	}
	return out, nil
}

func (l *Ledger) UploadGitHubSourceSnapshot(ctx context.Context, actor domain.Actor, raw []byte) (map[string]any, error) {
	return l.uploadSourceSnapshot(ctx, actor, "github", raw)
}

func (l *Ledger) UploadGitLabSourceSnapshot(ctx context.Context, actor domain.Actor, raw []byte) (map[string]any, error) {
	return l.uploadSourceSnapshot(ctx, actor, "gitlab", raw)
}

type sourceSnapshot struct {
	ProjectID  string `json:"project_id"`
	Repository struct {
		FullName      string `json:"full_name"`
		CloneURL      string `json:"clone_url"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	Commit *struct {
		SHA         string    `json:"sha"`
		Author      string    `json:"author"`
		Message     string    `json:"message"`
		CommittedAt time.Time `json:"committed_at"`
	} `json:"commit,omitempty"`
	Branch *struct {
		Name           string `json:"name"`
		Protected      bool   `json:"protected"`
		ProtectionHash string `json:"protection_hash"`
	} `json:"branch,omitempty"`
	PullRequest *struct {
		ProviderID     string `json:"provider_id"`
		Title          string `json:"title"`
		State          string `json:"state"`
		SourceBranch   string `json:"source_branch"`
		TargetBranch   string `json:"target_branch"`
		ReviewDecision string `json:"review_decision"`
	} `json:"pull_request,omitempty"`
}

func (l *Ledger) uploadSourceSnapshot(ctx context.Context, actor domain.Actor, provider string, raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > 2<<20 {
		return nil, ErrValidation
	}
	var snapshot sourceSnapshot
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snapshot); err != nil {
		return nil, ErrValidation
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrValidation
	}
	repo, err := l.CreateSourceRepository(ctx, actor, CreateRepositoryInput{
		ProjectID:     snapshot.ProjectID,
		Provider:      provider,
		FullName:      snapshot.Repository.FullName,
		CloneURL:      snapshot.Repository.CloneURL,
		DefaultBranch: snapshot.Repository.DefaultBranch,
	})
	if err != nil {
		return nil, err
	}
	var commit domain.SourceCommit
	if snapshot.Commit != nil {
		commit, err = l.RecordSourceCommit(ctx, actor, RecordCommitInput{
			RepositoryID: repo.ID,
			SHA:          snapshot.Commit.SHA,
			Author:       snapshot.Commit.Author,
			Message:      snapshot.Commit.Message,
			CommittedAt:  snapshot.Commit.CommittedAt,
		})
		if err != nil {
			return nil, err
		}
	}
	var branch domain.SourceBranch
	if snapshot.Branch != nil {
		branch, err = l.UpsertSourceBranch(ctx, actor, UpsertBranchInput{
			RepositoryID:   repo.ID,
			Name:           snapshot.Branch.Name,
			HeadCommitID:   commit.ID,
			Protected:      snapshot.Branch.Protected,
			ProtectionHash: snapshot.Branch.ProtectionHash,
		})
		if err != nil {
			return nil, err
		}
	}
	var pr domain.PullRequest
	if snapshot.PullRequest != nil {
		pr, err = l.RecordPullRequest(ctx, actor, RecordPullRequestInput{
			RepositoryID:   repo.ID,
			Provider:       provider,
			ProviderID:     snapshot.PullRequest.ProviderID,
			Title:          snapshot.PullRequest.Title,
			State:          snapshot.PullRequest.State,
			SourceBranch:   snapshot.PullRequest.SourceBranch,
			TargetBranch:   snapshot.PullRequest.TargetBranch,
			HeadCommitID:   commit.ID,
			ReviewDecision: snapshot.PullRequest.ReviewDecision,
		})
		if err != nil {
			return nil, err
		}
	}
	return map[string]any{"repository": repo, "commit": commit, "branch": branch, "pull_request": pr}, nil
}

func (l *Ledger) UploadAPISecurityScan(ctx context.Context, actor domain.Actor, in UploadSecurityScanInput) (domain.SecurityScan, error) {
	value, err := l.evidenceCommands.UploadAPISecurityScan(ctx, actor, evidenceapp.UploadSecurityScanInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, ArtifactID: in.ArtifactID, Category: in.Category,
		Format: in.Format, Scanner: in.Scanner, TargetRef: in.TargetRef, Raw: append([]byte(nil), in.Raw...),
	})
	return securityScanFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) UploadSPDXSBOM(ctx context.Context, actor domain.Actor, releaseID, artifactID string, raw []byte) (domain.SBOM, error) {
	value, err := l.evidenceCommands.UploadSPDXSBOM(ctx, actor, releaseID, artifactID, raw)
	return sbomFromEvidenceContext(value), fromEvidenceContextError(err)
}

func (l *Ledger) ensureWaiverScopeLocked(tenantID, scope, id string) error {
	switch scope {
	case "release":
		item, ok := l.releases[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "control":
		item, ok := l.controls[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "policy":
		item, ok := l.customPolicies[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "finding":
		if _, _, ok := l.findFindingLocked(tenantID, id); !ok {
			return ErrNotFound
		}
	}
	return nil
}

func (l *Ledger) ensureApprovalSubjectLocked(tenantID, subject, id string) error {
	switch subject {
	case "release":
		item, ok := l.releases[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "contract_diff":
		item, ok := l.contractDiffs[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "waiver":
		item, ok := l.waivers[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	case "security_review":
		item, ok := l.manualDocs[id]
		if !ok || item.TenantID != tenantID || item.DocumentType != "security_review" {
			return ErrNotFound
		}
	case "customer_package":
		item, ok := l.customerPackages[id]
		if !ok || item.TenantID != tenantID {
			return ErrNotFound
		}
	}
	return nil
}
