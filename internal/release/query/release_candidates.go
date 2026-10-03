package query

import (
	"context"
	"errors"
	"sort"
	"strings"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// ReleaseCandidatePoint includes only the current product coordinate needed
// to authorize a candidate through its tenant-owned release.
type ReleaseCandidatePoint struct {
	Candidate releasedomain.ReleaseCandidate
	ProductID string
}

// ReleaseCandidatePageRequest carries service-derived visibility, which the
// SQL reader must apply before the keyset limit.
type ReleaseCandidatePageRequest struct {
	TenantID          string
	ReleaseID         string
	TenantWide        bool
	AllowedProductIDs []string
	AllowedReleaseIDs []string
	Page              appquery.PageRequest
	After             *appquery.SortKey
}

type ReleaseCandidateReader interface {
	GetReleaseCandidatePoint(context.Context, string, string) (ReleaseCandidatePoint, error)
	PageReleaseCandidates(context.Context, ReleaseCandidatePageRequest) (appquery.Result[ReleaseCandidatePoint], error)
}

type ReleaseCandidates struct {
	reader     ReleaseCandidateReader
	authorizer application.Authorizer
}

func NewReleaseCandidates(reader ReleaseCandidateReader, authorizer application.Authorizer) (*ReleaseCandidates, error) {
	if reader == nil || authorizer == nil {
		return nil, ErrValidation
	}
	return &ReleaseCandidates{reader: reader, authorizer: authorizer}, nil
}

func (s *ReleaseCandidates) GetReleaseCandidate(ctx context.Context, actor identitydomain.Actor, id string) (releasedomain.ReleaseCandidate, error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return releasedomain.ReleaseCandidate{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, ScopeOnly: true}); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	point, err := s.reader.GetReleaseCandidatePoint(ctx, actor.TenantID, id)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	candidate := point.Candidate
	if candidate.ID != id || candidate.TenantID != actor.TenantID || candidate.ReleaseID == "" || point.ProductID == "" {
		return releasedomain.ReleaseCandidate{}, ErrNotFound
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, Resources: application.ResourceReferences{ProductID: point.ProductID, ReleaseID: candidate.ReleaseID}}); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func (s *ReleaseCandidates) ListPage(ctx context.Context, actor identitydomain.Actor, releaseID string, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[releasedomain.ReleaseCandidate], error) {
	if s == nil || ctx == nil || strings.TrimSpace(actor.TenantID) == "" {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, ErrValidation
	}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, ScopeOnly: true}); err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	}
	request := ReleaseCandidatePageRequest{TenantID: actor.TenantID, ReleaseID: strings.TrimSpace(releaseID), Page: page, After: after}
	if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, TenantWide: true}); err == nil {
		request.TenantWide = true
	} else if !errors.Is(err, application.ErrForbidden) {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	} else {
		products := make(map[string]struct{})
		releases := make(map[string]struct{})
		for _, grant := range actor.ResourceGrants {
			id := grant.ResourceID
			if strings.TrimSpace(id) == "" || !catalogGrantHasScope(grant, scopeReleaseRead) {
				continue
			}
			switch grant.ResourceType {
			case "product":
				products[id] = struct{}{}
			case "release":
				releases[id] = struct{}{}
			}
		}
		for id := range products {
			request.AllowedProductIDs = append(request.AllowedProductIDs, id)
		}
		for id := range releases {
			request.AllowedReleaseIDs = append(request.AllowedReleaseIDs, id)
		}
		sort.Strings(request.AllowedProductIDs)
		sort.Strings(request.AllowedReleaseIDs)
		if len(request.AllowedProductIDs) == 0 && len(request.AllowedReleaseIDs) == 0 {
			return appquery.Result[releasedomain.ReleaseCandidate]{Items: []releasedomain.ReleaseCandidate{}}, nil
		}
	}
	result, err := s.reader.PageReleaseCandidates(ctx, request)
	if err != nil {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, err
	}
	if len(result.Items) > page.PageSize || result.Next != nil && (len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].Candidate.ID, result.Items[len(result.Items)-1].Candidate.CreatedAt, page.Sort)) {
		return appquery.Result[releasedomain.ReleaseCandidate]{}, ErrInvalidProjection
	}
	items := make([]releasedomain.ReleaseCandidate, 0, len(result.Items))
	for _, point := range result.Items {
		candidate := point.Candidate
		if candidate.ID == "" || candidate.TenantID != actor.TenantID || candidate.ReleaseID == "" || point.ProductID == "" || request.ReleaseID != "" && candidate.ReleaseID != request.ReleaseID {
			return appquery.Result[releasedomain.ReleaseCandidate]{}, ErrInvalidProjection
		}
		if err := s.authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: scopeReleaseRead, Resources: application.ResourceReferences{ProductID: point.ProductID, ReleaseID: candidate.ReleaseID}}); err != nil {
			return appquery.Result[releasedomain.ReleaseCandidate]{}, ErrInvalidProjection
		}
		items = append(items, candidate)
	}
	return appquery.Result[releasedomain.ReleaseCandidate]{Items: items, Next: result.Next}, nil
}
