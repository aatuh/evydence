package app

import (
	"context"
	"fmt"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
)

// Historical aggregate list/page behavior remains only as unchanged test
// oracles. Focused fixtures use current typed repository pages instead.
func (l *Ledger) ListEvidence(ctx context.Context, actor domain.Actor, releaseID, typ string) ([]domain.EvidenceItem, error) {
	values, err := l.evidenceCommands.ListEvidence(ctx, actor, releaseID, typ)
	if err != nil {
		return nil, fromEvidenceContextError(err)
	}
	result := make([]domain.EvidenceItem, 0, len(values))
	for _, value := range values {
		result = append(result, evidenceFromContext(value))
	}
	return result, nil
}

// ListEvidencePage uses an indexed persistence query for tenant-wide actors.
// Production stores can also scan bounded, snapshot-consistent batches for
// granular human grants, authorizing rows before they contribute to a page.
// Local-memory stores retain the compatibility in-process query path.
func (l *Ledger) ListEvidencePage(ctx context.Context, actor domain.Actor, request EvidencePageRequest) (appquery.Result[domain.EvidenceItem], error) {
	if err := ctx.Err(); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if request.TenantID != "" && request.TenantID != actor.TenantID {
		return appquery.Result[domain.EvidenceItem]{}, ErrForbidden
	}
	request.TenantID = actor.TenantID
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	if l.evidencePages != nil && actorHasTenantWideRead(actor, ScopeEvidenceRead) {
		page, err := l.evidencePages.ListEvidencePage(ctx, request)
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validateEvidencePageProjection(ctx, actor, request.Page, page, false); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validatePagedParserNormalizations(ctx, actor.TenantID, page.Items); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		return page, nil
	}
	if pages, ok := l.evidencePages.(EvidenceVisiblePageStore); ok {
		if err := l.refreshEvidencePageAuthorization(ctx, actor.TenantID); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		page, err := pages.ListEvidencePageVisible(ctx, request, l.evidencePageVisibility(ctx, actor))
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validateEvidencePageProjection(ctx, actor, request.Page, page, true); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validatePagedParserNormalizations(ctx, actor.TenantID, page.Items); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		return page, nil
	}
	items, err := l.ListEvidence(ctx, actor, request.ReleaseID, request.Type)
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	page, err := appquery.Page(items, request.Page, request.After, func(item domain.EvidenceItem, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(item.ID, item.CreatedAt, sort)
	})
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	return page, nil
}

func actorHasTenantWideRead(actor domain.Actor, scope string) bool {
	if !humanSessionActor(actor) {
		return true
	}
	for _, grant := range actor.ResourceGrants {
		if grantHasScope(grant, scope) && (grant.ResourceType == "" || grant.ResourceType == "tenant") && (grant.ResourceID == "" || grant.ResourceID == actor.TenantID) {
			return true
		}
	}
	return false
}

// SearchEvidencePage applies the complete search predicate before paging. It
// does not use EvidenceSearchInput.Limit because cursor page bounds are kept
// separate from matching semantics.
func (l *Ledger) SearchEvidencePage(ctx context.Context, actor domain.Actor, request EvidenceSearchPageRequest) (appquery.Result[domain.EvidenceItem], error) {
	if err := ctx.Err(); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	if request.TenantID != "" && request.TenantID != actor.TenantID {
		return appquery.Result[domain.EvidenceItem]{}, ErrForbidden
	}
	if err := appquery.Validate(request.Page, request.After); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	request.TenantID = actor.TenantID
	request.Filter.Limit = 0
	if l.evidencePages != nil && actorHasTenantWideRead(actor, ScopeEvidenceRead) {
		page, err := l.evidencePages.SearchEvidencePage(ctx, request)
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validateEvidencePageProjection(ctx, actor, request.Page, page, false); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validatePagedParserNormalizations(ctx, actor.TenantID, page.Items); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		return page, nil
	}
	if pages, ok := l.evidencePages.(EvidenceVisiblePageStore); ok {
		if err := l.refreshEvidencePageAuthorization(ctx, actor.TenantID); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		page, err := pages.SearchEvidencePageVisible(ctx, request, l.evidencePageVisibility(ctx, actor))
		if err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validateEvidencePageProjection(ctx, actor, request.Page, page, true); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		if err := l.validatePagedParserNormalizations(ctx, actor.TenantID, page.Items); err != nil {
			return appquery.Result[domain.EvidenceItem]{}, err
		}
		return page, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return appquery.Result[domain.EvidenceItem]{}, err
	}
	items := make([]domain.EvidenceItem, 0)
	for _, item := range l.evidence {
		if item.TenantID != actor.TenantID || !matchesEvidenceSearch(item, request.Filter) {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeEvidenceRead, refsForEvidence(item)) {
			continue
		}
		items = append(items, item)
	}
	page, err := appquery.Page(items, request.Page, request.After, func(item domain.EvidenceItem, sort appquery.Sort) appquery.SortKey {
		return appquery.RecordSortKey(item.ID, item.CreatedAt, sort)
	})
	if err != nil {
		return appquery.Result[domain.EvidenceItem]{}, ErrValidation
	}
	return page, nil
}

func (l *Ledger) refreshEvidencePageAuthorization(ctx context.Context, tenantID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refreshWorkerProjectionLocked(ctx, tenantID)
}

func (l *Ledger) evidencePageVisibility(ctx context.Context, actor domain.Actor) EvidenceVisibility {
	return func(item domain.EvidenceItem) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if item.ID == "" || item.TenantID != actor.TenantID {
			return false, evidencePageConflict("tenant")
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		return l.resourceAllowedLocked(actor, ScopeEvidenceRead, refsForEvidence(item)), nil
	}
}

func (l *Ledger) validateEvidencePageProjection(ctx context.Context, actor domain.Actor, request appquery.PageRequest, page appquery.Result[domain.EvidenceItem], granular bool) error {
	if len(page.Items) > request.PageSize {
		return evidencePageConflict("size")
	}
	seen := make(map[string]struct{}, len(page.Items))
	visible := l.evidencePageVisibility(ctx, actor)
	for _, item := range page.Items {
		if item.ID == "" || item.TenantID != actor.TenantID {
			return evidencePageConflict("tenant")
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return evidencePageConflict("duplicate")
		}
		seen[item.ID] = struct{}{}
		if granular {
			allowed, err := visible(item)
			if err != nil {
				return err
			}
			if !allowed {
				return evidencePageConflict("visibility")
			}
		}
	}
	if page.Next != nil {
		if len(page.Items) == 0 || *page.Next != appquery.RecordSortKey(page.Items[len(page.Items)-1].ID, page.Items[len(page.Items)-1].CreatedAt, request.Sort) {
			return evidencePageConflict("cursor")
		}
	}
	return nil
}

func evidencePageConflict(subject string) error {
	return fmt.Errorf("invalid evidence page %s: %w", subject, ErrConflict)
}

func (l *Ledger) validatePagedParserNormalizations(ctx context.Context, tenantID string, items []domain.EvidenceItem) error {
	hasParserNormalization := false
	for _, item := range items {
		if item.Type == "parser_normalization" {
			hasParserNormalization = true
			break
		}
	}
	if !hasParserNormalization {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, tenantID); err != nil {
		return err
	}
	for _, item := range items {
		if item.Type != "parser_normalization" {
			continue
		}
		cached, ok := l.evidence[item.ID]
		if !ok || cached.TenantID != tenantID || !sameParserNormalizationEvidence(cached, item) {
			return projectionConflict("parser normalization page row")
		}
		source, ok := l.evidence[parserReplayOf(item.Metadata)]
		if !ok {
			return projectionConflict("parser normalization page source")
		}
		var entry domain.AuditChainEntry
		matches := 0
		for _, candidate := range l.chain[tenantID] {
			if candidate.ID == item.ChainEntryID {
				entry = candidate
				matches++
			}
		}
		if matches != 1 {
			return projectionConflict("parser normalization page audit")
		}
		if err := ValidateParserNormalizationRecord(tenantID, item, source, entry); err != nil {
			return err
		}
	}
	return nil
}
