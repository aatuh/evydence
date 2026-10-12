package app

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

var _ operationsquery.DeploymentListReader = memoryDeploymentRepository{}

// These typed pages retain at most page-size+1 candidate coordinates after
// current ownership, filters and grants. They model keyset semantics, not
// native SQL work/transfer, byte budgets, row locks or durability.
func (r memoryDeploymentRepository) PageDeploymentEnvironments(ctx context.Context, req operationsquery.EnvironmentPageRequest) (appquery.Result[operationsdomain.DeploymentEnvironment], error) {
	var out appquery.Result[operationsdomain.DeploymentEnvironment]
	if req.TenantWide && len(req.AllowedProductIDs) != 0 || !req.TenantWide && len(req.AllowedProductIDs) == 0 {
		return out, ErrValidation
	}
	window, err := newMemoryDeploymentPageWindow(req.Page, req.After)
	if err != nil {
		return out, err
	}
	err = memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		for id, environment := range s.DeploymentEnvironments {
			if err := ctx.Err(); err != nil {
				return err
			}
			if environment.TenantID != req.TenantID || req.ProductID != "" && environment.ProductID != req.ProductID {
				continue
			}
			product, ok := s.Products[environment.ProductID]
			if !ok || product.ID != environment.ProductID || product.TenantID != req.TenantID || environment.ProductID == "" {
				continue
			}
			if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, product.ID) {
				continue
			}
			window.offer(id, environment.CreatedAt)
		}
		items := make([]operationsdomain.DeploymentEnvironment, 0, len(window.keys))
		for _, key := range window.keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			value := s.DeploymentEnvironments[key.id]
			if value.ID != key.id || value.ID == "" || !memoryGovernanceText(value.ID, 1024) || value.CreatedAt.IsZero() {
				return operationsquery.ErrInvalidProjection
			}
			items = append(items, operationsdomain.DeploymentEnvironment(value))
		}
		out = appquery.Result[operationsdomain.DeploymentEnvironment]{Items: items, Next: window.next()}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[operationsdomain.DeploymentEnvironment]{}, err
	}
	return out, nil
}

func (r memoryDeploymentRepository) PageDeployments(ctx context.Context, req operationsquery.DeploymentPageRequest) (appquery.Result[operationsquery.DeploymentPoint], error) {
	var out appquery.Result[operationsquery.DeploymentPoint]
	if req.TenantWide && (len(req.AllowedProductIDs) != 0 || len(req.AllowedReleaseIDs) != 0) || !req.TenantWide && len(req.AllowedProductIDs) == 0 && len(req.AllowedReleaseIDs) == 0 {
		return out, ErrValidation
	}
	window, err := newMemoryDeploymentPageWindow(req.Page, req.After)
	if err != nil {
		return out, err
	}
	err = memoryGovernanceRead(ctx, r.uow, req.TenantID, req.TenantID, func(s *MemoryUnitOfWorkSnapshot) error {
		for id, deployment := range s.DeploymentEvents {
			if err := ctx.Err(); err != nil {
				return err
			}
			if deployment.TenantID != req.TenantID || req.ReleaseID != "" && deployment.ReleaseID != req.ReleaseID || req.EnvironmentID != "" && deployment.EnvironmentID != req.EnvironmentID {
				continue
			}
			product, ok := memoryDeploymentProduct(s, req.TenantID, deployment)
			if !ok {
				continue
			}
			if !req.TenantWide && !slices.Contains(req.AllowedProductIDs, product) && !slices.Contains(req.AllowedReleaseIDs, deployment.ReleaseID) {
				continue
			}
			window.offer(id, deployment.CreatedAt)
		}
		items := make([]operationsquery.DeploymentPoint, 0, len(window.keys))
		for _, key := range window.keys {
			if err := ctx.Err(); err != nil {
				return err
			}
			deployment := s.DeploymentEvents[key.id]
			if deployment.ID != key.id || deployment.ID == "" || !memoryGovernanceText(deployment.ID, 1024) || deployment.CreatedAt.IsZero() {
				return operationsquery.ErrInvalidProjection
			}
			product, ok := memoryDeploymentProduct(s, req.TenantID, deployment)
			if !ok {
				return operationsquery.ErrInvalidProjection
			}
			value := operationsdomain.DeploymentEvent(deployment)
			value.ArtifactIDs = slices.Clone(deployment.ArtifactIDs)
			value.FinishedAt = cloneTimePtr(deployment.FinishedAt)
			items = append(items, operationsquery.DeploymentPoint{Deployment: value, ProductID: product})
		}
		out = appquery.Result[operationsquery.DeploymentPoint]{Items: items, Next: window.next()}
		if len(items) > req.Page.PageSize {
			out.Items = items[:req.Page.PageSize]
		}
		return ctx.Err()
	})
	if err != nil {
		return appquery.Result[operationsquery.DeploymentPoint]{}, err
	}
	return out, nil
}

type memoryDeploymentPageKey struct {
	id string
	at time.Time
}
type memoryDeploymentPageWindow struct {
	page  appquery.PageRequest
	after *memoryDeploymentPageKey
	keys  []memoryDeploymentPageKey
}

func newMemoryDeploymentPageWindow(page appquery.PageRequest, after *appquery.SortKey) (memoryDeploymentPageWindow, error) {
	w := memoryDeploymentPageWindow{page: page, keys: make([]memoryDeploymentPageKey, 0)}
	if err := appquery.Validate(page, after); err != nil {
		return w, err
	}
	if after != nil {
		key := memoryDeploymentPageKey{id: after.ID}
		if page.Sort == appquery.SortCreatedAt {
			at, err := time.Parse(time.RFC3339Nano, after.Value)
			if err != nil || at.UTC().Format(time.RFC3339Nano) != after.Value {
				return w, appquery.ErrInvalidCursor
			}
			key.at = at
		} else if after.Value != after.ID {
			return w, appquery.ErrInvalidCursor
		}
		w.after = &key
	}
	w.keys = make([]memoryDeploymentPageKey, 0, page.PageSize+1)
	return w, nil
}

func (w memoryDeploymentPageWindow) before(a, b memoryDeploymentPageKey) bool {
	comparison := 0
	if w.page.Sort == appquery.SortCreatedAt {
		comparison = a.at.Compare(b.at)
	}
	if comparison == 0 {
		comparison = strings.Compare(a.id, b.id)
	}
	if w.page.Direction == appquery.Descending {
		return comparison > 0
	}
	return comparison < 0
}

func (w *memoryDeploymentPageWindow) offer(id string, at time.Time) {
	key := memoryDeploymentPageKey{id: id, at: at}
	if w.after != nil && !w.before(*w.after, key) {
		return
	}
	position := sort.Search(len(w.keys), func(i int) bool { return w.before(key, w.keys[i]) })
	if position >= w.page.PageSize+1 {
		return
	}
	if len(w.keys) < w.page.PageSize+1 {
		w.keys = append(w.keys, memoryDeploymentPageKey{})
	}
	copy(w.keys[position+1:], w.keys[position:])
	w.keys[position] = key
}

func (w memoryDeploymentPageWindow) next() *appquery.SortKey {
	if len(w.keys) <= w.page.PageSize {
		return nil
	}
	last := w.keys[w.page.PageSize-1]
	key := appquery.RecordSortKey(last.id, last.at, w.page.Sort)
	return &key
}
