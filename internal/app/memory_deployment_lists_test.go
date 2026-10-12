package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

func memoryDeploymentListsFixture(t *testing.T) (*memoryUnitOfWork, operationsquery.DeploymentListReader) {
	t.Helper()
	tx, _, _ := memoryDeploymentPointFixture(t)
	reader, ok := tx.Repositories().Deployments.(operationsquery.DeploymentListReader)
	if !ok {
		t.Fatal("memory deployment repository lacks focused list reader")
	}
	environment := tx.state.DeploymentEnvironments["environment"]
	environment.Name, environment.Kind, environment.SchemaVersion = "Production", "production", "1"
	environment.CreatedAt = fixedNow()
	tx.state.DeploymentEnvironments[environment.ID] = environment
	return tx, reader
}

func TestMemoryDeploymentListsFilterBeforeLimitAndDetachPublicFields(t *testing.T) {
	tx, reader := memoryDeploymentListsFixture(t)
	template := tx.state.DeploymentEvents["deployment"]
	delete(tx.state.DeploymentEvents, "deployment")
	for _, id := range []string{"a", "b", "c"} {
		v := template
		v.ID = id
		tx.state.DeploymentEvents[id] = v
	}
	foreignEnv := domain.DeploymentEnvironment{ID: "0-foreign", TenantID: "foreign", ProductID: "foreign-product", Name: "foreign", CreatedAt: fixedNow()}
	tx.state.DeploymentEnvironments[foreignEnv.ID] = foreignEnv
	privateEnv := domain.DeploymentEnvironment{ID: "0-private", TenantID: "tenant", ProductID: "private-product", Name: "private", CreatedAt: fixedNow()}
	tx.state.Products["private-product"] = domain.Product{ID: "private-product", TenantID: "tenant"}
	tx.state.Releases["private-release"] = domain.Release{ID: "private-release", TenantID: "tenant", ProductID: "private-product"}
	tx.state.DeploymentEnvironments[privateEnv.ID] = privateEnv
	for _, env := range []domain.DeploymentEnvironment{privateEnv, foreignEnv} {
		v := template
		v.ID = env.ID
		v.TenantID = env.TenantID
		v.EnvironmentID = env.ID
		v.ReleaseID = strings.TrimSuffix(env.ProductID, "-product") + "-release"
		tx.state.DeploymentEvents[v.ID] = v
	}
	bad := template
	bad.ID = "0-dangling"
	bad.EnvironmentID = "missing"
	tx.state.DeploymentEvents[bad.ID] = bad
	bad.ID, bad.EnvironmentID, bad.ReleaseID = "0-cross-product", "environment", "private-release"
	tx.state.DeploymentEvents[bad.ID] = bad
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	envs, err := reader.PageDeploymentEnvironments(t.Context(), operationsquery.EnvironmentPageRequest{TenantID: "tenant", AllowedProductIDs: []string{"tenant-product"}, Page: page})
	if err != nil || !reflect.DeepEqual(envs.Items, []operationsdomain.DeploymentEnvironment{operationsdomain.DeploymentEnvironment(tx.state.DeploymentEnvironments["environment"])}) || envs.Next != nil {
		t.Fatal("environment visibility was applied after limit or changed DTO", err)
	}
	req := operationsquery.DeploymentPageRequest{TenantID: "tenant", AllowedReleaseIDs: []string{"tenant-release"}, Page: page}
	deps, err := reader.PageDeployments(t.Context(), req)
	want := template
	want.ID = "a"
	if err != nil || len(deps.Items) != 1 || !reflect.DeepEqual(deps.Items[0], operationsquery.DeploymentPoint{Deployment: operationsdomain.DeploymentEvent(want), ProductID: "tenant-product"}) || deps.Next == nil || deps.Next.ID != "a" {
		t.Fatal("deployment visibility/current parent filtering was applied after limit or changed DTO", err)
	}
	deps.Items[0].Deployment.ArtifactIDs[0] = "modified"
	*deps.Items[0].Deployment.FinishedAt = deps.Items[0].Deployment.FinishedAt.Add(time.Hour)
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("page exposed aliases or changed repository state")
	}
	req.EnvironmentID = privateEnv.ID
	if v, err := reader.PageDeployments(t.Context(), req); err != nil || len(v.Items) != 0 || v.Next != nil {
		t.Fatal("environment filter crossed current release visibility", err)
	}
	req.EnvironmentID = ""
	req.ReleaseID = "private-release"
	if v, err := reader.PageDeployments(t.Context(), req); err != nil || len(v.Items) != 0 {
		t.Fatal("release filter crossed current visibility", err)
	}
	if v, err := reader.PageDeploymentEnvironments(t.Context(), operationsquery.EnvironmentPageRequest{TenantID: "tenant", ProductID: privateEnv.ProductID, AllowedProductIDs: []string{"tenant-product"}, Page: page}); err != nil || len(v.Items) != 0 {
		t.Fatal("product filter crossed environment visibility", err)
	}
}

func TestMemoryDeploymentListsTraverseFiveHundredRecordsInEveryOrder(t *testing.T) {
	tx, reader := memoryDeploymentListsFixture(t)
	template := tx.state.DeploymentEvents["deployment"]
	tx.state.DeploymentEvents = map[string]domain.DeploymentEvent{}
	tx.state.DeploymentEnvironments = map[string]domain.DeploymentEnvironment{}
	for i := range 501 {
		id := fmt.Sprintf("record-%03d", i)
		at := fixedNow().Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.DeploymentEnvironments[id] = domain.DeploymentEnvironment{ID: id, TenantID: "tenant", ProductID: "tenant-product", Name: id, Kind: "production", SchemaVersion: "1", CreatedAt: at}
		v := template
		v.ID = id
		v.EnvironmentID = id
		v.CreatedAt = at
		tx.state.DeploymentEvents[id] = v
	}
	for _, sortBy := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			for _, events := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/events=%t", sortBy, direction, events), func(t *testing.T) {
					page := appquery.PageRequest{PageSize: 7, Sort: sortBy, Direction: direction}
					var after *appquery.SortKey
					var got []string
					for count := 0; count < 80; count++ {
						var next *appquery.SortKey
						var last appquery.SortKey
						if events {
							result, err := reader.PageDeployments(t.Context(), operationsquery.DeploymentPageRequest{TenantID: "tenant", TenantWide: true, Page: page, After: after})
							if err != nil || len(result.Items) > 7 {
								t.Fatal("deployment page failed", err)
							}
							for _, point := range result.Items {
								v := point.Deployment
								got = append(got, v.ID)
								last = appquery.RecordSortKey(v.ID, v.CreatedAt, sortBy)
							}
							next = result.Next
						} else {
							result, err := reader.PageDeploymentEnvironments(t.Context(), operationsquery.EnvironmentPageRequest{TenantID: "tenant", TenantWide: true, Page: page, After: after})
							if err != nil || len(result.Items) > 7 {
								t.Fatal("environment page failed", err)
							}
							for _, v := range result.Items {
								got = append(got, v.ID)
								last = appquery.RecordSortKey(v.ID, v.CreatedAt, sortBy)
							}
							next = result.Next
						}
						if next == nil {
							break
						}
						if *next != last {
							t.Fatal("cursor was not final returned record")
						}
						after = next
					}
					want := make([]string, 501)
					for i := range want {
						want[i] = fmt.Sprintf("record-%03d", i)
					}
					if sortBy == appquery.SortCreatedAt {
						slices.SortFunc(want, func(a, b string) int {
							comparison := tx.state.DeploymentEnvironments[a].CreatedAt.Compare(tx.state.DeploymentEnvironments[b].CreatedAt)
							if comparison == 0 {
								comparison = strings.Compare(a, b)
							}
							return comparison
						})
					}
					if direction == appquery.Descending {
						slices.Reverse(want)
					}
					if !slices.Equal(got, want) {
						t.Fatal("page traversal omitted, duplicated or misordered records", len(got))
					}
				})
			}
		}
	}
}

func TestMemoryDeploymentListsUseKeysetsAfterDeletionAndValidateSelectedLookahead(t *testing.T) {
	tx, reader := memoryDeploymentListsFixture(t)
	template := tx.state.DeploymentEvents["deployment"]
	delete(tx.state.DeploymentEvents, "deployment")
	base := tx.state.DeploymentEnvironments["environment"]
	delete(tx.state.DeploymentEnvironments, "environment")
	for _, id := range []string{"a", "b", "c"} {
		e := base
		e.ID = id
		e.CreatedAt = fixedNow()
		tx.state.DeploymentEnvironments[id] = e
		v := template
		v.ID = id
		v.EnvironmentID = id
		v.CreatedAt = fixedNow()
		tx.state.DeploymentEvents[id] = v
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	ereq := operationsquery.EnvironmentPageRequest{TenantID: "tenant", TenantWide: true, Page: page}
	dreq := operationsquery.DeploymentPageRequest{TenantID: "tenant", TenantWide: true, Page: page}
	e, err := reader.PageDeploymentEnvironments(t.Context(), ereq)
	if err != nil || e.Next == nil {
		t.Fatal(err)
	}
	d, err := reader.PageDeployments(t.Context(), dreq)
	if err != nil || d.Next == nil {
		t.Fatal(err)
	}
	bad := tx.state.DeploymentEvents["c"]
	bad.ID = "bad"
	tx.state.DeploymentEvents["c"] = bad
	if _, err := reader.PageDeployments(t.Context(), dreq); err != nil {
		t.Fatal("unselected corruption affected earlier page", err)
	}
	delete(tx.state.DeploymentEnvironments, "a")
	delete(tx.state.DeploymentEvents, "a")
	ereq.After = e.Next
	dreq.After = d.Next
	if v, err := reader.PageDeploymentEnvironments(t.Context(), ereq); err != nil || len(v.Items) != 1 || v.Items[0].ID != "b" {
		t.Fatal("deleted cursor prevented environment keyset continuation", err)
	}
	if v, err := reader.PageDeployments(t.Context(), dreq); !errors.Is(err, operationsquery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[operationsquery.DeploymentPoint]{}) {
		t.Fatal("invalid selected deployment lookahead returned partial page", err)
	}
	bad.ID = "c"
	tx.state.DeploymentEvents["c"] = bad
	if v, err := reader.PageDeployments(t.Context(), dreq); err != nil || len(v.Items) != 1 || v.Items[0].Deployment.ID != "b" {
		t.Fatal("deleted cursor prevented deployment keyset continuation", err)
	}
	badEnv := tx.state.DeploymentEnvironments["c"]
	badEnv.ID = "bad"
	tx.state.DeploymentEnvironments["c"] = badEnv
	if v, err := reader.PageDeploymentEnvironments(t.Context(), ereq); !errors.Is(err, operationsquery.ErrInvalidProjection) || !reflect.DeepEqual(v, appquery.Result[operationsdomain.DeploymentEnvironment]{}) {
		t.Fatal("invalid selected environment lookahead returned partial page", err)
	}
}

func TestMemoryDeploymentListsRejectInvalidReads(t *testing.T) {
	tx, reader := memoryDeploymentListsFixture(t)
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	ereq := operationsquery.EnvironmentPageRequest{TenantID: "tenant", TenantWide: true, Page: page}
	dreq := operationsquery.DeploymentPageRequest{TenantID: "tenant", TenantWide: true, Page: page}
	for _, tc := range []struct {
		sort appquery.Sort
		key  appquery.SortKey
	}{{appquery.SortID, appquery.SortKey{ID: "a", Value: "different"}}, {appquery.SortCreatedAt, appquery.SortKey{ID: "a", Value: "not-time"}}, {appquery.SortCreatedAt, appquery.SortKey{ID: "a", Value: "2026-10-09T12:00:00+00:00"}}} {
		ereq.Page.Sort, dreq.Page.Sort = tc.sort, tc.sort
		ereq.After, dreq.After = &tc.key, &tc.key
		if v, err := reader.PageDeploymentEnvironments(t.Context(), ereq); !errors.Is(err, appquery.ErrInvalidCursor) || !reflect.DeepEqual(v, appquery.Result[operationsdomain.DeploymentEnvironment]{}) {
			t.Fatal("invalid environment cursor returned data", err)
		}
		if v, err := reader.PageDeployments(t.Context(), dreq); !errors.Is(err, appquery.ErrInvalidCursor) || !reflect.DeepEqual(v, appquery.Result[operationsquery.DeploymentPoint]{}) {
			t.Fatal("invalid deployment cursor returned data", err)
		}
	}
	ereq.Page, dreq.Page = page, page
	ereq.After, dreq.After = nil, nil
	ereq.Page.PageSize, dreq.Page.PageSize = 0, 0
	if v, err := reader.PageDeploymentEnvironments(t.Context(), ereq); !errors.Is(err, appquery.ErrInvalidPage) || !reflect.DeepEqual(v, appquery.Result[operationsdomain.DeploymentEnvironment]{}) {
		t.Fatal("invalid environment page returned data", err)
	}
	if v, err := reader.PageDeployments(t.Context(), dreq); !errors.Is(err, appquery.ErrInvalidPage) || !reflect.DeepEqual(v, appquery.Result[operationsquery.DeploymentPoint]{}) {
		t.Fatal("invalid deployment page returned data", err)
	}
	ereq.Page, dreq.Page = page, page
	ereq.TenantID, dreq.TenantID = "missing", "missing"
	if v, err := reader.PageDeploymentEnvironments(t.Context(), ereq); err == nil || !reflect.DeepEqual(v, appquery.Result[operationsdomain.DeploymentEnvironment]{}) {
		t.Fatal("missing tenant returned environments", err)
	}
	if v, err := reader.PageDeployments(t.Context(), dreq); err == nil || !reflect.DeepEqual(v, appquery.Result[operationsquery.DeploymentPoint]{}) {
		t.Fatal("missing tenant returned deployments", err)
	}
	ereq.TenantID, dreq.TenantID = "tenant", "tenant"
	var missingContext context.Context
	if _, err := reader.PageDeploymentEnvironments(missingContext, ereq); err == nil {
		t.Fatal("nil environment context accepted")
	}
	if _, err := reader.PageDeployments(missingContext, dreq); err == nil {
		t.Fatal("nil deployment context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.PageDeploymentEnvironments(ctx, ereq); !errors.Is(err, context.Canceled) {
		t.Fatal("environment cancellation lost", err)
	}
	if _, err := reader.PageDeployments(ctx, dreq); !errors.Is(err, context.Canceled) {
		t.Fatal("deployment cancellation lost", err)
	}
	ereq.AllowedProductIDs = []string{"tenant-product"}
	dreq.AllowedReleaseIDs = []string{"tenant-release"}
	if _, err := reader.PageDeploymentEnvironments(t.Context(), ereq); err == nil {
		t.Fatal("mixed environment visibility accepted")
	}
	if _, err := reader.PageDeployments(t.Context(), dreq); err == nil {
		t.Fatal("mixed deployment visibility accepted")
	}
	ereq.AllowedProductIDs = nil
	dreq.AllowedReleaseIDs = nil
	ereq.TenantWide = false
	dreq.TenantWide = false
	if _, err := reader.PageDeploymentEnvironments(t.Context(), ereq); err == nil {
		t.Fatal("unscoped environment read accepted")
	}
	if _, err := reader.PageDeployments(t.Context(), dreq); err == nil {
		t.Fatal("unscoped deployment read accepted")
	}
	ereq.TenantWide = true
	dreq.TenantWide = true
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.PageDeploymentEnvironments(t.Context(), ereq); err == nil {
		t.Fatal("closed environment transaction accepted")
	}
	if _, err := reader.PageDeployments(t.Context(), dreq); err == nil {
		t.Fatal("closed deployment transaction accepted")
	}
}
