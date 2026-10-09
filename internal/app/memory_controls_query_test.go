package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

func memoryControlsQueryFixture(t *testing.T) (*memoryUnitOfWork, riskquery.ControlsReader) {
	t.Helper()
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Controls.(riskquery.ControlsReader)
	if !ok {
		t.Fatal("memory controls lack focused point/page reader")
	}
	for _, tenant := range []string{"tenant", "foreign"} {
		id := tenant + "-framework"
		tx.state.ControlFrameworks[id] = domain.ControlFramework{ID: id, TenantID: tenant, Name: "Framework", Slug: "framework", Version: "1", Description: "Recorded guidance", Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: fixedNow()}
		id = tenant + "-control"
		tx.state.SecurityControls[id] = domain.SecurityControl{ID: id, TenantID: tenant, FrameworkID: tenant + "-framework", Code: "BUILD", Title: "Build review", Objective: "Record evidence", EvidenceRequirements: []domain.ControlEvidenceRequirement{{Type: "build", FreshnessDays: 30, Required: false}}, Applicability: []string{"software"}, Limitations: []string{"Human review required"}, SchemaVersion: domain.SecurityControlSchemaVersion, CreatedAt: fixedNow()}
	}
	return tx, reader
}

func TestMemoryControlsQueryFiltersBeforeLimitAndDetachesCompleteDefinitions(t *testing.T) {
	tx, reader := memoryControlsQueryFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	v, err := reader.PageFrameworks(t.Context(), riskquery.FrameworkPageRequest{TenantID: "tenant", Page: page})
	if err != nil || len(v.Items) != 1 || v.Next != nil || !reflect.DeepEqual(domain.ControlFramework(v.Items[0]), tx.state.ControlFrameworks["tenant-framework"]) {
		t.Fatal("framework page lost tenant or complete DTO", err)
	}
	control, err := reader.GetControl(t.Context(), "tenant", "tenant-control")
	if err != nil || !reflect.DeepEqual(memoryControlQueryDTO(control), tx.state.SecurityControls["tenant-control"]) {
		t.Fatal("control point lost complete definition", err)
	}
	control.EvidenceRequirements[0].Type, control.Applicability[0], control.Limitations[0] = "modified", "modified", "modified"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("definition read exposed aliases or changed snapshot")
	}
	if v, err := reader.GetControl(t.Context(), "tenant", "foreign-control"); !errors.Is(err, riskquery.ErrNotFound) || !reflect.DeepEqual(v, riskdomain.SecurityControl{}) {
		t.Fatal("foreign control disclosed", err)
	}
	for _, parent := range []string{"absent", "foreign"} {
		framework := tx.state.ControlFrameworks["tenant-framework"]
		if parent == "absent" {
			delete(tx.state.ControlFrameworks, framework.ID)
		} else {
			framework.TenantID = "foreign"
			tx.state.ControlFrameworks[framework.ID] = framework
		}
		if _, err := reader.GetControl(t.Context(), "tenant", "tenant-control"); !errors.Is(err, riskquery.ErrNotFound) {
			t.Fatal("missing/foreign framework allowed control", err)
		}
		tx.state.ControlFrameworks[framework.ID] = before.ControlFrameworks[framework.ID]
	}
}

func TestMemoryControlsQueryTraversesFiveHundredFrameworksWithDeletedCursor(t *testing.T) {
	tx, reader := memoryControlsQueryFixture(t)
	template := tx.state.ControlFrameworks["tenant-framework"]
	tx.state.ControlFrameworks = map[string]domain.ControlFramework{}
	for i := range 501 {
		v := template
		v.ID = fmt.Sprintf("record-%03d", i)
		v.CreatedAt = fixedNow().Add(time.Duration((501-i)/3) * time.Minute)
		tx.state.ControlFrameworks[v.ID] = v
	}
	foreign := template
	foreign.ID, foreign.TenantID, foreign.Description = "0-foreign", "foreign", strings.Repeat("private", 10000)
	tx.state.ControlFrameworks[foreign.ID] = foreign
	for _, order := range []appquery.Sort{appquery.SortID, appquery.SortCreatedAt} {
		for _, direction := range []appquery.Direction{appquery.Ascending, appquery.Descending} {
			t.Run(fmt.Sprintf("%s/%s", order, direction), func(t *testing.T) {
				page := appquery.PageRequest{PageSize: 7, Sort: order, Direction: direction}
				var after *appquery.SortKey
				var got []string
				for count := 0; count < 80; count++ {
					result, err := reader.PageFrameworks(t.Context(), riskquery.FrameworkPageRequest{TenantID: "tenant", Page: page, After: after})
					if err != nil || len(result.Items) == 0 || len(result.Items) > 7 {
						t.Fatal("framework page failed", err)
					}
					for _, v := range result.Items {
						if v.TenantID != "tenant" {
							t.Fatal("foreign page row")
						}
						got = append(got, v.ID)
					}
					if result.Next == nil {
						break
					}
					last := result.Items[len(result.Items)-1]
					if *result.Next != appquery.RecordSortKey(last.ID, last.CreatedAt, order) {
						t.Fatal("cursor does not identify final returned record")
					}
					after = result.Next
				}
				want := make([]domain.ControlFramework, 0, 501)
				for _, v := range tx.state.ControlFrameworks {
					if v.TenantID == "tenant" {
						want = append(want, v)
					}
				}
				sort.Slice(want, func(i, j int) bool {
					cmp := 0
					if order == appquery.SortCreatedAt {
						cmp = want[i].CreatedAt.Compare(want[j].CreatedAt)
					}
					if cmp == 0 {
						cmp = strings.Compare(want[i].ID, want[j].ID)
					}
					if direction == appquery.Descending {
						return cmp > 0
					}
					return cmp < 0
				})
				ids := make([]string, len(want))
				for i, v := range want {
					ids[i] = v.ID
				}
				if !slices.Equal(got, ids) {
					t.Fatal("framework traversal lost, duplicated or reordered records")
				}
				first, err := reader.PageFrameworks(t.Context(), riskquery.FrameworkPageRequest{TenantID: "tenant", Page: page})
				if err != nil || first.Next == nil {
					t.Fatal("first cursor missing", err)
				}
				deleted := tx.state.ControlFrameworks[first.Next.ID]
				delete(tx.state.ControlFrameworks, deleted.ID)
				next, err := reader.PageFrameworks(t.Context(), riskquery.FrameworkPageRequest{TenantID: "tenant", Page: page, After: first.Next})
				tx.state.ControlFrameworks[deleted.ID] = deleted
				if err != nil || len(next.Items) != 7 || next.Items[0].ID != ids[7] {
					t.Fatal("keyset required cursor row to remain present", err)
				}
			})
		}
	}
}

func TestMemoryControlsQueryEnforcesStoredJSONBoundsAndZeroFailureResults(t *testing.T) {
	tx, reader := memoryControlsQueryFixture(t)
	control := tx.state.SecurityControls["tenant-control"]
	for _, field := range []string{"applicability", "limitations"} {
		v := control
		atLimit := []string{strings.Repeat("x", (1<<20)-4)}
		if field == "applicability" {
			v.Applicability = atLimit
		} else {
			v.Limitations = atLimit
		}
		tx.state.SecurityControls[v.ID] = v
		if _, err := reader.GetControl(t.Context(), "tenant", v.ID); err != nil {
			t.Fatal("exact JSON byte limit rejected", field, err)
		}
		atLimit[0] += "x"
		if v, err := reader.GetControl(t.Context(), "tenant", control.ID); !errors.Is(err, riskquery.ErrInvalidProjection) || v.ID != "" || v.EvidenceRequirements != nil || v.Applicability != nil || v.Limitations != nil {
			t.Fatal("overflow exposed partial control", field, err)
		}
	}
	minimal := []domain.ControlEvidenceRequirement{{Required: false}}
	encoded, err := json.Marshal(minimal)
	if err != nil {
		t.Fatal(err)
	}
	minimal[0].Type = strings.Repeat("x", (1<<20)-len(encoded))
	v := control
	v.EvidenceRequirements = minimal
	tx.state.SecurityControls[v.ID] = v
	if _, err := reader.GetControl(t.Context(), "tenant", v.ID); err != nil {
		t.Fatal("exact requirements JSON limit rejected", err)
	}
	minimal[0].Type += "x"
	if v, err := reader.GetControl(t.Context(), "tenant", control.ID); !errors.Is(err, riskquery.ErrInvalidProjection) || v.ID != "" || v.EvidenceRequirements != nil {
		t.Fatal("requirements overflow exposed partial control", err)
	}
	tx.state.SecurityControls[control.ID] = control
	var nilContext context.Context
	if _, err := reader.GetControl(nilContext, "tenant", control.ID); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := reader.GetControl(ctx, "tenant", control.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	page := appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}
	lookahead := tx.state.ControlFrameworks["tenant-framework"]
	lookahead.ID = "z"
	lookahead.Name = ""
	tx.state.ControlFrameworks[lookahead.ID] = lookahead
	if v, err := reader.PageFrameworks(t.Context(), riskquery.FrameworkPageRequest{TenantID: "tenant", Page: page}); !errors.Is(err, riskquery.ErrInvalidProjection) || v.Items != nil || v.Next != nil {
		t.Fatal("invalid selected lookahead exposed page", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetControl(t.Context(), "tenant", control.ID); err == nil {
		t.Fatal("closed transaction accepted")
	}
}

func memoryControlQueryDTO(v riskdomain.SecurityControl) domain.SecurityControl {
	requirements := make([]domain.ControlEvidenceRequirement, len(v.EvidenceRequirements))
	for i, r := range v.EvidenceRequirements {
		requirements[i] = domain.ControlEvidenceRequirement(r)
	}
	return domain.SecurityControl{ID: v.ID, TenantID: v.TenantID, FrameworkID: v.FrameworkID, Code: v.Code, Title: v.Title, Objective: v.Objective, EvidenceRequirements: requirements, Applicability: v.Applicability, Limitations: v.Limitations, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
