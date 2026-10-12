package app

import (
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	integrationquery "github.com/aatuh/evydence/internal/integration/query"
)

func TestMemoryCollectorHealthSelectsLatestAndPinnedCurrentRowsWithDetachedLimitations(t *testing.T) {
	_, tx := memoryGovernanceReadFixture(t)
	reader, ok := tx.Repositories().Builds.(integrationquery.CollectorHealthReader)
	if !ok {
		t.Fatal("memory builds lacks native collector health")
	}
	at := fixedNow()
	tx.state.Collectors["collector"] = domain.Collector{ID: "collector", TenantID: "tenant", APIKeyID: "key", Status: "active", CreatedAt: at, AllowedScopes: []string{"unselected-credential-scope"}}
	for _, v := range []domain.CollectorRelease{
		{ID: "a", TenantID: "tenant", CollectorID: "collector", Version: "old", Pinned: true, HealthStatus: "needs_evidence", Limitations: []string{"old-limit"}, CreatedAt: at},
		{ID: "b", TenantID: "tenant", CollectorID: "collector", Version: "new", HealthStatus: "healthy", Limitations: []string{"new-limit"}, CreatedAt: at},
		{ID: "z", TenantID: "foreign", CollectorID: "collector", Version: "foreign", Pinned: true, CreatedAt: at},
	} {
		tx.state.CollectorReleases[v.ID] = v
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	v, err := reader.GetCollectorHealthPoint(t.Context(), "tenant", "collector")
	if err != nil || v.LatestRelease == nil || v.PinnedRelease == nil || v.LatestRelease.ID != "b" || v.PinnedRelease.ID != "a" || v.Collector.AllowedScopes != nil {
		t.Fatal("health point lost tie ordering, pinning or omitted metadata", err)
	}
	v.LatestRelease.Limitations[0], v.PinnedRelease.Limitations[0] = "changed", "changed"
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("health point aliases or mutates state")
	}
}
