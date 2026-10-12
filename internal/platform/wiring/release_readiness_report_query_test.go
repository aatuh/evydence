package wiring

import (
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

func TestBuildReleaseReadinessReportQueryUsesFocusedReader(t *testing.T) {
	if _, err := BuildReleaseReadinessReportQuery(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
	store := &postgres.Store{}
	service, err := BuildReleaseReadinessReportQuery(store)
	if err != nil || service == nil {
		t.Fatal(err)
	}
	var _ packagequery.ReleaseReadinessReportReader = store
}
