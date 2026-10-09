package postgres

import (
	"encoding/json"
	"testing"
	"time"

	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestCustomerPackageSnapshotBudgetIsEvaluatedOncePerPage(t *testing.T) {
	s := customerVerificationFixture(t)
	if _, err := s.pool.Exec(t.Context(), `INSERT INTO verification_results(id,tenant_id,subject_type,subject_id,result,checks,assurance_profile,limitations,schema_version,verified_at)
	 SELECT 'budget_'||lpad(n::text,4,'0'),'tenant','evidence_item','ev_selected','not_verified','[]','{}','{}','verification-result.v2',now() FROM generate_series(1,4092)n`); err != nil {
		t.Fatal(err)
	}
	// Explain the actual reader statement, not a parallel simplified query.
	// The assertion is an execution-count invariant, not a flaky time limit.
	query := customerSnapshotMetadataQuery(customerVerificationResultsSQL)
	var raw []byte
	if err := s.pool.QueryRow(t.Context(), "EXPLAIN (ANALYZE,FORMAT JSON) "+query, "tenant", "product", "release", packageapp.MaxCustomerPackageManifestBytes, packageapp.MaxSecurityReviewEvidenceIDs+1, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []map[string]any
	if err := json.Unmarshal(raw, &plans); err != nil {
		t.Fatal(err)
	}
	aggregates := 0
	var inspect func(map[string]any)
	inspect = func(node map[string]any) {
		budgetAggregate := false
		if children, ok := node["Plans"].([]any); ok {
			for _, child := range children {
				budgetAggregate = budgetAggregate || child.(map[string]any)["CTE Name"] == "records"
			}
		}
		if node["Node Type"] == "Aggregate" && budgetAggregate {
			aggregates++
			if node["Actual Loops"] != float64(1) {
				t.Fatalf("budget aggregate ran %v times for one page; execution=%v ms", node["Actual Loops"], plans[0]["Execution Time"])
			}
		}
		if children, ok := node["Plans"].([]any); ok {
			for _, child := range children {
				inspect(child.(map[string]any))
			}
		}
	}
	inspect(plans[0]["Plan"].(map[string]any))
	if aggregates != 1 {
		t.Fatalf("expected exactly one complete-page budget aggregate, got %d", aggregates)
	}
	t.Logf("complete-page budget evaluated once; query execution %v ms", plans[0]["Execution Time"])
}
