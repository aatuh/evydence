package app

import (
	"encoding/json"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestMemoryIdempotencyResponseClonePreservesTypedJSONBytesAndDetachesFields(t *testing.T) {
	response := domain.BuildRun{ID: "build", TenantID: "tenant", ProjectID: "project", Provider: "github_actions", SourceIdentity: map[string]any{"run_attempt": json.Number("9007199254740993")}, CreatedAt: fixedNow()}
	cloned, err := cloneMemoryIdempotencyRecord(IdempotencyRecord{Response: response})
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(cloned.Response)
	if err != nil || string(before) != string(after) {
		t.Fatal("typed response changed bytes during memory transaction/replay clone", string(before), string(after), err)
	}
	got, ok := cloned.Response.(domain.BuildRun)
	if !ok {
		t.Fatal("memory clone lost response type")
	}
	got.SourceIdentity["run_attempt"] = json.Number("1")
	if response.SourceIdentity["run_attempt"] != json.Number("9007199254740993") {
		t.Fatal("typed replay response aliases original metadata")
	}
}
