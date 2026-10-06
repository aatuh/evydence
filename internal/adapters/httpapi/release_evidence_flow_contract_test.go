package httpapi

import (
	"encoding/json"
	"testing"
)

func TestReleaseEvidenceFlowReadOnlyPostDoesNotRequireIdempotencyKey(t *testing.T) {
	server, _ := testServer(t)
	data, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Paths map[string]map[string]struct {
			Idempotency struct {
				Required bool `json:"required"`
			} `json:"x-idempotency-key"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if document.Paths["/v1/releases/{id}/evidence-flow/start"]["post"].Idempotency.Required {
		t.Fatal("read-only workflow plan requires an idempotency key in OpenAPI")
	}
}
