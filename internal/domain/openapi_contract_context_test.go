package domain

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestOpenAPIContractContextMapperPreservesWireFieldsAndCopiesOperations(t *testing.T) {
	in := evidencedomain.OpenAPIContract{ID: "oas", TenantID: "tenant", ProductID: "product", ReleaseID: "release", Version: "1", Hash: "sha256:hash", PathCount: 1, EvidenceID: "evidence", CreatedAt: time.Date(2026, 10, 3, 12, 1, 2, 123456000, time.UTC), Operations: []evidencedomain.OpenAPIOperation{{Path: "/health", Method: "GET", OperationID: "health", Deprecated: true, RequestBodyRequired: true, RequiredRequestFields: []string{"required"}, ResponseStatuses: []string{"200", "404"}}}}
	v := OpenAPIContractFromContext(in)
	// Context models intentionally have no HTTP JSON tags. Pin the public DTO
	// representation rather than serializing the internal model as the oracle.
	want := []byte(`{"id":"oas","tenant_id":"tenant","product_id":"product","release_id":"release","version":"1","hash":"sha256:hash","path_count":1,"operations":[{"path":"/health","method":"GET","operation_id":"health","deprecated":true,"request_body_required":true,"required_request_fields":["required"],"response_statuses":["200","404"]}],"evidence_id":"evidence","created_at":"2026-10-03T12:01:02.123456Z"}`)
	got, err := json.Marshal(v)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatal("wire fields changed", string(got), string(want), err)
	}
	v.Operations[0].Path = "/changed"
	v.Operations[0].RequiredRequestFields[0] = "changed"
	v.Operations[0].ResponseStatuses[0] = "changed"
	if in.Operations[0].Path != "/health" || in.Operations[0].RequiredRequestFields[0] != "required" || in.Operations[0].ResponseStatuses[0] != "200" {
		t.Fatal("DTO shares parser-owned operation data", in)
	}
	for _, operations := range [][]evidencedomain.OpenAPIOperation{nil, {}} {
		v := OpenAPIContractFromContext(evidencedomain.OpenAPIContract{Operations: operations})
		if (v.Operations == nil) != (operations == nil) || len(v.Operations) != 0 {
			t.Fatal("nil/empty compatibility changed", v.Operations, operations)
		}
	}
}
