package app

import (
	"reflect"
	"testing"
)

func TestCustomerPackageOperationSummariesNormalizeSortAndOwnLists(t *testing.T) {
	in := []CustomerPackageAPIOperation{
		{Path: " /z ", Method: " post ", OperationID: "create", RequestBodyRequired: true, RequiredRequestFields: []string{"id"}, ResponseStatuses: []string{"201"}},
		{Path: "\u2003/a\u2003", Method: "\u2003get\u2003", Deprecated: true},
		{Path: " ", Method: "GET"}, {Path: "/ignored", Method: ""},
	}
	out := CustomerPackageOperationSummaries(in)
	if len(out) != 2 || out[0]["label"] != "GET /a" || out[1]["label"] != "POST /z" || out[1]["method"] != "POST" || out[1]["path"] != "/z" || out[0]["deprecated"] != true || out[1]["request_body_required"] != true {
		t.Fatal("public operation summaries changed", out)
	}
	if !reflect.DeepEqual(out[1]["required_request_fields"], []string{"id"}) || !reflect.DeepEqual(out[1]["response_statuses"], []string{"201"}) || out[1]["operation_id"] != "create" {
		t.Fatal("operation public fields changed", out)
	}
	out[1]["required_request_fields"].([]string)[0] = "changed"
	out[1]["response_statuses"].([]string)[0] = "changed"
	if in[0].RequiredRequestFields[0] != "id" || in[0].ResponseStatuses[0] != "201" || in[0].Path != " /z " {
		t.Fatal("public operation output aliases its input")
	}
	if got := CustomerPackageOperationSummaries(nil); got == nil || len(got) != 0 {
		t.Fatal("empty operation collection changed", got)
	}
}
