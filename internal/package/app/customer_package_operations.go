package app

import (
	"sort"
	"strings"
)

// CustomerPackageAPIOperation is the public, normalized-operation input to a
// customer manifest. Raw OpenAPI documents and extensions are not part of it.
type CustomerPackageAPIOperation struct {
	Path, Method, OperationID               string
	Deprecated, RequestBodyRequired         bool
	RequiredRequestFields, ResponseStatuses []string
}

// CustomerPackageOperationSummaries keeps the package format's normalization,
// empty-entry handling and label ordering shared by native and local readers.
func CustomerPackageOperationSummaries(operations []CustomerPackageAPIOperation) []map[string]any {
	out := make([]map[string]any, 0, len(operations))
	for _, op := range operations {
		method, path := strings.ToUpper(strings.TrimSpace(op.Method)), strings.TrimSpace(op.Path)
		if method == "" || path == "" {
			continue
		}
		out = append(out, map[string]any{
			"label": method + " " + path, "path": path, "method": method,
			"operation_id": op.OperationID, "deprecated": op.Deprecated,
			"request_body_required":   op.RequestBodyRequired,
			"required_request_fields": append([]string(nil), op.RequiredRequestFields...),
			"response_statuses":       append([]string(nil), op.ResponseStatuses...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["label"].(string) < out[j]["label"].(string) })
	return out
}
