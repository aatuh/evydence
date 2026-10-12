package app

import "sort"

// CustomerPackageVerificationCheck is public recorded metadata, not a fresh
// verification operation or a decision to upgrade an assurance result.
type CustomerPackageVerificationCheck struct{ Name, Result, Detail string }

func CustomerPackageVerificationCheckSummaries(values []CustomerPackageVerificationCheck) []map[string]any {
	rows := make([]map[string]any, 0, len(values))
	for _, v := range values {
		rows = append(rows, map[string]any{"name": v.Name, "result": v.Result, "detail": v.Detail})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i]["name"].(string) < rows[j]["name"].(string) })
	return rows
}
