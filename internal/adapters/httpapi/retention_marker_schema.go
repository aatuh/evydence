package httpapi

import operationsapp "github.com/aatuh/evydence/internal/operations/app"

func retentionMarkerCreationSchema(override bool) map[string]any {
	fields := map[string]any{
		"scope_type": map[string]any{"type": "string", "enum": []string{"tenant", "product", "project", "release", "evidence"}, "maxLength": 64, "description": "Raw NUL-free UTF-8 is capped at 64 bytes before trimming."},
		"scope_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": 1024, "description": "Current tenant-owned subject ID; raw NUL-free UTF-8 is capped at 1024 bytes before trimming."},
		"reason":     map[string]any{"type": "string", "minLength": 1, "maxLength": operationsapp.MaxRetentionMarkerTextBytes, "description": "Nonblank reason; raw NUL-free UTF-8 is capped at 64 KiB before trimming. Do not include credentials."},
		"owner":      map[string]any{"type": "string", "minLength": 1, "maxLength": operationsapp.MaxRetentionMarkerTextBytes, "description": "Nonblank owner; raw NUL-free UTF-8 is capped at 64 KiB before trimming. Do not include credentials."},
	}
	required := []string{"scope_type", "scope_id", "reason", "owner"}
	if override {
		fields["retention_until"] = map[string]any{"type": "string", "format": "date-time", "description": "UTC-normalized date after the command creation time for a new extension. Completed replay remains available after this date."}
		required = []string{"scope_type", "scope_id", "retention_until", "reason", "owner"}
	}
	v := objectSchema(fields, required...)
	v["description"] = "Creates an append-only retention marker; it does not enforce provider storage lifecycle or establish a legal conclusion. Current tenant-wide admin authority and locked subject ownership are checked before reservation and every native PostgreSQL replay. Marker, audit and successful replay writes commit together without a Ledger clone. Both profiles reject unknown, duplicate, case-aliased, explicitly null, invalid UTF-8/NUL or over-budget fields; the whole JSON body is capped at 64 KiB. Unsafe cookie writes require same-origin protection. Local memory retains explicit nondurable compatibility storage."
	return v
}
