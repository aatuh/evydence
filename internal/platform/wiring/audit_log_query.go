package wiring

import verificationquery "github.com/aatuh/evydence/internal/verification/query"

// BuildAuditLogQuery binds the admin audit read to a tenant-filtered store.
func BuildAuditLogQuery(reader verificationquery.AuditLogReader) (*verificationquery.AuditLog, error) {
	return verificationquery.NewAuditLog(reader)
}
