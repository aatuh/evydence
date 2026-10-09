package wiring

import operationsquery "github.com/aatuh/evydence/internal/operations/query"

// BuildOutboxDiagnosticsQuery binds durable, payload-free queue counts to the
// explicit instance-authority service.
func BuildOutboxDiagnosticsQuery(reader operationsquery.OutboxDiagnosticsReader) (*operationsquery.OutboxDiagnostics, error) {
	return operationsquery.NewOutboxDiagnostics(reader)
}
