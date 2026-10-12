package wiring

import riskquery "github.com/aatuh/evydence/internal/risk/query"

// BuildExceptionsQuery binds current verify grants to tenant-scoped durable
// release and exception pages.
func BuildExceptionsQuery(reader riskquery.ExceptionReader) (*riskquery.Exceptions, error) {
	return riskquery.NewExceptions(reader)
}
