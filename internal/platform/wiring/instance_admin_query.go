package wiring

import (
	"time"

	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

// BuildInstanceAdminQuery binds one safe global count projection to the
// explicit instance-authority service.
func BuildInstanceAdminQuery(reader operationsquery.InstanceCountsReader) (*operationsquery.InstanceAdmin, error) {
	return operationsquery.NewInstanceAdmin(reader, time.Now)
}
