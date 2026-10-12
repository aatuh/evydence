package wiring

import (
	"time"

	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// BuildIncidentReportQuery binds one tenant-scoped incident report reader.
func BuildIncidentReportQuery(reader packagequery.IncidentReportReader) (*packagequery.IncidentReport, error) {
	return packagequery.NewIncidentReport(reader, time.Now)
}
