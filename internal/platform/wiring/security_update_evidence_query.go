package wiring

import (
	"time"

	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// BuildSecurityUpdateEvidenceQuery binds one bounded release report reader.
func BuildSecurityUpdateEvidenceQuery(reader packagequery.SecurityUpdateReader) (*packagequery.SecurityUpdateEvidence, error) {
	return packagequery.NewSecurityUpdateEvidence(reader, time.Now)
}
