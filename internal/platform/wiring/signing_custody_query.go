package wiring

import (
	"time"

	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// BuildSigningCustodyQuery binds only the bounded provider/policy inventory,
// sharing verification assessment without a Ledger or service locator.
func BuildSigningCustodyQuery(reader verificationquery.SigningCustodyReader) (*verificationquery.SigningCustody, error) {
	return verificationquery.NewSigningCustody(reader, time.Now)
}
