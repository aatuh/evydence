package wiring

import verificationquery "github.com/aatuh/evydence/internal/verification/query"

// BuildSigningKeyQuery binds public signing-key listing to a durable reader.
func BuildSigningKeyQuery(reader verificationquery.SigningKeyReader) (*verificationquery.SigningKeys, error) {
	return verificationquery.NewSigningKeys(reader)
}
