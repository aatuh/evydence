package wiring

import verificationquery "github.com/aatuh/evydence/internal/verification/query"

// BuildArtifactSignatureQuery binds the verification-owned read policy to the
// tenant-filtered PostgreSQL signature point.
func BuildArtifactSignatureQuery(reader verificationquery.ArtifactSignatureReader) (*verificationquery.ArtifactSignatures, error) {
	return verificationquery.NewArtifactSignatures(reader)
}
