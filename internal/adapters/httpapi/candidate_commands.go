package httpapi

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// CandidateCommands exposes snapshot creation only, not unrelated catalog
// reads or lifecycle transitions.
type CandidateCommands interface {
	AuthorizeCandidateCreation(context.Context, identitydomain.Actor, releaseapp.CreateReleaseCandidateInput) error
	CreateReleaseCandidate(context.Context, identitydomain.Actor, releaseapp.CreateReleaseCandidateInput) (releasedomain.ReleaseCandidate, error)
}
