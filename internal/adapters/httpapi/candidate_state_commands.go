package httpapi

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// CandidateStateCommands exposes only promotion/rejection, not candidate
// creation, catalog reads, or unrelated release workflows.
type CandidateStateCommands interface {
	AuthorizeCandidateTransition(context.Context, identitydomain.Actor, string) error
	UpdateReleaseCandidateState(context.Context, identitydomain.Actor, string, string, string, int64) (releasedomain.ReleaseCandidate, error)
}
