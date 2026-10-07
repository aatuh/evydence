package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Only historical HTTP tests use these adapters. The existing real guard
// checks current fixture ownership/associations; writes use isolated replay
// clones. Former point reads do not establish native digest/SQL-lock guarantees.
type artifactSignatureFixture struct{ catalogFixtureCommands }

func (f artifactSignatureFixture) AuthorizeArtifactSignatureCreation(ctx context.Context, a domain.Actor, in verificationapp.CreateArtifactSignatureInput) error {
	return f.commandLedger(ctx).AuthorizeArtifactSignatureCreation(ctx, a, in)
}
func (f artifactSignatureFixture) CreateArtifactSignature(ctx context.Context, a domain.Actor, in verificationapp.CreateArtifactSignatureInput) (verificationdomain.ArtifactSignature, error) {
	v, err := f.commandLedger(ctx).CreateArtifactSignature(ctx, a, app.CreateArtifactSignatureInput{ArtifactID: in.ArtifactID, Algorithm: in.Algorithm, KeyID: in.KeyID, Signature: in.Signature, RawPayload: slices.Clone(in.RawPayload), PayloadMediaType: in.PayloadMediaType})
	return verificationdomain.ArtifactSignature(v), err
}
func (f artifactSignatureFixture) GetArtifactSignature(ctx context.Context, a domain.Actor, id string) (verificationdomain.ArtifactSignature, error) {
	v, err := f.commandLedger(ctx).GetArtifactSignature(ctx, a, id)
	return verificationdomain.ArtifactSignature(v), err
}
func (s *Server) bindArtifactSignatureFixturePorts(ledger *app.Ledger) {
	f := artifactSignatureFixture{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.artifactSignatureCommands.(artifactSignatureFixture); s.artifactSignatureCommands == nil || fixture {
		s.artifactSignatureCommands = f
	}
	if _, fixture := s.artifactSignatureQuery.(artifactSignatureFixture); s.artifactSignatureQuery == nil || fixture {
		s.artifactSignatureQuery = f
	}
}

var (
	_ ArtifactSignatureCommands = artifactSignatureFixture{}
	_ ArtifactSignatureQuery    = artifactSignatureFixture{}
)
