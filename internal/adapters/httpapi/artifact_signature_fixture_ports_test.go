package httpapi

import (
	"context"
	"slices"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

// Only historical HTTP tests use these adapters. The existing real guard
// checks current fixture ownership/associations; writes use isolated replay
// clones. Point reads compose the focused query over current typed repositories;
// the memory model does not establish SQL transfer/work, locks or durability.
type artifactSignatureFixture struct{ catalogFixtureCommands }

func (f artifactSignatureFixture) AuthorizeArtifactSignatureCreation(ctx context.Context, a domain.Actor, in verificationapp.CreateArtifactSignatureInput) error {
	return f.commandLedger(ctx).AuthorizeArtifactSignatureCreation(ctx, a, in)
}
func (f artifactSignatureFixture) CreateArtifactSignature(ctx context.Context, a domain.Actor, in verificationapp.CreateArtifactSignatureInput) (verificationdomain.ArtifactSignature, error) {
	v, err := f.commandLedger(ctx).CreateArtifactSignature(ctx, a, app.CreateArtifactSignatureInput{ArtifactID: in.ArtifactID, Algorithm: in.Algorithm, KeyID: in.KeyID, Signature: in.Signature, RawPayload: slices.Clone(in.RawPayload), PayloadMediaType: in.PayloadMediaType})
	return verificationdomain.ArtifactSignature(v), err
}
func (f artifactSignatureFixture) GetArtifactSignature(ctx context.Context, a domain.Actor, id string) (verificationdomain.ArtifactSignature, error) {
	query, err := verificationquery.NewArtifactSignatures(f)
	if err != nil {
		return verificationdomain.ArtifactSignature{}, err
	}
	v, err := query.GetArtifactSignature(ctx, a, id)
	return v, mapArtifactSignatureQueryError(err)
}

func (f artifactSignatureFixture) GetArtifactSignaturePoint(ctx context.Context, request verificationquery.SignatureReadRequest) (verificationquery.SignaturePoint, error) {
	var out verificationquery.SignaturePoint
	if ctx == nil {
		return out, verificationquery.ErrSignatureValidation
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	err := f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.ReleaseCatalog.(verificationquery.ArtifactSignatureReader)
		if !ok {
			return app.ErrValidation
		}
		var err error
		out, err = reader.GetArtifactSignaturePoint(ctx, request)
		return err
	})
	if err != nil {
		return verificationquery.SignaturePoint{}, err
	}
	return out, nil
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
