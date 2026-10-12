package app

// Historical characterization only; runtime and HTTP fixtures compose the
// focused Cosign command rather than exposing this aggregate facade.

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type VerifyCosignInput struct {
	ArtifactSignatureID string
	ExpectedIdentity    string
	ExpectedIssuer      string
	Mode                CosignVerificationMode
	Offline             bool
}

func (l *Ledger) VerifyCosignSignature(ctx context.Context, actor domain.Actor, in VerifyCosignInput) (domain.CosignVerification, error) {
	value, err := l.legacyVerificationCommands().VerifyCosign(ctx, actor, verificationapp.VerifyCosignInput{
		ArtifactSignatureID: in.ArtifactSignatureID, ExpectedIdentity: in.ExpectedIdentity, ExpectedIssuer: in.ExpectedIssuer,
		Mode: verificationapp.CosignVerificationMode(in.Mode), Offline: in.Offline,
	})
	return cosignVerificationFromVerificationContext(value), fromVerificationContextError(err)
}
