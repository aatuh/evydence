package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Test-only composition uses current repositories and focused commands, never
// aggregate key/provider/root caches. Runtime signing administration has no fallback.
type signingAdministrationFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}

func (f signingAdministrationFixtureCommands) AuthorizeSigningKeyRotation(ctx context.Context, actor domain.Actor) error {
	c, err := f.signingCommands()
	if err != nil {
		return err
	}
	return mapSigningKeyCommandError(c.AuthorizeSigningKeyRotation(ctx, actor))
}

func (f signingAdministrationFixtureCommands) AuthorizeSigningKeyRevocation(ctx context.Context, actor domain.Actor, id string) error {
	c, err := f.signingCommands()
	if err != nil {
		return err
	}
	return mapSigningKeyCommandError(c.AuthorizeSigningKeyRevocation(ctx, actor, id))
}

func (f signingAdministrationFixtureCommands) RotateSigningKey(ctx context.Context, actor domain.Actor, reason string) (verificationdomain.SigningKey, error) {
	c, err := f.signingCommands()
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	value, err := c.RotateSigningKey(ctx, actor, reason)
	return value, mapSigningKeyCommandError(err)
}

func (f signingAdministrationFixtureCommands) RevokeSigningKey(ctx context.Context, actor domain.Actor, id string, input verificationapp.SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	c, err := f.signingCommands()
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	value, err := c.RevokeSigningKey(ctx, actor, id, input)
	return value, mapSigningKeyCommandError(err)
}

func (f signingAdministrationFixtureCommands) AuthorizeTrustConfiguration(ctx context.Context, actor domain.Actor) error {
	c, err := f.trustCommands()
	if err != nil {
		return err
	}
	return mapSigningKeyCommandError(c.AuthorizeTrustConfiguration(ctx, actor))
}

func (f signingAdministrationFixtureCommands) CreateSigningProvider(ctx context.Context, actor domain.Actor, input verificationapp.CreateSigningProviderInput) (verificationdomain.SigningProvider, error) {
	c, err := f.trustCommands()
	if err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	value, err := c.CreateSigningProvider(ctx, actor, input)
	return value, mapSigningKeyCommandError(err)
}

func (f signingAdministrationFixtureCommands) CreateDSSETrustRoot(ctx context.Context, actor domain.Actor, input verificationapp.CreateDSSETrustRootInput) (verificationdomain.DSSETrustRoot, error) {
	c, err := f.trustCommands()
	if err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	value, err := c.CreateDSSETrustRoot(ctx, actor, input)
	return value, mapSigningKeyCommandError(err)
}

func (s *Server) bindSigningAdministrationFixturePorts(ledger *app.Ledger) {
	commands := signingAdministrationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if old, fixture := s.signingKeyCommands.(signingAdministrationFixtureCommands); fixture {
		old.ledger = ledger
		s.signingKeyCommands = old
	} else if s.signingKeyCommands == nil {
		s.signingKeyCommands = commands
	}
	if old, fixture := s.trustConfigurationCommands.(signingAdministrationFixtureCommands); fixture {
		old.ledger = ledger
		s.trustConfigurationCommands = old
	} else if s.trustConfigurationCommands == nil {
		s.trustConfigurationCommands = commands
	}
}

var (
	_ SigningKeyCommands         = signingAdministrationFixtureCommands{}
	_ TrustConfigurationCommands = signingAdministrationFixtureCommands{}
)
