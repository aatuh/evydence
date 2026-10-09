package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Test-only adapters preserve the former fixture's actual policies and its
// isolated command ledger. Runtime signing administration has no fallback.
type signingAdministrationFixtureCommands struct{ catalogFixtureCommands }

func (f signingAdministrationFixtureCommands) AuthorizeSigningKeyRotation(ctx context.Context, actor domain.Actor) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeKeysAdmin)
}

func (f signingAdministrationFixtureCommands) AuthorizeSigningKeyRevocation(ctx context.Context, actor domain.Actor, id string) error {
	return f.commandLedger(ctx).AuthorizeSigningKeyRevocation(ctx, actor, id)
}

func (f signingAdministrationFixtureCommands) RotateSigningKey(ctx context.Context, actor domain.Actor, reason string) (verificationdomain.SigningKey, error) {
	value, err := f.commandLedger(ctx).RotateSigningKey(ctx, actor, reason)
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return signingKeyFixtureModel(value)
}

func (f signingAdministrationFixtureCommands) RevokeSigningKey(ctx context.Context, actor domain.Actor, id string, input verificationapp.SigningKeyRevocationInput) (verificationdomain.SigningKey, error) {
	value, err := f.commandLedger(ctx).RevokeSigningKeyWithPolicy(ctx, actor, id, app.SigningKeyRevocationInput(input))
	if err != nil {
		return verificationdomain.SigningKey{}, err
	}
	return signingKeyFixtureModel(value)
}

func (f signingAdministrationFixtureCommands) AuthorizeTrustConfiguration(ctx context.Context, actor domain.Actor) error {
	return application.AuthorizeTenantWideScope(ctx, actor, app.ScopeKeysAdmin)
}

func (f signingAdministrationFixtureCommands) CreateSigningProvider(ctx context.Context, actor domain.Actor, input verificationapp.CreateSigningProviderInput) (verificationdomain.SigningProvider, error) {
	value, err := f.commandLedger(ctx).CreateSigningProvider(ctx, actor, app.CreateSigningProviderInput(input))
	if err != nil {
		return verificationdomain.SigningProvider{}, err
	}
	return domain.SigningProviderToContextModel(value), nil
}

func (f signingAdministrationFixtureCommands) CreateDSSETrustRoot(ctx context.Context, actor domain.Actor, input verificationapp.CreateDSSETrustRootInput) (verificationdomain.DSSETrustRoot, error) {
	value, err := f.commandLedger(ctx).CreateDSSETrustRoot(ctx, actor, app.CreateDSSETrustRootInput(input))
	if err != nil {
		return verificationdomain.DSSETrustRoot{}, err
	}
	return domain.DSSETrustRootToContextModel(value), nil
}

func (s *Server) bindSigningAdministrationFixturePorts(ledger *app.Ledger) {
	commands := signingAdministrationFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	if _, fixture := s.signingKeyCommands.(signingAdministrationFixtureCommands); s.signingKeyCommands == nil || fixture {
		s.signingKeyCommands = commands
	}
	if _, fixture := s.trustConfigurationCommands.(signingAdministrationFixtureCommands); s.trustConfigurationCommands == nil || fixture {
		s.trustConfigurationCommands = commands
	}
}

var (
	_ SigningKeyCommands         = signingAdministrationFixtureCommands{}
	_ TrustConfigurationCommands = signingAdministrationFixtureCommands{}
)
