package app

import (
	"context"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Historical package-local tests delegate login state entirely to the focused
// memory repositories. No request state is added to the retired Ledger oracle.
func (r ledgerIdentityReader) ReadOIDCAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	var out identitydomain.OIDCAuthenticationRequest
	err := r.ledger.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
		reader, ok := repos.Identity.(identityapp.OIDCAuthenticationRequestReader)
		if !ok {
			return ErrValidation
		}
		var err error
		out, err = reader.ReadOIDCAuthenticationRequest(ctx, tenant, provider, id)
		return err
	})
	return out, toIdentityContextError(err)
}
func (t *ledgerIdentityTransaction) ConsumeOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, clock application.Clock) (time.Time, error) {
	if t.repositories == nil {
		return time.Time{}, identityapp.ErrValidation
	}
	w, ok := t.repositories.Identity.(identityapp.OIDCAuthenticationRequestConsumer)
	if !ok {
		return time.Time{}, identityapp.ErrValidation
	}
	at, err := w.ConsumeOIDCAuthenticationRequest(ctx, v, clock)
	return at, toIdentityContextError(err)
}
func (t *ledgerIdentityTransaction) ValidateOIDCProvider(ctx context.Context, p identitydomain.SSOProvider) error {
	if t.repositories == nil {
		return identityapp.ErrValidation
	}
	w, ok := t.repositories.Identity.(interface {
		ValidateOIDCProvider(context.Context, identitydomain.SSOProvider) error
	})
	if !ok {
		return identityapp.ErrValidation
	}
	return toIdentityContextError(w.ValidateOIDCProvider(ctx, p))
}
func (t *ledgerIdentityTransaction) InsertOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, at time.Time) error {
	if t.repositories == nil {
		return identityapp.ErrValidation
	}
	w, ok := t.repositories.Identity.(interface {
		InsertOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, time.Time) error
	})
	if !ok {
		return identityapp.ErrValidation
	}
	return toIdentityContextError(w.InsertOIDCAuthenticationRequest(ctx, v, at))
}

type oracleOIDCRequestTransactions struct{ ledger *Ledger }

func (r oracleOIDCRequestTransactions) ExecuteOIDCAuthenticationRequest(ctx context.Context, run func(context.Context, identityapp.OIDCAuthenticationRequestTransaction) error) error {
	return ledgerIdentityTransactions(r).execute(ctx, func(ctx context.Context, tx *ledgerIdentityTransaction) error { return run(ctx, tx) })
}
func beginOIDCOracleRequest(t *testing.T, l *Ledger, providerID string) (string, string, string) {
	t.Helper()
	credentials, err := identityapp.NewHMACAuthenticationCredentials(string(l.pepper))
	if err != nil {
		t.Fatal(err)
	}
	c, err := identityapp.NewOIDCAuthenticationRequestCommands(identityapp.OIDCAuthenticationRequestCommandConfig{Reader: ledgerIdentityReader{l}, Transactions: oracleOIDCRequestTransactions{l}, Credentials: credentials, Clock: application.ClockFunc(l.now), IDs: application.IDGeneratorFunc(newID)})
	if err != nil {
		t.Fatal(err)
	}
	v, state, nonce, err := c.BeginOIDCAuthentication(t.Context(), identityapp.BeginOIDCAuthenticationInput{ProviderID: providerID})
	if err != nil {
		t.Fatal(err)
	}
	return v.ID, state, nonce
}
func (f failingIdentityRepository) ConsumeOIDCAuthenticationRequest(ctx context.Context, v identitydomain.OIDCAuthenticationRequest, clock application.Clock) (time.Time, error) {
	c, ok := f.IdentityRepository.(identityapp.OIDCAuthenticationRequestConsumer)
	if !ok {
		return time.Time{}, ErrValidation
	}
	return c.ConsumeOIDCAuthenticationRequest(ctx, v, clock)
}

func (f failingIdentityRepository) ReadOIDCAuthenticationRequest(ctx context.Context, tenant, provider, id string) (identitydomain.OIDCAuthenticationRequest, error) {
	r, ok := f.IdentityRepository.(identityapp.OIDCAuthenticationRequestReader)
	if !ok {
		return identitydomain.OIDCAuthenticationRequest{}, ErrValidation
	}
	return r.ReadOIDCAuthenticationRequest(ctx, tenant, provider, id)
}
