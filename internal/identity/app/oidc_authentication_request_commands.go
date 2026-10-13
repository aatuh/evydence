package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type OIDCRequestProviderReader interface {
	SSOProviderByID(context.Context, string) (identitydomain.SSOProvider, error)
}
type OIDCRequestCredentials interface {
	GenerateLoginState() (Credential, error)
	GenerateLoginNonce() (Credential, error)
	Hash(string) string
}
type OIDCAuthenticationRequestReader interface {
	ReadOIDCAuthenticationRequest(context.Context, string, string, string) (identitydomain.OIDCAuthenticationRequest, error)
}
type OIDCAuthenticationRequestConsumer interface {
	ConsumeOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, application.Clock) (time.Time, error)
}
type OIDCAuthenticationRequestTransaction interface {
	// Hold the current active OIDC provider/trust snapshot through commit.
	ValidateOIDCProvider(context.Context, identitydomain.SSOProvider) error
	// Under that provider's lock, prune bounded expired operational rows and
	// reject capacity overflow instead of allocating unbounded login state.
	InsertOIDCAuthenticationRequest(context.Context, identitydomain.OIDCAuthenticationRequest, time.Time) error
	application.AuditAppender
}
type OIDCAuthenticationRequestTransactions interface {
	ExecuteOIDCAuthenticationRequest(context.Context, func(context.Context, OIDCAuthenticationRequestTransaction) error) error
}
type OIDCAuthenticationRequestCommandConfig struct {
	Reader       OIDCRequestProviderReader
	Transactions OIDCAuthenticationRequestTransactions
	Credentials  OIDCRequestCredentials
	Clock        application.Clock
	IDs          application.IDGenerator
}
type BeginOIDCAuthenticationInput struct{ ProviderID, Delivery string }
type OIDCAuthenticationRequestCommands struct {
	config OIDCAuthenticationRequestCommandConfig
}

func NewOIDCAuthenticationRequestCommands(c OIDCAuthenticationRequestCommandConfig) (*OIDCAuthenticationRequestCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Credentials == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &OIDCAuthenticationRequestCommands{config: c}, nil
}

// OIDCProviderTrustFingerprint binds the complete configured provider snapshot
// using Evydence's existing normalized-JSON SHA-256 profile. No raw login state
// or nonce enters this public-trust binding.
func OIDCProviderTrustFingerprint(provider identitydomain.SSOProvider) (string, error) {
	return application.NormalizedJSONHash(cloneSSOProvider(provider))
}

func (s *OIDCAuthenticationRequestCommands) BeginOIDCAuthentication(ctx context.Context, in BeginOIDCAuthenticationInput) (identitydomain.OIDCAuthenticationRequest, string, string, error) {
	if s == nil || ctx == nil {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", err
	}
	if !validAPIKeyText(in.ProviderID, 1024) || !validAPIKeyText(in.Delivery, 16) {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", ErrValidation
	}
	in.ProviderID = strings.TrimSpace(in.ProviderID)
	in.Delivery = strings.TrimSpace(in.Delivery)
	if in.Delivery == "" {
		in.Delivery = "api"
	}
	if in.ProviderID == "" || (in.Delivery != "api" && in.Delivery != "browser") {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", ErrValidation
	}
	provider, err := s.config.Reader.SSOProviderByID(ctx, in.ProviderID)
	if err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", err
	}
	if provider.ID != in.ProviderID || !validAPIKeyID(provider.TenantID) || provider.Type != "oidc" || provider.Status != "active" || strings.TrimSpace(provider.Issuer) == "" || strings.TrimSpace(provider.ClientID) == "" || len(provider.JWKS) == 0 {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", ErrUnauthorized
	}
	provider = cloneSSOProvider(provider)
	fingerprint, err := OIDCProviderTrustFingerprint(provider)
	if err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", ErrValidation
	}
	var request identitydomain.OIDCAuthenticationRequest
	var state, nonce Credential
	err = s.config.Transactions.ExecuteOIDCAuthenticationRequest(ctx, func(ctx context.Context, tx OIDCAuthenticationRequestTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.ValidateOIDCProvider(ctx, cloneSSOProvider(provider)); err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validAPIKeyTime(now) || now.IsZero() {
			return ErrValidation
		}
		var err error
		state, err = s.config.Credentials.GenerateLoginState()
		if err != nil {
			return err
		}
		nonce, err = s.config.Credentials.GenerateLoginNonce()
		if err != nil {
			return err
		}
		if !validIssuedOIDCCredential(state, "evylogin_") || !validIssuedOIDCCredential(nonce, "evynonce_") || state.Hash != s.config.Credentials.Hash(state.Secret) || nonce.Hash != s.config.Credentials.Hash(nonce.Secret) || state.Hash == nonce.Hash {
			return ErrValidation
		}
		request = identitydomain.OIDCAuthenticationRequest{ID: s.config.IDs.NewID("oidcreq"), TenantID: provider.TenantID, ProviderID: provider.ID, Delivery: in.Delivery, TrustFingerprint: fingerprint, StateHash: state.Hash, NonceHash: nonce.Hash, CreatedAt: now, ExpiresAt: now.Add(identitydomain.MaximumOIDCAuthenticationRequestLifetime), SchemaVersion: identitydomain.OIDCAuthenticationRequestSchemaVersion}
		if !validAPIKeyID(request.ID) || !validAPIKeyTime(request.ExpiresAt) || !request.PendingAt(now) {
			return ErrValidation
		}
		if err := tx.InsertOIDCAuthenticationRequest(ctx, request, now); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("aud"), TenantID: provider.TenantID, EntryType: "oidc_authentication_request.created", SubjectType: "sso_provider", SubjectID: provider.ID, ActorType: "sso_authentication_request", ActorID: request.ID, OccurredAt: now})
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !request.PendingAt(s.config.Clock.Now().UTC()) {
			return ErrUnauthorized
		}
		return nil
	})
	if err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", err
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", err
	}
	if !request.PendingAt(s.config.Clock.Now().UTC()) {
		return identitydomain.OIDCAuthenticationRequest{}, "", "", ErrUnauthorized
	}
	return PublicOIDCAuthenticationRequest(request), state.Secret, nonce.Secret, nil
}

func PublicOIDCAuthenticationRequest(value identitydomain.OIDCAuthenticationRequest) identitydomain.OIDCAuthenticationRequest {
	value.StateHash = ""
	value.NonceHash = ""
	value.TrustFingerprint = ""
	if value.ConsumedAt != nil {
		at := *value.ConsumedAt
		value.ConsumedAt = &at
	}
	return value
}

func validIssuedOIDCCredential(value Credential, prefix string) bool {
	if len(value.Secret) != len(prefix)+43 || !strings.HasPrefix(value.Secret, prefix) || len(value.Prefix) != 12 || value.Prefix != value.Secret[:12] || len(value.Hash) != 64 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value.Secret[len(prefix):])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value.Secret[len(prefix):] {
		return false
	}
	hash, err := hex.DecodeString(value.Hash)
	return err == nil && len(hash) == 32 && value.Hash == strings.ToLower(value.Hash)
}
