package app

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SAMLRequestProviderReader interface {
	SAMLProviderBindingByID(context.Context, string) (identitydomain.SAMLProviderBinding, error)
}
type SAMLRequestCredentials interface {
	GenerateLoginState() (Credential, error)
	Hash(string) string
}
type SAMLAuthenticationRequestReader interface {
	ReadSAMLAuthenticationRequest(context.Context, string, string, string) (identitydomain.SAMLAuthenticationRequest, error)
}
type SAMLAuthenticationRequestConsumer interface {
	// Atomically consume request state and the scoped assertion hash after
	// current trust/request locks. Recheck both deadlines after lock waits.
	ConsumeSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, identitydomain.SAMLAssertionUse, application.Clock) (time.Time, error)
}
type SAMLAuthenticationRequestTransaction interface {
	ValidateSAMLProviderBinding(context.Context, identitydomain.SAMLProviderBinding) error
	// Capacity and expiry cleanup must be bounded under the provider lock.
	InsertSAMLAuthenticationRequest(context.Context, identitydomain.SAMLAuthenticationRequest, time.Time) error
	application.AuditAppender
}
type SAMLAuthenticationRequestTransactions interface {
	ExecuteSAMLAuthenticationRequest(context.Context, func(context.Context, SAMLAuthenticationRequestTransaction) error) error
}
type SAMLAuthenticationRequestCommandConfig struct {
	Reader       SAMLRequestProviderReader
	Transactions SAMLAuthenticationRequestTransactions
	Credentials  SAMLRequestCredentials
	Clock        application.Clock
	IDs          application.IDGenerator
}
type BeginSAMLAuthenticationInput struct{ ProviderID, Delivery string }
type SAMLAuthenticationRequestCommands struct {
	config SAMLAuthenticationRequestCommandConfig
}

func NewSAMLAuthenticationRequestCommands(c SAMLAuthenticationRequestCommandConfig) (*SAMLAuthenticationRequestCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Credentials == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SAMLAuthenticationRequestCommands{config: c}, nil
}

func NormalizeSAMLBindingParameters(recipient, format string) (string, string, error) {
	if !validAPIKeyText(recipient, 4096) || !validAPIKeyText(format, 256) {
		return "", "", ErrValidation
	}
	u, err := url.Parse(recipient)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.String() != recipient {
		return "", "", ErrValidation
	}
	format, ok := identitydomain.NormalizeSAMLNameIDFormat(format)
	if !ok {
		return "", "", ErrValidation
	}
	return recipient, format, nil
}

func cloneSAMLProviderBinding(b identitydomain.SAMLProviderBinding) identitydomain.SAMLProviderBinding {
	b.Provider = cloneSSOProvider(b.Provider)
	return b
}
func ValidSAMLProviderBinding(b identitydomain.SAMLProviderBinding) bool {
	_, format, err := NormalizeSAMLBindingParameters(b.Recipient, b.NameIDFormat)
	p := b.Provider
	return err == nil && format == b.NameIDFormat && b.SchemaVersion == identitydomain.SAMLProviderBindingSchemaVersion && validAPIKeyTime(b.UpdatedAt) && !b.UpdatedAt.IsZero() && validAPIKeyID(b.TenantID) && validAPIKeyID(b.ProviderID) && p.TenantID == b.TenantID && p.ID == b.ProviderID && p.Type == "saml" && p.Status == "active" && p.Issuer != "" && validAPIKeyText(p.Issuer, 4096) && p.ClientID != "" && validAPIKeyText(p.ClientID, 4096) && len(p.SAMLSigningCertificates) > 0 && len(p.SAMLSigningCertificates) <= 5
}

// SAMLProviderTrustFingerprint binds both the existing provider trust snapshot
// and its tenant-owned SP binding using the normalized-JSON SHA-256 profile.
func SAMLProviderTrustFingerprint(b identitydomain.SAMLProviderBinding) (string, error) {
	return application.NormalizedJSONHash(cloneSAMLProviderBinding(b))
}

func SAMLAssertionFingerprint(r identitydomain.SAMLAuthenticationRequest, id string) (string, error) {
	if !identitydomain.ValidSAMLID(id) || !validAPIKeyID(r.TenantID) || !validAPIKeyID(r.ProviderID) || r.Issuer == "" {
		return "", ErrValidation
	}
	return application.NormalizedJSONHash(struct{ SchemaVersion, TenantID, ProviderID, Issuer, AssertionID string }{"saml-assertion-replay.v1.0.0", r.TenantID, r.ProviderID, r.Issuer, id})
}

func (s *SAMLAuthenticationRequestCommands) BeginSAMLAuthentication(ctx context.Context, in BeginSAMLAuthenticationInput) (identitydomain.SAMLAuthenticationRequest, string, error) {
	if s == nil || ctx == nil {
		return identitydomain.SAMLAuthenticationRequest{}, "", ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, "", err
	}
	if !validAPIKeyText(in.ProviderID, 1024) || !validAPIKeyText(in.Delivery, 16) {
		return identitydomain.SAMLAuthenticationRequest{}, "", ErrValidation
	}
	in.ProviderID = strings.TrimSpace(in.ProviderID)
	in.Delivery = strings.TrimSpace(in.Delivery)
	if in.Delivery == "" {
		in.Delivery = "api"
	}
	if in.ProviderID == "" || in.Delivery != "api" && in.Delivery != "browser" {
		return identitydomain.SAMLAuthenticationRequest{}, "", ErrValidation
	}
	binding, err := s.config.Reader.SAMLProviderBindingByID(ctx, in.ProviderID)
	if err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, "", err
	}
	if binding.ProviderID != in.ProviderID || !ValidSAMLProviderBinding(binding) {
		return identitydomain.SAMLAuthenticationRequest{}, "", ErrUnauthorized
	}
	binding = cloneSAMLProviderBinding(binding)
	fingerprint, err := SAMLProviderTrustFingerprint(binding)
	if err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, "", ErrValidation
	}
	var request identitydomain.SAMLAuthenticationRequest
	var state Credential
	err = s.config.Transactions.ExecuteSAMLAuthenticationRequest(ctx, func(ctx context.Context, tx SAMLAuthenticationRequestTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.ValidateSAMLProviderBinding(ctx, cloneSAMLProviderBinding(binding)); err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || !validAPIKeyTime(now) {
			return ErrValidation
		}
		var err error
		state, err = s.config.Credentials.GenerateLoginState()
		if err != nil {
			return err
		}
		if !validIssuedLoginCredential(state, "evylogin_") || state.Hash != s.config.Credentials.Hash(state.Secret) {
			return ErrValidation
		}
		request = identitydomain.SAMLAuthenticationRequest{ID: s.config.IDs.NewID("samlreq"), TenantID: binding.TenantID, ProviderID: binding.ProviderID, Delivery: in.Delivery, Issuer: binding.Provider.Issuer, Audience: binding.Provider.ClientID, Recipient: binding.Recipient, NameIDFormat: binding.NameIDFormat, TrustFingerprint: fingerprint, StateHash: state.Hash, CreatedAt: now, ExpiresAt: now.Add(identitydomain.MaximumSAMLAuthenticationRequestLifetime), SchemaVersion: identitydomain.SAMLAuthenticationRequestSchemaVersion}
		if !request.PendingAt(now) {
			return ErrValidation
		}
		if err := tx.InsertSAMLAuthenticationRequest(ctx, request, now); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("aud"), TenantID: binding.TenantID, EntryType: "saml_authentication_request.created", SubjectType: "sso_provider", SubjectID: binding.ProviderID, ActorType: "sso_authentication_request", ActorID: request.ID, OccurredAt: now})
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
		return identitydomain.SAMLAuthenticationRequest{}, "", err
	}
	if err := ctx.Err(); err != nil {
		return identitydomain.SAMLAuthenticationRequest{}, "", err
	}
	if !request.PendingAt(s.config.Clock.Now().UTC()) {
		return identitydomain.SAMLAuthenticationRequest{}, "", ErrUnauthorized
	}
	return PublicSAMLAuthenticationRequest(request), state.Secret, nil
}

func PublicSAMLAuthenticationRequest(r identitydomain.SAMLAuthenticationRequest) identitydomain.SAMLAuthenticationRequest {
	r.StateHash, r.TrustFingerprint = "", ""
	if r.ConsumedAt != nil {
		at := *r.ConsumedAt
		r.ConsumedAt = &at
	}
	return r
}
