package wiring

import (
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

// BuildAuthenticator composes durable credential verification. The local
// compatibility pepper is never accepted in production.
func BuildAuthenticator(reader identityapp.AuthenticationReader, activity identityapp.AuthenticationActivity, pepper string, production bool) (*identityapp.Authenticator, error) {
	credentials, err := buildAuthenticationCredentials(pepper, production)
	if err != nil {
		return nil, err
	}
	return identityapp.NewAuthenticator(identityapp.AuthenticationConfig{
		Reader: reader, Activity: activity, Credentials: credentials,
		Clock: application.ClockFunc(func() time.Time { return time.Now().UTC() }),
	})
}

// Issuance and verification share the same production-safety and pepper rules.
func buildAuthenticationCredentials(pepper string, production bool) (*identityapp.HMACAuthenticationCredentials, error) {
	pepper = strings.TrimSpace(pepper)
	if pepper == "" {
		if production {
			return nil, identityapp.ErrValidation
		}
		pepper = identityapp.LocalDevelopmentPepper
	}
	if production && pepper == identityapp.LocalDevelopmentPepper {
		return nil, identityapp.ErrValidation
	}
	return identityapp.NewHMACAuthenticationCredentials(pepper)
}
