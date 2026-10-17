package main

import (
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/config"
)

func sessionPolicyFromSettings(settings config.APISettings) identitydomain.SessionPolicy {
	return identitydomain.SessionPolicy{MaximumLifetime: settings.SSOSessionMaxLifetime, IdleTimeout: settings.SSOSessionIdleTimeout}
}
