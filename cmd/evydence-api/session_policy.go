package main

import (
	"errors"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func sessionPolicyFromEnv() (identitydomain.SessionPolicy, error) {
	maximum, err := boundedDurationSecondsEnv("EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS", 43200, 60, 43200)
	if err != nil {
		return identitydomain.SessionPolicy{}, err
	}
	idle, err := boundedDurationSecondsEnv("EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS", 1800, 60, 43200)
	if err != nil {
		return identitydomain.SessionPolicy{}, err
	}
	policy, ok := (identitydomain.SessionPolicy{MaximumLifetime: maximum, IdleTimeout: idle}).Normalized()
	if !ok {
		return identitydomain.SessionPolicy{}, errors.New("EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS must not exceed EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS")
	}
	return policy, nil
}
