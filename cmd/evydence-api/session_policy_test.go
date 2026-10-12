package main

import (
	"strings"
	"testing"
	"time"
)

func TestSessionPolicyEnvironmentHasBoundedDefaultsAndCanTighten(t *testing.T) {
	t.Setenv("EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS", "")
	t.Setenv("EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS", "")
	policy, err := sessionPolicyFromEnv()
	if err != nil || policy.MaximumLifetime != 12*time.Hour || policy.IdleTimeout != 30*time.Minute {
		t.Fatal("session defaults differ", err)
	}
	t.Setenv("EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS", "3600")
	t.Setenv("EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS", "300")
	policy, err = sessionPolicyFromEnv()
	if err != nil || policy.MaximumLifetime != time.Hour || policy.IdleTimeout != 5*time.Minute {
		t.Fatal("tightened policy was not retained", err)
	}
}

func TestSessionPolicyEnvironmentRejectsUnsafeValuesWithoutEchoingInput(t *testing.T) {
	for _, values := range [][2]string{{"0", "1800"}, {"43201", "1800"}, {"-1", "1800"}, {"43200", "0"}, {"60", "61"}, {"9223372036854775807", "1800"}, {"3600", "sensitive-placeholder"}, {"43200", "30.5"}} {
		t.Run(values[0]+"/"+values[1], func(t *testing.T) {
			t.Setenv("EVYDENCE_SSO_SESSION_MAX_LIFETIME_SECONDS", values[0])
			t.Setenv("EVYDENCE_SSO_SESSION_IDLE_TIMEOUT_SECONDS", values[1])
			_, err := sessionPolicyFromEnv()
			if err == nil || strings.Contains(err.Error(), "sensitive-placeholder") {
				t.Fatal("unsafe policy accepted or input exposed")
			}
		})
	}
}
