package domain

import (
	"testing"
	"time"
)

func TestOIDCAuthenticationRequestHasExclusiveFiniteSingleUseLifetime(t *testing.T) {
	created := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	base := OIDCAuthenticationRequest{ID: "request", TenantID: "tenant", ProviderID: "provider", Delivery: "api", CreatedAt: created, ExpiresAt: created.Add(5 * time.Minute), SchemaVersion: OIDCAuthenticationRequestSchemaVersion}
	for _, tc := range []struct {
		name   string
		at     time.Time
		change func(*OIDCAuthenticationRequest)
		want   bool
	}{
		{"creation", created, nil, true},
		{"before deadline", created.Add(5*time.Minute - time.Microsecond), nil, true},
		{"deadline", created.Add(5 * time.Minute), nil, false},
		{"before creation", created.Add(-time.Microsecond), nil, false},
		{"overlong", created, func(r *OIDCAuthenticationRequest) { r.ExpiresAt = created.Add(5*time.Minute + time.Microsecond) }, false},
		{"missing creation", created, func(r *OIDCAuthenticationRequest) { r.CreatedAt = time.Time{} }, false},
		{"consumed", created, func(r *OIDCAuthenticationRequest) { r.ConsumedAt = &created }, false},
		{"missing tenant", created, func(r *OIDCAuthenticationRequest) { r.TenantID = "" }, false},
		{"missing provider", created, func(r *OIDCAuthenticationRequest) { r.ProviderID = "" }, false},
		{"unknown delivery", created, func(r *OIDCAuthenticationRequest) { r.Delivery = "redirect" }, false},
		{"browser delivery", created, func(r *OIDCAuthenticationRequest) { r.Delivery = "browser" }, true},
		{"unknown schema", created, func(r *OIDCAuthenticationRequest) { r.SchemaVersion = "unknown" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base
			if tc.change != nil {
				tc.change(&r)
			}
			if r.PendingAt(tc.at) != tc.want {
				t.Fatal("authentication request lifetime or single-use predicate mismatch")
			}
		})
	}
}
