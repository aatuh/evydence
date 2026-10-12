package domain

import (
	"math"
	"testing"
	"time"
)

func TestSSOSessionLifecycleBounds(t *testing.T) {
	created := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	session := SSOSession{CreatedAt: created, ExpiresAt: created.Add(8 * time.Hour)}
	for _, test := range []struct {
		name   string
		at     time.Time
		change func(*SSOSession)
		want   bool
	}{
		{"creation", created, nil, true},
		{"before idle deadline", created.Add(30*time.Minute - time.Microsecond), nil, true},
		{"idle deadline", created.Add(30 * time.Minute), nil, false},
		{"before creation", created.Add(-time.Microsecond), nil, false},
		{"missing creation", created, func(s *SSOSession) { s.CreatedAt = time.Time{} }, false},
		{"absolute deadline", session.ExpiresAt, func(s *SSOSession) { last := session.ExpiresAt.Add(-time.Minute); s.LastUsedAt = &last }, false},
		{"maximum lifetime exceeded", created, func(s *SSOSession) { s.ExpiresAt = created.Add(12*time.Hour + time.Microsecond) }, false},
		{"revoked", created, func(s *SSOSession) { s.RevokedAt = &created }, false},
		{"activity before creation", created, func(s *SSOSession) { last := created.Add(-time.Second); s.LastUsedAt = &last }, false},
		{"activity at expiry", created, func(s *SSOSession) { last := s.ExpiresAt; s.LastUsedAt = &last }, false},
		{"activity extends idle only", created.Add(time.Hour), func(s *SSOSession) { last := created.Add(45 * time.Minute); s.LastUsedAt = &last }, true},
		{"stricter idle", created.Add(5 * time.Minute), func(s *SSOSession) { s.IdleTimeoutSeconds = 300 }, false},
		{"stricter maximum", created, func(s *SSOSession) { s.MaximumLifetimeSeconds = 3600 }, false},
		{"invalid idle", created, func(s *SSOSession) { s.IdleTimeoutSeconds = -1 }, false},
		{"overflow maximum", created, func(s *SSOSession) { s.MaximumLifetimeSeconds = math.MaxInt64 }, false},
		{"overflow idle", created, func(s *SSOSession) { s.IdleTimeoutSeconds = math.MaxInt64 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := session
			if test.change != nil {
				test.change(&s)
			}
			if got := s.ActiveAt(test.at); got != test.want {
				t.Fatalf("ActiveAt = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSessionPolicyCannotDisableOrExceedLifecycleBounds(t *testing.T) {
	for _, policy := range []SessionPolicy{
		{MaximumLifetime: -time.Second}, {IdleTimeout: -time.Second},
		{MaximumLifetime: 13 * time.Hour}, {IdleTimeout: 13 * time.Hour},
		{MaximumLifetime: time.Minute, IdleTimeout: 2 * time.Minute},
		{IdleTimeout: 30 * time.Second}, {IdleTimeout: time.Minute + time.Nanosecond},
	} {
		if _, ok := policy.Normalized(); ok {
			t.Fatalf("unsafe policy accepted: %#v", policy)
		}
	}
	policy, ok := (SessionPolicy{}).Normalized()
	if !ok || policy.MaximumLifetime != 12*time.Hour || policy.IdleTimeout != 30*time.Minute {
		t.Fatal("bounded defaults changed")
	}
}
