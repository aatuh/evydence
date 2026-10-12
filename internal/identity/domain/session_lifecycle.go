package domain

import "time"

const MaximumSessionLifetime = 12 * time.Hour
const DefaultSessionIdleTimeout = 30 * time.Minute

// SessionPolicy may tighten the hard lifetime ceiling, never disable it.
// Issued sessions retain their policy so all processes enforce the same bounds.
type SessionPolicy struct {
	MaximumLifetime time.Duration
	IdleTimeout     time.Duration
}

func (p SessionPolicy) Normalized() (SessionPolicy, bool) {
	if p.MaximumLifetime == 0 {
		p.MaximumLifetime = MaximumSessionLifetime
	}
	if p.IdleTimeout == 0 {
		p.IdleTimeout = DefaultSessionIdleTimeout
	}
	return p, p.MaximumLifetime >= time.Minute && p.MaximumLifetime <= MaximumSessionLifetime &&
		p.IdleTimeout >= time.Minute && p.IdleTimeout <= p.MaximumLifetime &&
		p.MaximumLifetime%time.Second == 0 && p.IdleTimeout%time.Second == 0
}

func (s SSOSession) LifecyclePolicy() (SessionPolicy, bool) {
	// Validate seconds before multiplying untrusted persisted integers.
	for _, seconds := range []int64{s.MaximumLifetimeSeconds, s.IdleTimeoutSeconds} {
		if seconds != 0 && (seconds < 60 || seconds > int64(MaximumSessionLifetime/time.Second)) {
			return SessionPolicy{}, false
		}
	}
	return (SessionPolicy{MaximumLifetime: time.Duration(s.MaximumLifetimeSeconds) * time.Second, IdleTimeout: time.Duration(s.IdleTimeoutSeconds) * time.Second}).Normalized()
}

// ActiveAt uses exclusive expiry/idle bounds. Missing last-use metadata from
// an older row means creation time; an upgrade cannot revive an idle session.
func (s SSOSession) ActiveAt(now time.Time) bool {
	p, ok := s.LifecyclePolicy()
	if !ok || now.IsZero() || s.CreatedAt.IsZero() || now.Before(s.CreatedAt) ||
		s.RevokedAt != nil || !s.ExpiresAt.After(now) || s.ExpiresAt.After(s.CreatedAt.Add(p.MaximumLifetime)) {
		return false
	}
	last := s.CreatedAt
	if s.LastUsedAt != nil {
		last = *s.LastUsedAt
	}
	return !last.Before(s.CreatedAt) && last.Before(s.ExpiresAt) && now.Before(last.Add(p.IdleTimeout))
}
