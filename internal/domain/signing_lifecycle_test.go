package domain

import (
	"testing"
	"time"
)

func TestSigningKeyHistoricalValidityIsDeterministic(t *testing.T) {
	signedAt := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	retiredAt := signedAt.Add(time.Hour)
	verifiedAt := retiredAt.Add(24 * time.Hour)
	key := SigningKey{
		Status:                   SigningKeyStatusRetiring,
		ValidFrom:                signedAt.Add(-time.Hour),
		ValidUntil:               &retiredAt,
		HistoricalValidityPolicy: SigningKeyHistoricalValidityPreserve,
	}

	if got := key.HistoricalValidityAt(signedAt, verifiedAt); got != SigningKeyHistoricalValidityValid {
		t.Fatalf("historical validity=%q, want %q", got, SigningKeyHistoricalValidityValid)
	}
	if got := key.HistoricalValidityAt(retiredAt.Add(time.Nanosecond), verifiedAt); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("post-retirement validity=%q, want %q", got, SigningKeyHistoricalValidityOutsideWindow)
	}
}

func TestCompromisedSigningKeyCanInvalidateHistoricalSignatures(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	key := SigningKey{
		Status:                   SigningKeyStatusRevoked,
		ValidFrom:                now.Add(-time.Hour),
		RevokedAt:                &now,
		RevocationSemantics:      SigningKeyRevocationCompromised,
		HistoricalValidityPolicy: SigningKeyHistoricalValidityInvalidateAll,
	}

	if got := key.HistoricalValidityAt(now.Add(-30*time.Minute), now.Add(time.Hour)); got != SigningKeyHistoricalValidityCompromised {
		t.Fatalf("compromised validity=%q, want %q", got, SigningKeyHistoricalValidityCompromised)
	}
}

func TestLegacyRevokedSigningKeyRetainsItsHistoricalUpperBound(t *testing.T) {
	revokedAt := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	key := SigningKey{Status: SigningKeyStatusRevoked, CreatedAt: revokedAt.Add(-time.Hour), RevokedAt: &revokedAt}
	if got := key.HistoricalValidityAt(revokedAt.Add(time.Nanosecond), revokedAt.Add(time.Hour)); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("legacy post-revocation validity=%q, want %q", got, SigningKeyHistoricalValidityOutsideWindow)
	}
}

func TestSigningKeyHistoricalValidityRejectsInvalidTimesAndSupportsCompromiseCutoff(t *testing.T) {
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	if got := (SigningKey{}).HistoricalValidityAt(now, now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("zero lifecycle validity=%q, want %q", got, SigningKeyHistoricalValidityOutsideWindow)
	}
	key := SigningKey{ValidFrom: now, ValidUntil: timePointer(now.Add(time.Hour))}
	if got := key.HistoricalValidityAt(now.Add(-time.Nanosecond), now); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("pre-validity validity=%q, want %q", got, SigningKeyHistoricalValidityOutsideWindow)
	}
	if got := key.HistoricalValidityAt(now, now.Add(-time.Nanosecond)); got != SigningKeyHistoricalValidityOutsideWindow {
		t.Fatalf("pre-signature verification validity=%q, want %q", got, SigningKeyHistoricalValidityOutsideWindow)
	}
	compromisedAt := now.Add(30 * time.Minute)
	key = SigningKey{ValidFrom: now.Add(-time.Hour), RevokedAt: &compromisedAt, RevocationSemantics: SigningKeyRevocationCompromised, HistoricalValidityPolicy: SigningKeyHistoricalValidityInvalidateFromCompromise}
	if got := key.HistoricalValidityAt(now, compromisedAt.Add(time.Hour)); got != SigningKeyHistoricalValidityValid {
		t.Fatalf("pre-compromise validity=%q, want %q", got, SigningKeyHistoricalValidityValid)
	}
	if got := key.HistoricalValidityAt(compromisedAt, compromisedAt.Add(time.Hour)); got != SigningKeyHistoricalValidityCompromised {
		t.Fatalf("post-compromise validity=%q, want %q", got, SigningKeyHistoricalValidityCompromised)
	}
}

func timePointer(value time.Time) *time.Time { return &value }
