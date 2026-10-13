package domain

import (
	"strings"
	"testing"
	"time"
)

func TestSAMLAssertionUseRequiresAHashAndFiniteUnexpiredProof(t *testing.T) {
	now := time.Date(2026, 10, 13, 17, 0, 0, 0, time.UTC)
	p := SAMLAssertionUse{AssertionHash: "sha256:" + strings.Repeat("a", 64), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if !p.ValidAt(now) || p.ValidAt(p.ExpiresAt) {
		t.Fatal("proof expiry is not exclusive")
	}
	for _, edit := range []func(*SAMLAssertionUse){
		func(v *SAMLAssertionUse) { v.AssertionHash = "" },
		func(v *SAMLAssertionUse) { v.AssertionHash = "sha256:" + strings.Repeat("A", 64) },
		func(v *SAMLAssertionUse) { v.IssuedAt = now.Add(61 * time.Second) },
		func(v *SAMLAssertionUse) { v.ExpiresAt = now.Add(5*time.Minute + time.Nanosecond) },
		func(v *SAMLAssertionUse) { v.ExpiresAt = now },
	} {
		v := p
		edit(&v)
		if v.ValidAt(now) {
			t.Fatal("invalid replay proof retained consumption authority")
		}
	}
}

func TestSAMLAuthenticationRequestHasExclusiveBoundedSingleUseLifetime(t *testing.T) {
	now := time.Date(2026, 10, 13, 17, 0, 0, 0, time.UTC)
	r := SAMLAuthenticationRequest{ID: "samlreq_fixture", TenantID: "tenant", ProviderID: "provider", Delivery: "api", Issuer: "https://idp.example.test", Audience: "sp", Recipient: "https://sp.example.test/v1/sso/session-exchanges", NameIDFormat: SAMLNameIDUnspecified, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute), SchemaVersion: SAMLAuthenticationRequestSchemaVersion}
	if !r.PendingAt(now) || r.PendingAt(r.ExpiresAt) || r.PendingAt(now.Add(-time.Nanosecond)) {
		t.Fatal("SAML state lifetime is not exclusive")
	}
	for _, edit := range []func(*SAMLAuthenticationRequest){
		func(v *SAMLAuthenticationRequest) { v.ID = "bad:request" },
		func(v *SAMLAuthenticationRequest) { v.TenantID = "" },
		func(v *SAMLAuthenticationRequest) { v.ProviderID = "" },
		func(v *SAMLAuthenticationRequest) { v.Recipient = "" },
		func(v *SAMLAuthenticationRequest) { v.NameIDFormat = "unknown" },
		func(v *SAMLAuthenticationRequest) { v.ExpiresAt = now.Add(5*time.Minute + time.Nanosecond) },
		func(v *SAMLAuthenticationRequest) { v.ConsumedAt = &now },
		func(v *SAMLAuthenticationRequest) { v.Delivery = "redirect" },
		func(v *SAMLAuthenticationRequest) { v.SchemaVersion = "future" },
	} {
		v := r
		edit(&v)
		if v.PendingAt(now) {
			t.Fatal("invalid SAML request retained authority")
		}
	}
}

func TestSAMLIdentifiersAndConfiguredNameIDFormatsAreExplicit(t *testing.T) {
	for _, value := range []string{"", "1request", "a:b", "a b", "é", string(make([]byte, 129))} {
		if ValidSAMLID(value) {
			t.Fatal("ambiguous SAML ID accepted")
		}
	}
	for _, value := range []string{"_request", "a", "a-1.2_3"} {
		if !ValidSAMLID(value) {
			t.Fatal("supported SAML ID rejected")
		}
	}
	if got, ok := NormalizeSAMLNameIDFormat(""); !ok || got != SAMLNameIDUnspecified {
		t.Fatal("default subject format is not explicit")
	}
	if _, ok := NormalizeSAMLNameIDFormat("unknown"); ok {
		t.Fatal("unknown subject namespace accepted")
	}
}
