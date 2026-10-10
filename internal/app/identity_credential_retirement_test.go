package app

import (
	"encoding/base64"
	"strings"
	"testing"

	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestIdentityOwnedCredentialsPreserveHistoricalHashesPrefixesAndComparisons(t *testing.T) {
	for _, pepper := range []string{"test-pepper", "longer-public-fixture-pepper", "unicode-é-pepper"} {
		ledger := newLegacyLedgerFixture(Config{APIKeyPepper: pepper})
		legacy := ledgerCredentialManager{ledger: ledger}
		owned, err := identityapp.NewHMACAuthenticationCredentials(pepper)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"", "short", "evy_0123456789abcdefghijklmnopqrstuvwxyz", "evysso_0123456789abcdefghijklmnopqrstuvwxyz", "evycp_0123456789abcdefghijklmnopqrstuvwxyz", "unicode-é-secret"} {
			if owned.Hash(secret) != legacy.Hash(secret) || owned.Prefix(secret) != legacy.Prefix(secret) || !owned.Equal(owned.Hash(secret), legacy.Hash(secret)) {
				t.Fatal("owned credential format changed historical storage interpretation")
			}
			for _, invalid := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.ToUpper(owned.Hash(secret))} {
				if owned.Equal(owned.Hash(secret), invalid) != legacy.Equal(legacy.Hash(secret), invalid) {
					t.Fatal("owned comparison changed malformed/case-sensitive hash policy")
				}
			}
		}
		for _, generate := range []struct {
			prefix     string
			issue      func() (identityapp.Credential, error)
			historical func() (identityapp.Credential, error)
		}{{"evy_", owned.Generate, legacy.Generate}, {"evysso_", owned.GenerateSession, (ledgerSessionCredentialManager{ledger: ledger}).GenerateSession}} {
			for _, issue := range []func() (identityapp.Credential, error){generate.issue, generate.historical} {
				v, err := issue()
				if err != nil || !strings.HasPrefix(v.Secret, generate.prefix) || len(v.Secret) != len(generate.prefix)+43 || v.Prefix != legacy.Prefix(v.Secret) || !legacy.Equal(v.Hash, legacy.Hash(v.Secret)) {
					t.Fatal("credential issuance changed prefix, entropy encoding or stored hash", err)
				}
				entropy, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v.Secret, generate.prefix))
				if err != nil || len(entropy) != 32 {
					t.Fatal("credential issuance changed 32-byte URL-safe entropy format")
				}
			}
		}
	}
}
