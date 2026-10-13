package repositories_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresrepositories "github.com/aatuh/evydence/internal/adapters/postgres/repositories"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
)

func TestProviderTrustRotationMatchesHistoricalEmptyCollectionsButRejectsStaleKeys(t *testing.T) {
	for _, kind := range []string{"saml", "oidc"} {
		t.Run(kind, func(t *testing.T) {
			ctx, pool := openRepositoryTestPool(t)
			defer pool.Close()
			jwks, certs := `{}`, `["old public certificate metadata"]`
			if kind == "oidc" {
				jwks, certs = `{"keys":[{"kid":"old public key metadata"}]}`, `[]`
			}
			if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name)VALUES('tenant','Historical trust'); INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at,jwks,saml_signing_certificates)VALUES('provider','tenant','Provider','`+kind+`','https://issuer.example.test','client','active','sso-provider.v1',now(),'`+jwks+`','`+certs+`')`); err != nil {
				t.Fatal(err)
			}
			tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			r := postgresrepositories.New(tx).Identity
			reader, ok := r.(identityapp.SSOProviderWriteReader)
			if !ok {
				t.Fatal("focused owned provider reader missing")
			}
			before, err := reader.ReadOwnedSSOProvider(ctx, "tenant", "provider")
			if err != nil {
				t.Fatal(err)
			}
			if kind == "saml" && before.JWKS != nil || kind == "oidc" && before.SAMLSigningCertificates != nil {
				t.Fatal("historical empty trust was not normalized")
			}
			after := domain.SSOProvider(before)
			at := time.Now().UTC().Truncate(time.Microsecond)
			after.TrustMaterialUpdatedAt = &at
			if kind == "saml" {
				after.SAMLSigningCertificates = []string{"new public certificate metadata"}
			} else {
				after.JWKS = map[string]any{"keys": []any{map[string]any{"kid": "new public key metadata"}}}
			}
			if err := r.CompareAndSwapSSOProviderTrustMaterial(ctx, domain.SSOProvider(before), after); err != nil {
				t.Fatal("unchanged historical empty collection blocked rotation", err)
			}
			stale := after
			at = at.Add(time.Second)
			stale.TrustMaterialUpdatedAt = &at
			if err := r.CompareAndSwapSSOProviderTrustMaterial(ctx, domain.SSOProvider(before), stale); !errors.Is(err, app.ErrConflict) {
				t.Fatal("empty-collection equivalence bypassed populated trust comparison", err)
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
