package wiring

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func samlBindingWiringActor() identitydomain.Actor {
	return identitydomain.Actor{TenantID: "tenant", UserID: "user", Scopes: []string{identityapp.ScopeIdentityAdmin}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{identityapp.ScopeIdentityAdmin}}}}
}

func TestPostgresSAMLConfigurationAndRequestUseFocusedRuntimePorts(t *testing.T) {
	store, pool := openHTMLReportWiringStore(t)
	_ = seedSSOExchangeWiring(t, pool)
	if _, err := pool.Exec(t.Context(), `UPDATE sso_providers SET type='saml',jwks='{}',saml_signing_certificates='["fixture public certificate"]' WHERE id='provider'`); err != nil {
		t.Fatal(err)
	}
	canary := newAggregateLoadCanary(t, t.Context(), store)
	c, err := BuildSAMLProviderBindingCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	a := samlBindingWiringActor()
	in := identityapp.ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/v1/sso/session-exchanges"}
	b, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in)
	if err != nil || b.TenantID != "tenant" || b.ProviderID != "provider" || b.Recipient != in.Recipient || b.NameIDFormat != identitydomain.SAMLNameIDUnspecified {
		t.Fatal("native binding creation failed", err)
	}
	counts := func() [3]int {
		t.Helper()
		var out [3]int
		if err := pool.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM saml_provider_bindings),(SELECT count(*)FROM saml_authentication_requests),(SELECT count(*)FROM audit_chain_entries)`).Scan(&out[0], &out[1], &out[2]); err != nil {
			t.Fatal(err)
		}
		return out
	}
	before := counts()
	if err := c.AuthorizeConfigureSAMLProviderBinding(t.Context(), a, "provider", in); err != nil || counts() != before {
		t.Fatal("native replay guard changed binding or audit", err)
	}
	restarted, err := BuildSAMLProviderBindingCommands(store)
	if err != nil {
		t.Fatal(err)
	}
	got, err := restarted.GetSAMLProviderBinding(t.Context(), a, "provider")
	if err != nil || !reflect.DeepEqual(b, got) || counts() != before {
		t.Fatal("native binding did not survive reconstruction", err)
	}
	a.ResourceGrants = nil
	if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in); !errors.Is(err, application.ErrForbidden) || counts() != before {
		t.Fatal("native configuration bypassed revoked tenant grant", err)
	}
	if _, err := c.GetSAMLProviderBinding(t.Context(), a, "provider"); !errors.Is(err, application.ErrForbidden) || counts() != before {
		t.Fatal("native read bypassed revoked tenant grant", err)
	}
	a = samlBindingWiringActor()
	if _, err := pool.Exec(t.Context(), `INSERT INTO sso_providers(id,tenant_id,name,type,issuer,client_id,status,schema_version,created_at,saml_signing_certificates)SELECT 'foreign','other',name,type,issuer,client_id,status,schema_version,created_at,saml_signing_certificates FROM sso_providers WHERE id='provider'`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "foreign", in); !errors.Is(err, identityapp.ErrNotFound) || counts() != before {
		t.Fatal("native configuration crossed tenant boundary", err)
	}
	begin, err := BuildSAMLAuthenticationRequestCommands(store, "saml-request-runtime-pepper", false)
	if err != nil {
		t.Fatal(err)
	}
	r, state, err := begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"})
	if err != nil || r.ID == "" || state == "" || r.StateHash != "" || r.TrustFingerprint != "" || r.Recipient != b.Recipient || r.NameIDFormat != b.NameIDFormat {
		t.Fatal("native request creation leaked or lost bindings", err)
	}
	credentials, err := identityapp.NewHMACAuthenticationCredentials("saml-request-runtime-pepper")
	if err != nil {
		t.Fatal(err)
	}
	var storedHash string
	if err := pool.QueryRow(t.Context(), `SELECT state_hash FROM saml_authentication_requests WHERE tenant_id='tenant' AND provider_id='provider' AND id=$1`, r.ID).Scan(&storedHash); err != nil || storedHash != credentials.Hash(state) || counts() != [3]int{before[0], before[1] + 1, before[2] + 1} || !canary.Intact(t.Context()) {
		t.Fatal("native request lost atomic hash-only state/audit or reloaded aggregate", err)
	}
	if c, err := BuildSAMLProviderBindingCommands(nil); err == nil || c != nil {
		t.Fatal("missing binding factory accepted")
	}
	if c, err := BuildSAMLAuthenticationRequestCommands(nil, "pepper", false); err == nil || c != nil {
		t.Fatal("missing request factory accepted")
	}
	if c, err := BuildSAMLAuthenticationRequestCommands(store, "", true); err == nil || c != nil {
		t.Fatal("production SAML state accepted missing credential pepper")
	}
}

func TestPostgresSAMLRuntimeRollbackWithholdsStateAndConfiguration(t *testing.T) {
	for _, stage := range []string{"binding write", "binding audit", "binding commit", "request write", "request audit", "request commit"} {
		t.Run(stage, func(t *testing.T) {
			store, pool := openHTMLReportWiringStore(t)
			_ = seedSSOExchangeWiring(t, pool)
			if _, err := pool.Exec(t.Context(), `UPDATE sso_providers SET type='saml',jwks='{}',saml_signing_certificates='["fixture public certificate"]' WHERE id='provider'`); err != nil {
				t.Fatal(err)
			}
			c, err := BuildSAMLProviderBindingCommands(store)
			if err != nil {
				t.Fatal(err)
			}
			a, in := samlBindingWiringActor(), identityapp.ConfigureSAMLProviderBindingInput{Recipient: "https://sp.example.test/consume"}
			requestStage := stage[:7] == "request"
			if requestStage {
				if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in); err != nil {
					t.Fatal(err)
				}
			}
			counts := func() [3]int {
				t.Helper()
				var v [3]int
				if err := pool.QueryRow(t.Context(), `SELECT(SELECT count(*)FROM saml_provider_bindings),(SELECT count(*)FROM saml_authentication_requests),(SELECT count(*)FROM audit_chain_entries)`).Scan(&v[0], &v[1], &v[2]); err != nil {
					t.Fatal(err)
				}
				return v
			}
			before := counts()
			table := "saml_provider_bindings"
			if requestStage {
				table = "saml_authentication_requests"
			}
			definition := "CREATE TRIGGER reject_saml_stage BEFORE INSERT ON "
			if stage == "binding audit" || stage == "request audit" {
				table = "audit_chain_entries"
			}
			if stage == "binding commit" || stage == "request commit" {
				definition = "CREATE CONSTRAINT TRIGGER reject_saml_stage AFTER INSERT ON "
			}
			definition += table
			if stage == "binding commit" || stage == "request commit" {
				definition += " DEFERRABLE INITIALLY DEFERRED"
			}
			definition += " FOR EACH ROW EXECUTE FUNCTION reject_saml_stage()"
			if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_saml_stage()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'private SAML storage failure';END$$;`+definition); err != nil {
				t.Fatal(err)
			}
			begin, err := BuildSAMLAuthenticationRequestCommands(store, "saml-request-runtime-pepper", false)
			if err != nil {
				t.Fatal(err)
			}
			if requestStage {
				if r, state, err := begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"}); err == nil || state != "" || r.ID != "" || counts() != before {
					t.Fatal("failed native request published secret or partial effects", err)
				}
			} else if b, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in); err == nil || b.ProviderID != "" || counts() != before {
				t.Fatal("failed native configuration published partial effects", err)
			}
			if _, err := pool.Exec(t.Context(), "DROP TRIGGER reject_saml_stage ON "+table); err != nil {
				t.Fatal(err)
			}
			if requestStage {
				if r, state, err := begin.BeginSAMLAuthentication(t.Context(), identityapp.BeginSAMLAuthenticationInput{ProviderID: "provider"}); err != nil || state == "" || r.ID == "" {
					t.Fatal("native request could not retry after rollback", err)
				}
			} else if _, err := c.ConfigureSAMLProviderBinding(t.Context(), a, "provider", in); err != nil {
				t.Fatal("native binding could not retry after rollback", err)
			}
		})
	}
}
