package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type countingSSOFixtureDiscovery struct {
	fakeOIDCDiscoveryHTTP
	calls int
}

func (f *countingSSOFixtureDiscovery) FetchOIDCTrustMaterial(ctx context.Context, in app.OIDCDiscoveryRequest) (app.OIDCDiscoveryResult, error) {
	f.calls++
	return f.fakeOIDCDiscoveryHTTP.FetchOIDCTrustMaterial(ctx, in)
}
func publicSSOFixtureJWKS(kid string) map[string]any {
	return map[string]any{"keys": []any{map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": kid, "x": "public-only"}}}
}
func ssoFixtureLedger() (*app.Ledger, *app.MemoryUnitOfWorkFactory, *countingSSOFixtureDiscovery) {
	factory := app.NewMemoryUnitOfWorkFactory()
	discovery := &countingSSOFixtureDiscovery{fakeOIDCDiscoveryHTTP: fakeOIDCDiscoveryHTTP{result: app.OIDCDiscoveryResult{Issuer: "https://issuer.example.test", JWKS: publicSSOFixtureJWKS("discovered")}}}
	return newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, OIDC: discovery, Now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }}), factory, discovery
}

type ssoProviderFixtureScope struct {
	membershipFixtureScope
	provider domain.SSOProvider
}

func seedSSOProviderFixtureScope(t *testing.T, ledger *app.Ledger, name string) ssoProviderFixtureScope {
	t.Helper()
	f := ssoProviderFixtureScope{membershipFixtureScope: seedMembershipFixtureScope(t, ledger, name)}
	var err error
	f.provider, err = ledger.CreateSSOProvider(t.Context(), f.actor, app.CreateSSOProviderInput{Name: name, Type: "oidc", Issuer: "https://issuer.example.test", ClientID: "client", GroupsClaim: "groups", RoleMapping: map[string]string{"token-reviewers": "security_engineer"}, JWKS: publicSSOFixtureJWKS("initial")})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func ssoProviderFixtureRequests(f ssoProviderFixtureScope) []struct {
	name, path, body string
	status           int
} {
	return []struct {
		name, path, body string
		status           int
	}{
		{"create", "/v1/sso/providers", `{"name":"New","type":"oidc","issuer":"https://issuer.example.test","client_id":"client","groups_claim":"groups","role_mapping":{"token-reviewers":"security_engineer"},"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"created","x":"public-only"}]}}`, 201},
		{"update", "/v1/sso/providers/" + f.provider.ID + "/trust-material", `{"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"updated","x":"public-only"}]}}`, 200},
		{"discover", "/v1/sso/providers/" + f.provider.ID + "/discover-oidc", `{}`, 200},
		{"link", "/v1/sso/identity-links", fmt.Sprintf(`{"user_id":%q,"provider_id":%q,"subject":"identity@example.test","email":%q,"verified":true}`, f.user.ID, f.provider.ID, f.user.Email), 201},
	}
}

type failingSSOProviderFixture struct {
	ssoProviderFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingSSOProviderFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private SSO fixture failure after write")
}
func (f *failingSSOProviderFixture) CreateSSOProvider(ctx context.Context, a domain.Actor, in identityapp.CreateSSOProviderInput) (identitydomain.SSOProvider, error) {
	v, err := f.ssoProviderFixtureCommands.CreateSSOProvider(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingSSOProviderFixture) UpdateSSOProviderTrustMaterial(ctx context.Context, a domain.Actor, id string, in identityapp.UpdateSSOProviderTrustMaterialInput) (identitydomain.SSOProvider, error) {
	v, err := f.ssoProviderFixtureCommands.UpdateSSOProviderTrustMaterial(ctx, a, id, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingSSOProviderFixture) RefreshSSOProviderOIDCTrustMaterial(ctx context.Context, a domain.Actor, id string) (identitydomain.SSOProvider, error) {
	v, err := f.ssoProviderFixtureCommands.RefreshSSOProviderOIDCTrustMaterial(ctx, a, id)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingSSOProviderFixture) LinkSSOIdentity(ctx context.Context, a domain.Actor, in identityapp.LinkSSOIdentityInput) (identitydomain.UserIdentityLink, error) {
	v, err := f.ssoProviderFixtureCommands.LinkSSOIdentity(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}

func TestSSOProviderFixturesRollBackProviderTrustLinkAuditAndJobEffects(t *testing.T) {
	for index := 0; index < 4; index++ {
		ledger, factory, discovery := ssoFixtureLedger()
		owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
		request := ssoProviderFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: owner.actor}
			commands := &failingSSOProviderFixture{ssoProviderFixtureCommands: ssoProviderFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.ssoProviderCommands, server.ssoIdentityLinkCommands = commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, "failed-SSO", []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, "private SSO") || strings.Contains(out, `"data"`) || strings.Contains(out, "public-only") {
				t.Fatal("failed SSO command bypassed isolation or disclosed a partial DTO", out)
			}
			after, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Idempotency) != 1 {
				t.Fatal("failed SSO command lost failure receipt")
			}
			for _, r := range after.Idempotency {
				if r.State != app.IdempotencyFailed || r.Status != 0 || r.Response != nil {
					t.Fatal("failed SSO receipt retained response")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed SSO command committed provider, trust, link, audit or job effects")
			}
			wantCalls := 0
			if request.name == "discover" {
				wantCalls = 1
			}
			if discovery.calls != wantCalls {
				t.Fatal("discovery did not execute solely inside the real fresh command", discovery.calls, wantCalls)
			}
		})
	}
}

func TestSSOProviderFixturesReplayPublicDTOsAndRecheckCurrentAuthority(t *testing.T) {
	for index := 0; index < 4; index++ {
		ledger, factory, discovery := ssoFixtureLedger()
		owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
		foreign := seedSSOProviderFixtureScope(t, ledger, "Foreign")
		request := ssoProviderFixtureRequests(owner)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			human := owner.actor
			human.KeyID, human.UserID = "", owner.user.ID
			human.Scopes = []string{"identity:admin"}
			human.ResourceGrants = []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: human.TenantID, Scopes: []string{"identity:admin"}}}
			auth := &configuredAuthenticator{actor: human}
			server.authn = auth
			first := postRaw(t, server, "fixture-auth", request.path, "same-SSO", []byte(request.body), request.status)
			saved, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			id := dataField(t, first, "id")
			var expected any
			if request.name == "link" {
				expected = saved.IdentityLinks[id]
			} else {
				expected = saved.SSOProviders[id]
			}
			want, err := json.Marshal(map[string]any{"data": expected, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), first)
			last := saved.AuditEntries[human.TenantID][len(saved.AuditEntries[human.TenantID])-1]
			if last.ActorType != "human_user" || last.ActorID != human.UserID {
				t.Fatal("SSO audit lost human actor", last.ActorType, last.ActorID)
			}
			// A completed refresh returns the saved trust, not the provider's
			// later discovery result, and does not perform another network call.
			discovery.result.JWKS = publicSSOFixtureJWKS("later-discovery")
			replay := postRaw(t, server, "fixture-auth", request.path, "same-SSO", []byte(request.body), request.status)
			assertTrustHTTPReplay(t, first, replay)
			postRaw(t, server, "fixture-auth", request.path, "same-SSO", append([]byte(request.body), ' '), 409)
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"identity:admin"}}}, {{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"identity:admin"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, server, "fixture-auth", request.path, "same-SSO", []byte(request.body), 403)
				postRaw(t, server, "fixture-auth", request.path, "revoked-SSO", []byte(request.body), 403)
			}
			auth.actor = human
			if request.name == "link" {
				for label, body := range map[string]string{"user": strings.ReplaceAll(request.body, owner.user.ID, foreign.user.ID), "provider": strings.ReplaceAll(request.body, owner.provider.ID, foreign.provider.ID), "email": strings.ReplaceAll(request.body, owner.user.Email, foreign.user.Email)} {
					postRaw(t, server, "fixture-auth", request.path, "foreign-SSO-"+label, []byte(body), 404)
				}
			} else if request.name != "create" {
				postRaw(t, server, "fixture-auth", strings.ReplaceAll(request.path, owner.provider.ID, foreign.provider.ID), "foreign-SSO", []byte(request.body), 404)
			}
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(saved, after) {
				t.Fatal("SSO retry/conflict/revocation/foreign checks changed state", err)
			}
			wantCalls := 0
			if request.name == "discover" {
				wantCalls = 1
			}
			if discovery.calls != wantCalls {
				t.Fatal("SSO preflight/replay repeated discovery", discovery.calls, wantCalls)
			}
		})
	}
}

func TestSSOProviderFixtureGuardsArePureCancellableAndPreserveExplicitPorts(t *testing.T) {
	ledger, factory, discovery := ssoFixtureLedger()
	owner := seedSSOProviderFixtureScope(t, ledger, "Owner")
	f := ssoProviderFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{func(ctx context.Context) error {
		return f.AuthorizeCreateSSOProvider(ctx, owner.actor, identityapp.CreateSSOProviderInput{Name: "New", Type: "oidc", Issuer: owner.provider.Issuer, ClientID: "client", JWKS: publicSSOFixtureJWKS("new")})
	}, func(ctx context.Context) error {
		return f.AuthorizeUpdateSSOProviderTrustMaterial(ctx, owner.actor, owner.provider.ID, identityapp.UpdateSSOProviderTrustMaterialInput{JWKS: publicSSOFixtureJWKS("updated")})
	}, func(ctx context.Context) error {
		return f.AuthorizeRefreshSSOProviderOIDCTrustMaterial(ctx, owner.actor, owner.provider.ID)
	}, func(ctx context.Context) error {
		return f.AuthorizeLinkSSOIdentity(ctx, owner.actor, identityapp.LinkSSOIdentityInput{UserID: owner.user.ID, ProviderID: owner.provider.ID, Subject: "subject", Email: owner.user.Email, Verified: true})
	}} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("real SSO guard rejected owned references", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("SSO guard ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || discovery.calls != 0 {
		t.Fatal("SSO preflight wrote state or performed discovery", err)
	}
	providers, links := &ssoProviderHTTPFake{}, &identityLinkHTTPFake{}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{SSOProviderCommands: providers, SSOIdentityLinkCommands: links, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	server.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if server.ssoProviderCommands != providers || server.ssoIdentityLinkCommands != links {
		t.Fatal("fixture binding replaced explicit SSO ports")
	}
}
