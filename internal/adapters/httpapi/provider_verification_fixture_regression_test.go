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

// This fake is an observable I/O boundary, not evidence of provider truth.
type providerVerificationFixtureAPI struct {
	requests []app.ProviderIdentityValidationRequest
	mode     string
	hook     func()
}

func (f *providerVerificationFixtureAPI) ValidateProviderIdentity(ctx context.Context, r app.ProviderIdentityValidationRequest) (app.ProviderIdentityValidationResult, error) {
	f.requests = append(f.requests, r)
	if f.hook != nil {
		f.hook()
	}
	if err := ctx.Err(); err != nil {
		return app.ProviderIdentityValidationResult{}, err
	}
	if f.mode == "unavailable" {
		return app.ProviderIdentityValidationResult{}, errors.New("private provider response " + r.AccessToken)
	}
	v := app.ProviderIdentityValidationResult{Checks: []domain.VerifyCheck{{Name: "live_subject", Result: "passed", Detail: "credential echo " + r.AccessToken}}, Groups: []string{"token-reviewers"}, Limitations: []string{"safe receipt: " + r.AccessToken}}
	if f.mode == "malformed" {
		v.Checks[0].Result = "unrecognized"
	}
	return v, nil
}
func providerVerificationRegressionLedger() (*app.Ledger, *app.MemoryUnitOfWorkFactory, *providerVerificationFixtureAPI) {
	factory, live := app.NewMemoryUnitOfWorkFactory(), &providerVerificationFixtureAPI{}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "fixture-pepper", UnitOfWork: factory, ProviderAPI: live, Now: func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) }})
	return ledger, factory, live
}
func seedProviderVerificationFixture(t *testing.T, ledger *app.Ledger, name string) ssoProviderFixtureScope {
	t.Helper()
	f := seedSSOProviderFixtureScope(t, ledger, name)
	_, err := ledger.LinkSSOIdentity(t.Context(), f.actor, app.LinkSSOIdentityInput{UserID: f.user.ID, ProviderID: f.provider.ID, Subject: "subject-" + name, Email: f.user.Email, Verified: true})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func providerVerificationFixtureBody(f ssoProviderFixtureScope, credential string) string {
	return fmt.Sprintf(`{"provider_type":"oidc","provider_id":%q,"subject":%q%s}`, f.provider.ID, "subject-"+f.provider.Name, credential)
}
func providerVerificationFixtureHuman(f ssoProviderFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: f.user.ID, Scopes: []string{"identity:admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: f.actor.TenantID, Scopes: []string{"identity:admin"}}}}
}
func assertProviderVerificationFixturePrivate(t *testing.T, state app.MemoryUnitOfWorkSnapshot, secret string) {
	t.Helper()
	values := []any{state.ProviderVerifications, state.AuditEntries}
	for _, receipt := range state.Idempotency {
		values = append(values, receipt)
	}
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil || strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "private provider response") {
			t.Fatal("provider assessment/audit/replay retained credentials or private provider errors", err)
		}
	}
}

type failingProviderVerificationFixture struct {
	providerVerificationFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingProviderVerificationFixture) VerifyProviderIdentity(ctx context.Context, a domain.Actor, in identityapp.VerifyProviderIdentityInput) (identitydomain.ProviderVerification, error) {
	v, err := f.providerVerificationFixtureCommands.VerifyProviderIdentity(ctx, a, in)
	if err != nil {
		return v, err
	}
	f.changedID, f.isolated = v.ID, f.commandLedger(ctx) != f.ledger
	return v, errors.New("private provider failure after receipt write")
}
func TestProviderVerificationFixtureRollsBackReceiptAuditAndReplayAfterRealWrite(t *testing.T) {
	ledger, factory, live := providerVerificationRegressionLedger()
	owner := seedProviderVerificationFixture(t, ledger, "Owner")
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.bindProviderVerificationFixtureResources(live, providerVerificationFixtureClock())
	s.authn = &configuredAuthenticator{actor: providerVerificationFixtureHuman(owner)}
	f := &failingProviderVerificationFixture{providerVerificationFixtureCommands: providerVerificationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, live: live, clock: providerVerificationFixtureClock()}}
	s.providerVerificationCommands = f
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	const token = "access-token-rollback-canary"
	body := providerVerificationFixtureBody(owner, `,"access_token":"`+token+`"`)
	out := postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "failed-receipt", []byte(body), 500)
	if f.changedID == "" || !f.isolated || len(live.requests) != 1 || strings.Contains(out, f.changedID) || strings.Contains(out, "private provider") || strings.Contains(out, token) || strings.Contains(out, `"data"`) {
		t.Fatal("post-write failure bypassed real isolated execution or leaked receipt", out)
	}
	after, err := factory.Snapshot()
	if err != nil || len(after.Idempotency) != 1 {
		t.Fatal("failed command lost failed replay marker", err)
	}
	for _, receipt := range after.Idempotency {
		if receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil {
			t.Fatal("failed receipt retained a success response")
		}
	}
	assertProviderVerificationFixturePrivate(t, after, token)
	after.Idempotency = before.Idempotency
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed receipt committed assessment, audit, session, link or credential effects")
	}
}

func TestProviderVerificationFixturePreservesCompleteDTOAndCredentialFreeReplayWithCurrentGrants(t *testing.T) {
	for _, mode := range []string{"metadata", "live"} {
		t.Run(mode, func(t *testing.T) {
			ledger, factory, live := providerVerificationRegressionLedger()
			owner := seedProviderVerificationFixture(t, ledger, "Owner")
			foreign := seedProviderVerificationFixture(t, ledger, "Foreign")
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			human := providerVerificationFixtureHuman(owner)
			auth := &configuredAuthenticator{actor: human}
			s.bindProviderVerificationFixtureResources(live, providerVerificationFixtureClock())
			s.authn = auth
			const token = "access-token-redaction-canary"
			credential, wantCalls := "", 0
			if mode == "live" {
				credential, wantCalls = `,"access_token":"`+token+`"`, 1
			}
			body := providerVerificationFixtureBody(owner, credential)
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			first := postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "same-receipt", []byte(body), 201)
			saved, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			id := dataField(t, first, "id")
			v := saved.ProviderVerifications[id]
			if v.ID != id || v.TenantID != human.TenantID || v.ProviderID != owner.provider.ID || v.ProviderType != "oidc" || v.Subject != "subject-Owner" || v.SchemaVersion != identitydomain.ProviderVerificationVersion || v.CreatedAt != time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) || v.Profile.ID != "provider-identity-oidc.v1" || len(v.Profile.RequiredChecks) == 0 || len(v.Profile.TrustMaterial) == 0 || len(v.Limitations) == 0 {
				t.Fatal("fresh receipt lost owned bindings, schema, time or assurance metadata")
			}
			if mode == "live" && v.Result != "passed" || mode == "metadata" && v.Result != "limited" {
				t.Fatal("metadata was upgraded to credential verification or live assessment changed", v.Result)
			}
			wantChecks := []domain.VerifyCheck{{Name: "verified_identity_link", Result: "passed"}}
			if mode == "live" {
				wantChecks = append([]domain.VerifyCheck{{Name: "live_subject", Result: "passed", Detail: "credential echo [redacted]"}, {Name: "mapped_provider_api_groups", Result: "passed", Detail: "1 provider API group role mapping(s) can be applied to sessions"}}, wantChecks...)
				if !reflect.DeepEqual(v.Limitations, []string{"safe receipt: [redacted]"}) || !reflect.DeepEqual(v.Profile.Limitations, v.Limitations) {
					t.Fatal("provider diagnostic redaction or assurance limitations changed")
				}
			}
			if !reflect.DeepEqual(v.Checks, wantChecks) {
				t.Fatal("receipt dropped or changed provider/link checks", v.Checks)
			}
			want, err := json.Marshal(map[string]any{"data": v, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), first)
			if len(saved.ProviderVerifications) != len(before.ProviderVerifications)+1 || len(saved.Idempotency) != len(before.Idempotency)+1 || len(saved.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 {
				t.Fatal("fresh receipt did not commit exactly one assessment, audit and replay")
			}
			last := saved.AuditEntries[human.TenantID][len(saved.AuditEntries[human.TenantID])-1]
			if last.EntryType != "provider_identity.verified" || last.SubjectType != "provider_identity" || last.SubjectID != id || last.ActorType != "human_user" || last.ActorID != human.UserID {
				t.Fatal("receipt audit lost human attribution or subject binding")
			}
			unchanged := saved
			unchanged.ProviderVerifications, unchanged.AuditEntries, unchanged.Idempotency = before.ProviderVerifications, before.AuditEntries, before.Idempotency
			if !reflect.DeepEqual(before, unchanged) {
				t.Fatal("receipt unexpectedly issued session, modified trust/link or granted roles")
			}
			assertProviderVerificationFixturePrivate(t, saved, token)
			if strings.Contains(first, token) || len(live.requests) != wantCalls {
				t.Fatal("receipt leaked token or called provider during metadata assessment")
			}
			if mode == "live" {
				wantRequest := app.ProviderIdentityValidationRequest{TenantID: human.TenantID, ProviderID: owner.provider.ID, ProviderType: "oidc", Issuer: owner.provider.Issuer, Subject: "subject-Owner", GroupsClaim: owner.provider.GroupsClaim, AccessToken: token}
				if !reflect.DeepEqual(live.requests[0], wantRequest) {
					t.Fatal("provider I/O was not bound to the current owned metadata")
				}
			}
			live.mode = "unavailable"
			replay := postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "same-receipt", []byte(body), 201)
			assertTrustHTTPReplay(t, first, replay)
			postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "same-receipt", append([]byte(body), ' '), 409)
			for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"identity:admin"}}}, {{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"identity:admin"}}}} {
				auth.actor.ResourceGrants = grants
				postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "same-receipt", []byte(body), 403)
				postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "new-receipt", []byte(body), 403)
			}
			auth.actor = human
			for name, wrong := range map[string]string{"foreign": strings.ReplaceAll(body, owner.provider.ID, foreign.provider.ID), "missing": strings.ReplaceAll(body, owner.provider.ID, "missing-provider"), "type": strings.ReplaceAll(providerVerificationFixtureBody(owner, ""), "oidc", "saml")} {
				postRaw(t, s, "fixture-auth", "/v1/provider-verifications", name, []byte(wrong), 404)
			}
			auth.err = app.ErrUnauthorized
			postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "same-receipt", []byte(body), 401)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(saved, after) || len(live.requests) != wantCalls {
				t.Fatal("replay, revoked grants or foreign roots changed state or repeated I/O", err)
			}
		})
	}
}

func TestProviderVerificationFixtureFailedAssessmentsRollBackOnlyForHTTPCreate(t *testing.T) {
	for _, mode := range []string{"bad-local-token", "unlinked", "unavailable", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			ledger, factory, live := providerVerificationRegressionLedger()
			owner := seedProviderVerificationFixture(t, ledger, "Owner")
			live.mode = mode
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			s.bindProviderVerificationFixtureResources(live, providerVerificationFixtureClock())
			s.authn = &configuredAuthenticator{actor: owner.actor}
			const token = "credential-failure-canary"
			credential := `,"access_token":"` + token + `"`
			if mode == "bad-local-token" {
				credential = `,"id_token":"` + token + `"`
			}
			body := providerVerificationFixtureBody(owner, credential)
			if mode == "unlinked" {
				body = strings.ReplaceAll(body, "subject-Owner", "unlinked-subject")
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "failed", []byte(body), 422)
			postRaw(t, s, "fixture-auth", "/v1/provider-verifications", "failed", []byte(body), 409)
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != 1 || strings.Contains(out, token) || strings.Contains(out, "private provider") || strings.Contains(out, `"data"`) {
				t.Fatal("HTTP failure leaked assessment or lost failure marker", err, out)
			}
			for _, receipt := range after.Idempotency {
				if receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil {
					t.Fatal("failed HTTP assessment retained a response")
				}
			}
			assertProviderVerificationFixturePrivate(t, after, token)
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("HTTP failed assessment committed receipt, audit or identity effects")
			}
			in, err := decodeProviderVerificationRequest([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			commands := providerVerificationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, live: live, clock: providerVerificationFixtureClock()}
			v, err := commands.VerifyProviderIdentity(t.Context(), owner.actor, in)
			if !errors.Is(err, app.ErrVerificationFailed) || v.ID == "" || v.Profile.ID == "" || (v.Result != "failed" && v.Result != "error") {
				t.Fatal("direct command did not return committed failed assessment", err, v.Result)
			}
			direct, err := factory.Snapshot()
			if err != nil || len(direct.ProviderVerifications) != len(before.ProviderVerifications)+1 || len(direct.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 || len(direct.Idempotency) != 1 || !reflect.DeepEqual(app.ProviderVerificationFromIdentity(v), direct.ProviderVerifications[v.ID]) {
				t.Fatal("direct failure did not persist assessment/audit", err)
			}
			assertProviderVerificationFixturePrivate(t, direct, token)
			direct.ProviderVerifications, direct.AuditEntries, direct.Idempotency = before.ProviderVerifications, before.AuditEntries, before.Idempotency
			if !reflect.DeepEqual(before, direct) {
				t.Fatal("direct failed assessment issued identity/session effects")
			}
			wantCalls := 2
			if mode == "bad-local-token" {
				wantCalls = 0
			}
			if len(live.requests) != wantCalls {
				t.Fatal("failed-key replay repeated provider I/O", len(live.requests), wantCalls)
			}
		})
	}
}

func TestProviderVerificationFixtureGuardsArePureCancellableAndKeepExplicitBindings(t *testing.T) {
	ledger, factory, live := providerVerificationRegressionLedger()
	owner := seedProviderVerificationFixture(t, ledger, "Owner")
	foreign := seedProviderVerificationFixture(t, ledger, "Foreign")
	f := providerVerificationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, live: live, clock: providerVerificationFixtureClock()}
	in := identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: owner.provider.ID, Subject: "subject-Owner", AccessToken: "guard-credential-canary"}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.AuthorizeVerifyProviderIdentity(t.Context(), owner.actor, in); err != nil {
		t.Fatal("real guard rejected owned provider", err)
	}
	for _, c := range []struct {
		in   identityapp.VerifyProviderIdentityInput
		want error
	}{{identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: foreign.provider.ID, Subject: "subject"}, app.ErrNotFound}, {identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: owner.provider.ID, Subject: "guard-credential-canary", AccessToken: "guard-credential-canary"}, identityapp.ErrValidation}, {identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: owner.provider.ID, Subject: "subject", AccessToken: strings.Repeat("x", 16385)}, identityapp.ErrValidation}, {identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: owner.provider.ID, Subject: "subject\x00"}, identityapp.ErrValidation}, {identityapp.VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: owner.provider.ID, Subject: "subject", SAMLAssertion: "assertion"}, identityapp.ErrValidation}} {
		if err := f.AuthorizeVerifyProviderIdentity(t.Context(), owner.actor, c.in); !errors.Is(err, c.want) {
			t.Fatal("provider guard skipped input/ownership fence", err, c.want)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.AuthorizeVerifyProviderIdentity(ctx, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("guard ignored cancellation", err)
	}
	ctx, cancel = context.WithCancel(t.Context())
	defer cancel()
	live.hook = cancel
	if _, err := f.VerifyProviderIdentity(ctx, owner.actor, in); !errors.Is(err, context.Canceled) {
		t.Fatal("provider cancellation did not abort receipt command", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || len(live.requests) != 1 {
		t.Fatal("pure guards or cancelled provider published effects", err)
	}
	explicit := &providerReceiptHTTPFake{}
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{ProviderVerificationCommands: explicit, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if s.providerVerificationCommands != explicit {
		t.Fatal("fixture binding replaced explicit focused commands")
	}
}
