package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/redaction"
)

type portalFixtureScope struct {
	operationsFixtureScope
	pkg domain.CustomerSecurityPackage
}

func seedPortalFixtureScope(t *testing.T, ledger *app.Ledger, name string) portalFixtureScope {
	t.Helper()
	f := portalFixtureScope{operationsFixtureScope: seedOperationsFixtureScope(t, ledger, name)}
	profile, err := ledger.CreateRedactionProfile(t.Context(), f.actor, app.CreateRedactionProfileInput{Preset: "customer_safe"})
	if err != nil {
		t.Fatal(err)
	}
	f.pkg, err = ledger.CreateCustomerSecurityPackage(t.Context(), f.actor, app.CreateCustomerPackageInput{ProductID: f.product.ID, ReleaseID: f.release.ID, RedactionProfileID: profile.ID, Title: "Review <script>unsafe()</script>", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func portalRegressionPorts(ledger *app.Ledger) portalFixturePorts {
	return portalFixturePorts{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}, clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 7, 16, 0, 0, 0, time.UTC) })}
}
func portalFixtureInput(f portalFixtureScope) packageapp.CreatePortalAccessInput {
	return packageapp.CreatePortalAccessInput{PackageID: f.pkg.ID, CustomerName: "Customer", ReviewerName: "Reviewer", ReviewerEmail: "reviewer@example.test", Watermark: "Review <b>copy</b>", RequireNDA: true, ExpiresAt: time.Date(2098, 1, 1, 0, 0, 0, 0, time.UTC)}
}
func portalFixtureBody(f portalFixtureScope) string {
	return fmt.Sprintf(`{"package_id":%q,"customer_name":"Customer","reviewer_name":"Reviewer","reviewer_email":"reviewer@example.test","watermark":"Review <b>copy</b>","require_nda":true,"expires_at":"2098-01-01T00:00:00Z"}`, f.pkg.ID)
}
func portalFixtureHuman(f portalFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: "fixture-human", Scopes: []string{"package:write", "package:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: f.product.ID, Scopes: []string{"package:write", "package:read"}}}}
}

type failingPortalFixture struct {
	portalFixturePorts
	changedID, secret string
	isolated          bool
}

func (f *failingPortalFixture) CreatePortalAccess(ctx context.Context, a domain.Actor, in packageapp.CreatePortalAccessInput) (packagedomain.CustomerPortalAccess, string, error) {
	v, secret, err := f.portalFixturePorts.CreatePortalAccess(ctx, a, in)
	if err != nil {
		return v, secret, err
	}
	f.changedID, f.secret, f.isolated = v.ID, secret, f.commandLedger(ctx) != f.ledger
	return v, secret, errors.New("private portal failure after write")
}
func (f *failingPortalFixture) RevokePortalAccess(ctx context.Context, a domain.Actor, id string) (packagedomain.CustomerPortalAccess, error) {
	v, err := f.portalFixturePorts.RevokePortalAccess(ctx, a, id)
	if err != nil {
		return v, err
	}
	f.changedID, f.isolated = v.ID, f.commandLedger(ctx) != f.ledger
	return v, errors.New("private portal failure after write")
}
func TestPortalFixturesRollBackRealIssuanceRevocationAuditAndReplay(t *testing.T) {
	for _, action := range []string{"issue", "revoke"} {
		t.Run(action, func(t *testing.T) {
			ledger, factory := integrationRegressionLedger()
			owner := seedPortalFixtureScope(t, ledger, "Owner")
			ports := portalRegressionPorts(ledger)
			s, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			s.authn = &configuredAuthenticator{actor: portalFixtureHuman(owner)}
			f := &failingPortalFixture{portalFixturePorts: ports}
			s.portalAccessCommands = f
			path, body, token := "/v1/customer-portal/access", portalFixtureBody(owner), ""
			if action == "revoke" {
				v, secret, err := ports.CreatePortalAccess(t.Context(), owner.actor, portalFixtureInput(owner))
				if err != nil {
					t.Fatal(err)
				}
				path, body, token = path+"/"+v.ID+"/revoke", `{}`, secret
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, s, "fixture-auth", path, "failed-portal", []byte(body), 500)
			if f.changedID == "" || !f.isolated || strings.Contains(out, "private portal") || strings.Contains(out, `"data"`) || action == "issue" && (f.secret == "" || strings.Contains(out, f.secret) || strings.Contains(out, f.changedID)) {
				t.Fatal("failure bypassed real isolated write or leaked a credential/result", out)
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != 1 {
				t.Fatal("failed portal marker missing", err)
			}
			for _, r := range after.Idempotency {
				if r.State != app.IdempotencyFailed || r.Response != nil || r.Status != 0 {
					t.Fatal("failed portal retained success data")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed portal write committed credential, lifecycle or audit effects")
			}
			if action == "issue" {
				if _, err := ports.AccessPortalPackage(t.Context(), f.secret, packageapp.PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false); !errors.Is(err, application.ErrUnauthorized) {
					t.Fatal("rolled-back token remained usable", err)
				}
			} else if _, err := ports.AccessPortalPackage(t.Context(), token, packageapp.PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false); err != nil {
				t.Fatal("rolled-back revocation invalidated token", err)
			}
		})
	}
}
func TestPortalFixturesPreserveCompletePublicMetadataPrivateReplayAndCurrentGrants(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedPortalFixtureScope(t, ledger, "Owner"), seedPortalFixtureScope(t, ledger, "Foreign")
	ports := portalRegressionPorts(ledger)
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.portalAccessCommands, s.portalTokenCommands, s.portalAccessQuery = ports, ports, ports
	human := portalFixtureHuman(owner)
	auth := &configuredAuthenticator{actor: human}
	s.authn = auth
	body := portalFixtureBody(owner)
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	first := postRaw(t, s, "fixture-auth", "/v1/customer-portal/access", "issue", []byte(body), 201)
	id, token := dataFieldFromNestedObject(t, first, "access", "id"), nestedDataField(t, first, "secret")
	saved, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	v := saved.CustomerPortalAccess[id]
	c, err := identityapp.NewHMACAuthenticationCredentials("portal-fixture-pepper")
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 49 || v.Hash != c.Hash(token) || v.Prefix != token[:12] || v.PackageID != owner.pkg.ID || v.TenantID != human.TenantID || v.CustomerName != "Customer" || v.ReviewerEmail != "reviewer@example.test" || v.ExpiresAt != portalFixtureInput(owner).ExpiresAt || v.CreatedAt != ports.fixtureClock().Now() || !v.RequireNDA || v.Watermark != "Review <b>copy</b>" || v.SchemaVersion != packagedomain.CustomerPortalAccessVersion {
		t.Fatal("portal credential or complete public metadata contract changed")
	}
	public := v
	public.Hash = ""
	want, err := json.Marshal(map[string]any{"data": map[string]any{"access": public, "secret": token}, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), first)
	if len(saved.CustomerPortalAccess) != len(before.CustomerPortalAccess)+1 || len(saved.Idempotency) != len(before.Idempotency)+1 || len(saved.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 {
		t.Fatal("issuance did not commit exactly one credential, audit and replay")
	}
	last := saved.AuditEntries[human.TenantID][len(saved.AuditEntries[human.TenantID])-1]
	if last.EntryType != "customer_portal_access.created" || last.SubjectID != owner.pkg.ID || last.ActorType != "human_user" || last.ActorID != human.UserID {
		t.Fatal("portal issuance lost human attribution or package binding")
	}
	safe, _ := redaction.RemoveSensitive(map[string]any{"access": public, "secret": token})
	wantReplay, err := json.Marshal(map[string]any{"data": safe, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(wantReplay), postRaw(t, s, "fixture-auth", "/v1/customer-portal/access", "issue", []byte(body), 201))
	for _, r := range saved.Idempotency {
		encoded, err := json.Marshal(r.Response)
		if err != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), v.Hash) || strings.Contains(string(encoded), "reviewer@example.test") || strings.Contains(string(encoded), `"secret"`) {
			t.Fatal("cached portal replay retained credential or recipient PII", err)
		}
	}
	postRaw(t, s, "fixture-auth", "/v1/customer-portal/access", "issue", append([]byte(body), ' '), 409)
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"package:write"}}}} {
		auth.actor.ResourceGrants = grants
		postRaw(t, s, "fixture-auth", "/v1/customer-portal/access", "issue", []byte(body), 403)
		postRaw(t, s, "fixture-auth", "/v1/customer-portal/access/"+id+"/revoke", "denied-revoke", []byte(`{}`), 403)
	}
	auth.actor = human
	postRaw(t, s, "fixture-auth", "/v1/customer-portal/access", "foreign", []byte(portalFixtureBody(foreign)), 404)
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(saved, after) {
		t.Fatal("portal retry/denied/foreign checks changed state", err)
	}
	revokePath := "/v1/customer-portal/access/" + id + "/revoke"
	revoked := postRaw(t, s, "fixture-auth", revokePath, "revoke", []byte(`{}`), 200)
	after, err = factory.Snapshot()
	if err != nil || after.CustomerPortalAccess[id].RevokedAt == nil || len(after.AuditEntries[human.TenantID]) != len(saved.AuditEntries[human.TenantID])+1 {
		t.Fatal("revocation did not commit one lifecycle/audit change", err)
	}
	public = after.CustomerPortalAccess[id]
	public.Hash = ""
	want, err = json.Marshal(map[string]any{"data": public, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(want), revoked)
	safe, _ = redaction.RemoveSensitive(public)
	wantReplay, err = json.Marshal(map[string]any{"data": safe, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(wantReplay), postRaw(t, s, "fixture-auth", revokePath, "revoke", []byte(`{}`), 200))
	if _, err := ports.AccessPortalPackage(t.Context(), token, packageapp.PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("revoked portal token remained usable", err)
	}
}

func TestPortalFixtureGuardsArePureCancellableAndPreserveExplicitBindings(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPortalFixtureScope(t, ledger, "Owner")
	ports := portalRegressionPorts(ledger)
	v, token, err := ports.CreatePortalAccess(t.Context(), owner.actor, portalFixtureInput(owner))
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, guard := range []func(context.Context) error{
		func(ctx context.Context) error {
			return ports.AuthorizeCreatePortalAccess(ctx, portalFixtureHuman(owner), portalFixtureInput(owner))
		},
		func(ctx context.Context) error {
			return ports.AuthorizeRevokePortalAccess(ctx, portalFixtureHuman(owner), v.ID)
		},
	} {
		if err := guard(t.Context()); err != nil {
			t.Fatal("pure guard rejected owned package", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := guard(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("portal guard ignored cancellation", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ports.AccessPortalPackage(ctx, token, packageapp.PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, true); !errors.Is(err, context.Canceled) {
		t.Fatal("portal consumer ignored cancellation", err)
	}
	expired := ports
	expired.clock = application.ClockFunc(func() time.Time { return time.Date(2099, 2, 1, 0, 0, 0, 0, time.UTC) })
	if _, err := expired.AccessPortalPackage(t.Context(), token, packageapp.PortalAcceptanceInput{NDAAccepted: true, NDAAcceptedBy: "Reviewer"}, false); !errors.Is(err, application.ErrUnauthorized) {
		t.Fatal("expired token remained usable", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("preflight/cancellation/expiry changed repository state", err)
	}
	access, consumer, query := &portalHTTPFake{}, &portalTokenHTTPFake{}, &portalAccessQueryFake{}
	s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{PortalAccessCommands: access, PortalTokenCommands: consumer, PortalAccessQuery: query, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(newLegacyLedgerFixture(app.Config{}))
	if s.portalAccessCommands != access || s.portalTokenCommands != consumer || s.portalAccessQuery != query {
		t.Fatal("fixture binder replaced explicit portal ports")
	}
}

type failingPortalTokenTransactions struct {
	portalFixtureTransactions
	stage string
}
type failingPortalTokenTransaction struct {
	packageapp.PortalTokenTransaction
	stage string
}

func (f failingPortalTokenTransaction) UpdatePortalTokenAccess(ctx context.Context, old, v packagedomain.CustomerPortalAccess) error {
	if err := f.PortalTokenTransaction.UpdatePortalTokenAccess(ctx, old, v); err != nil {
		return err
	}
	if f.stage == "counter" {
		return errors.New("private portal counter failure")
	}
	return nil
}
func (f failingPortalTokenTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	v, err := f.PortalTokenTransaction.AppendAudit(ctx, e)
	if err == nil && f.stage == "audit" {
		err = errors.New("private portal audit failure")
	}
	return v, err
}
func (f failingPortalTokenTransactions) ExecutePortalToken(ctx context.Context, tenant string, run func(context.Context, packageapp.PortalTokenTransaction) error) error {
	return f.portalFixtureTransactions.ExecutePortalToken(ctx, tenant, func(ctx context.Context, tx packageapp.PortalTokenTransaction) error {
		if err := run(ctx, failingPortalTokenTransaction{tx, f.stage}); err != nil {
			return err
		}
		return errors.New("private portal post-command failure")
	})
}
func TestPortalFixtureTokenTransactionsRollBackNDAAccessAndAuditEffects(t *testing.T) {
	for _, stage := range []string{"counter", "audit", "post-command"} {
		t.Run(stage, func(t *testing.T) {
			ledger, factory := integrationRegressionLedger()
			owner := seedPortalFixtureScope(t, ledger, "Owner")
			ports := portalRegressionPorts(ledger)
			_, token, err := ports.CreatePortalAccess(t.Context(), owner.actor, portalFixtureInput(owner))
			if err != nil {
				t.Fatal(err)
			}
			c, err := identityapp.NewHMACAuthenticationCredentials("portal-fixture-pepper")
			if err != nil {
				t.Fatal(err)
			}
			command, err := packageapp.NewPortalTokenCommands(packageapp.PortalTokenCommandConfig{Lookup: ports, Transactions: failingPortalTokenTransactions{portalFixtureTransactions{ports, false}, stage}, Credentials: portalFixtureCredentials{c}, Clock: ports.fixtureClock(), IDs: application.IDGeneratorFunc(application.NewID)})
			if err != nil {
				t.Fatal(err)
			}
			s, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{PortalTokenCommands: command})
			if err != nil {
				t.Fatal(err)
			}
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, s, "", "/v1/customer-portal/package/download", "", []byte(fmt.Sprintf(`{"token":%q,"nda_accepted":true,"nda_accepted_by":"Reviewer"}`, token)), 500)
			after, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(before, after) || strings.Contains(out, token) || strings.Contains(out, "private portal") || strings.Contains(out, `"data"`) {
				t.Fatal("failed portal transaction committed NDA/counters/audits or disclosed content", err)
			}
		})
	}
}
func TestPortalFixturesKeepRealNDADenialsDownloadAuditsAndCompleteScopedPages(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner, foreign := seedPortalFixtureScope(t, ledger, "Owner"), seedPortalFixtureScope(t, ledger, "Foreign")
	ports := portalRegressionPorts(ledger)
	var token, id string
	for _, scope := range []portalFixtureScope{owner, foreign} {
		for i := 0; i < 3; i++ {
			v, secret, err := ports.CreatePortalAccess(t.Context(), scope.actor, portalFixtureInput(scope))
			if err != nil {
				t.Fatal(err)
			}
			if token == "" {
				token, id = secret, v.ID
			}
		}
	}
	s, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	s.portalAccessQuery, s.portalTokenCommands = ports, ports
	auth := &configuredAuthenticator{actor: portalFixtureHuman(owner)}
	s.authn = auth
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path, seen := "/v1/customer-portal/access?page_size=1", map[string]bool{}
	for {
		out := getJSON(t, s, "fixture-auth", path, 200)
		var page struct {
			Data []domain.CustomerPortalAccess `json:"data"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal([]byte(out), &page); err != nil || len(page.Data) != 1 || page.Data[0].TenantID != owner.actor.TenantID || seen[page.Data[0].ID] || strings.Contains(out, token) || strings.Contains(out, before.CustomerPortalAccess[page.Data[0].ID].Hash) {
			t.Fatal("portal page lost owned data or exposed credentials", err)
		}
		seen[page.Data[0].ID] = true
		want := before.CustomerPortalAccess[page.Data[0].ID]
		want.Hash = ""
		if !reflect.DeepEqual(want, page.Data[0]) {
			t.Fatal("portal page dropped public metadata")
		}
		if page.Meta.NextCursor == "" {
			break
		}
		path = "/v1/customer-portal/access?page_size=1&cursor=" + url.QueryEscape(page.Meta.NextCursor)
	}
	if len(seen) != 3 {
		t.Fatal("portal page omitted owned entries")
	}
	getJSON(t, s, "fixture-auth", "/v1/customer-portal/access?package_id="+foreign.pkg.ID, 404)
	auth.actor.ResourceGrants = nil
	getJSON(t, s, "fixture-auth", "/v1/customer-portal/access?package_id="+owner.pkg.ID, 403)
	auth.actor = portalFixtureHuman(owner)
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("portal lists changed repository state", err)
	}
	postRaw(t, s, "", "/v1/customer-portal/package", "", []byte(fmt.Sprintf(`{"token":%q}`, token)), 403)
	after, err = factory.Snapshot()
	if err != nil || after.CustomerPortalAccess[id].AccessCount != 0 || after.CustomerPortalAccess[id].NDAAcceptedAt != nil || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+1 {
		t.Fatal("NDA denial did not retain exactly its audit", err)
	}
	postJSONNoAuthRaw(t, s, "/v1/customer-portal/package/download", map[string]any{"token": token, "nda_accepted": true, "nda_accepted_by": "Reviewer"}, 200)
	after, err = factory.Snapshot()
	if err != nil || after.CustomerPortalAccess[id].AccessCount != 1 || after.CustomerPortalAccess[id].NDAAcceptedAt == nil || after.CustomerPortalAccess[id].NDAAcceptedBy != "Reviewer" || len(after.AuditEntries[owner.actor.TenantID]) != len(before.AuditEntries[owner.actor.TenantID])+4 {
		t.Fatal("download did not commit NDA, count and exact audits", err)
	}
	entries := after.AuditEntries[owner.actor.TenantID]
	for _, e := range entries[len(entries)-2:] {
		if e.EntryType != "customer_portal_package.downloaded" || e.ActorType != "customer_portal" || e.ActorID != id || e.PayloadHash != owner.pkg.ManifestHash {
			t.Fatal("download became an ordinary access or lost token/package bindings")
		}
	}
	// Wrong-token denials with the known prefix intentionally commit counters
	// and the five-failure revocation, never package content or replay receipts.
	wrong := token[:len(token)-1] + "x"
	if wrong == token {
		wrong = token[:len(token)-1] + "y"
	}
	for i := 0; i < packageapp.PortalFailedAccessLimit; i++ {
		postRaw(t, s, "", "/v1/customer-portal/package", "", []byte(fmt.Sprintf(`{"token":%q}`, wrong)), 401)
	}
	after, err = factory.Snapshot()
	if err != nil || after.CustomerPortalAccess[id].FailedAccessCount != packageapp.PortalFailedAccessLimit || after.CustomerPortalAccess[id].RevokedAt == nil || len(after.Idempotency) != 0 {
		t.Fatal("failed-token lifecycle or no-replay contract changed", err)
	}
	postRaw(t, s, "", "/v1/customer-portal/package", "", []byte(fmt.Sprintf(`{"token":%q}`, token)), 401)
}
