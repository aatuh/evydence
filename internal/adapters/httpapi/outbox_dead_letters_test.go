package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type deadLetterHTTPReader struct {
	result appquery.Result[operationsquery.OutboxDeadLetter]
	err    error
	reads  int
	page   appquery.PageRequest
	after  *appquery.SortKey
}

func (f *deadLetterHTTPReader) ReadOutboxCounts(context.Context) (operationsquery.OutboxCounts, error) {
	return operationsquery.OutboxCounts{}, nil
}
func (f *deadLetterHTTPReader) ReadOutboxDeadLettersPage(_ context.Context, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[operationsquery.OutboxDeadLetter], error) {
	f.reads++
	f.page, f.after = page, after
	return f.result, f.err
}
func deadLetterHTTPItem(id string) operationsquery.OutboxDeadLetter {
	at := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	return operationsquery.OutboxDeadLetter{ID: id, Kind: "parse_sbom", Status: "dead_letter", Attempts: 2, MaxAttempts: 5, FailureClass: "permanent", FailureCode: "invalid_document", CreatedAt: at.Add(-time.Hour), TerminalAt: at}
}
func newDeadLetterHTTPFixture(t *testing.T, reader *deadLetterHTTPReader) (*Server, string) {
	t.Helper()
	factory := app.NewMemoryUnitOfWorkFactory()
	ledger := newLegacyLedgerFixture(repositoryFixtureConfig{APIKeyPepper: "test", UnitOfWork: factory})
	bootstrap := tenantBootstrapNativeFixture{factory, fixtureSessionCredentials("test"), providerVerificationFixtureClock()}
	_, _, secret, err := bootstrap.BootstrapTenant(t.Context(), "Instance", "instance-admin", []string{app.ScopeInstanceAdmin})
	if err != nil {
		t.Fatal(err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	server.outboxDiagnosticsQuery, err = operationsquery.NewOutboxDiagnostics(reader)
	if err != nil {
		t.Fatal(err)
	}
	return server, secret
}
func deadLetterHTTPGet(t *testing.T, server *Server, secret, path string, status int) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("dead-letter request status=%d want=%d", response.Code, status)
	}
	return response
}

func TestOutboxDeadLetterRouteReturnsBoundedMetadata(t *testing.T) {
	reader := &deadLetterHTTPReader{}
	server, secret := newDeadLetterHTTPFixture(t, reader)
	response := deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters?page_size=2", http.StatusOK)
	body := response.Body.String()
	if !strings.Contains(body, `"data":[]`) || !strings.Contains(body, `"page_size":2`) || strings.Contains(body, "payload") || strings.Contains(body, "tenant_id") || reader.reads != 1 || reader.page.Sort != appquery.SortID || reader.page.Direction != appquery.Ascending || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("dead-letter route lost bounded private metadata semantics")
	}
}

func TestOutboxDeadLetterRouteBindsAndContinuesItsCursor(t *testing.T) {
	reader := &deadLetterHTTPReader{result: appquery.Result[operationsquery.OutboxDeadLetter]{Items: []operationsquery.OutboxDeadLetter{deadLetterHTTPItem("job_a"), deadLetterHTTPItem("job_b")}, Next: &appquery.SortKey{Value: "job_b", ID: "job_b"}}}
	server, secret := newDeadLetterHTTPFixture(t, reader)
	response := deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters?page_size=2", 200)
	var envelope struct {
		Data []operationsquery.OutboxDeadLetter `json:"data"`
		Meta struct {
			Next string `json:"next_cursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || len(envelope.Data) != 2 || envelope.Data[1].ID != "job_b" || envelope.Meta.Next == "" {
		t.Fatal("first dead-letter page lost metadata or continuation")
	}
	token := envelope.Meta.Next
	// The reader returns a current page after job_b has been replayed. The
	// continuation remains a boundary and never requires the old row to exist.
	reader.result = appquery.Result[operationsquery.OutboxDeadLetter]{Items: []operationsquery.OutboxDeadLetter{deadLetterHTTPItem("job_c")}}
	response = deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters?page_size=2&cursor="+url.QueryEscape(token), 200)
	if reader.after == nil || reader.after.ID != "job_b" || !strings.Contains(response.Body.String(), `"id":"job_c"`) || strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatal("replayed anchor invalidated continuation")
	}
	cursor, err := server.cursors.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*appquery.Cursor){func(c *appquery.Cursor) { c.Resource = "evidence-search" }, func(c *appquery.Cursor) { c.TenantID = "other-tenant" }} {
		changed := cursor
		mutate(&changed)
		bad, err := server.cursors.Encode(changed)
		if err != nil {
			t.Fatal(err)
		}
		before := reader.reads
		deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters?page_size=2&cursor="+url.QueryEscape(bad), 400)
		if reader.reads != before {
			t.Fatal("foreign cursor reached queue I/O")
		}
	}
	before := reader.reads
	deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters?page_size=2&direction=desc&cursor="+url.QueryEscape(token), 400)
	if reader.reads != before {
		t.Fatal("changed cursor ordering reached queue I/O")
	}
}

func TestOutboxDeadLetterRouteRejectsMalformedQueryBeforeReading(t *testing.T) {
	reader := &deadLetterHTTPReader{}
	server, secret := newDeadLetterHTTPFixture(t, reader)
	for _, query := range []string{"page_size=0", "page_size=501", "page_size=+1", "page_size=01", "page_size=2&page_size=3", "page_size=9999999999999999999999", "sort=created_at", "direction=sideways", "cursor=forged", "cursor=", "tenant_id=PRIVATE_TENANT", "status=running", "unknown=x", "page_size=%ZZ"} {
		deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters?"+query, 400)
		if reader.reads != 0 {
			t.Fatal("malformed dead-letter query reached queue I/O")
		}
	}
}

func TestOutboxDeadLetterRouteRejectsUnsafeProjectionAndHidesReadErrors(t *testing.T) {
	reader := &deadLetterHTTPReader{}
	server, secret := newDeadLetterHTTPFixture(t, reader)
	for _, test := range []struct {
		err    error
		status int
	}{{operationsquery.ErrInvalidProjection, 409}, {errors.New("PRIVATE database error"), 500}} {
		reader.err = test.err
		response := deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters", test.status)
		if strings.Contains(response.Body.String(), "PRIVATE") || strings.Contains(response.Body.String(), `"data"`) {
			t.Fatal("failed metadata read exposed data or a private error")
		}
	}
	reader.err = nil
	item := deadLetterHTTPItem("job_a")
	item.FailureCode = "PRIVATE error details"
	reader.result = appquery.Result[operationsquery.OutboxDeadLetter]{Items: []operationsquery.OutboxDeadLetter{item}}
	response := deadLetterHTTPGet(t, server, secret, "/v1/admin/outbox/dead-letters", 409)
	if strings.Contains(response.Body.String(), "PRIVATE") || strings.Contains(response.Body.String(), `"data"`) {
		t.Fatal("corrupt metadata was returned")
	}
}

func TestOutboxDeadLetterOpenAPIHasPrecisePageAndPrivateMetadata(t *testing.T) {
	server, _ := newDeadLetterHTTPFixture(t, &deadLetterHTTPReader{})
	body, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]struct {
			ID         string   `json:"operationId"`
			Scopes     []string `json:"x-scopes"`
			Parameters []struct {
				Name   string         `json:"name"`
				Schema map[string]any `json:"schema"`
			} `json:"parameters"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
				Additional bool                       `json:"additionalProperties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	op := doc.Paths["/v1/admin/outbox/dead-letters"]["get"]
	if op.ID != "listOutboxDeadLetters" || len(op.Scopes) != 1 || op.Scopes[0] != app.ScopeInstanceAdmin {
		t.Fatal("dead-letter contract lost explicit instance scope")
	}
	parameters := make(map[string]map[string]any)
	for _, parameter := range op.Parameters {
		parameters[parameter.Name] = parameter.Schema
	}
	if parameters["page_size"]["maximum"] != float64(500) || parameters["page_size"]["default"] != float64(50) || parameters["cursor"]["maxLength"] != float64(4096) || parameters["sort"]["default"] != "id" {
		t.Fatal("dead-letter pagination contract drifted from runtime bounds")
	}
	metadata := doc.Components.Schemas["OutboxDeadLetter"]
	fields := []string{"id", "kind", "status", "attempts", "max_attempts", "failure_class", "failure_code", "created_at", "terminal_at"}
	if metadata.Additional || len(metadata.Properties) != len(fields) || len(metadata.Required) != len(fields) {
		t.Fatal("dead-letter contract admits extra private or optional metadata")
	}
	for _, field := range fields {
		if _, ok := metadata.Properties[field]; !ok {
			t.Fatal("dead-letter metadata contract lost a required field", field)
		}
	}
}
