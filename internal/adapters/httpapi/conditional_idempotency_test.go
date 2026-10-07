package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

func TestConditionalActionsBindRevisionToIdempotencyReplay(t *testing.T) {
	server, secret := testServer(t)
	product := postJSON(t, server, secret, "/v1/products", "conditional-product", map[string]any{"name": "Conditional", "slug": "conditional"}, 201)
	release := postJSON(t, server, secret, "/v1/releases", "conditional-release", map[string]any{"product_id": dataField(t, product, "id"), "version": "1"}, 201)
	id := dataField(t, release, "id")
	freezePath := "/v1/releases/" + id + "/freeze"
	actor, err := server.authn.Authenticate(t.Context(), secret)
	if err != nil {
		t.Fatal(err)
	}
	// Seed the original body-only receipt directly through the historical test
	// ledger; the production server no longer exposes that replay interface.
	if _, _, err := legacyFixtureLedger(server).WithIdempotency(t.Context(), actor, "POST", freezePath, "legacy-body-only", []byte(`{}`), func(context.Context, *app.Ledger) (int, any, error) { return 200, map[string]any{"legacy": true}, nil }); err != nil {
		t.Fatal(err)
	}
	postJSONWithIfMatch(t, server, secret, freezePath, "legacy-body-only", 1, map[string]any{}, 409)
	frozen := postJSONWithIfMatch(t, server, secret, freezePath, "conditional-freeze", 1, map[string]any{}, 200)
	if replay := postJSONWithIfMatch(t, server, secret, freezePath, "conditional-freeze", 1, map[string]any{}, 200); replay != frozen {
		t.Fatal("same revision replay changed result", replay)
	}
	changed := postJSONWithIfMatch(t, server, secret, freezePath, "conditional-freeze", 2, map[string]any{}, 409)
	if !strings.Contains(changed, `"code":"IDEMPOTENCY_KEY_REUSED"`) {
		t.Fatal("changed replay intent not rejected", changed)
	}
	for i, values := range [][]string{nil, {`W/"1"`}, {`"01"`}, {`"+1"`}, {`"0"`}, {`"-1"`}, {`"9223372036854775808"`}, {`"1", "2"`}, {`"1"`, `"1"`}} {
		req := httptest.NewRequest(http.MethodPost, freezePath, strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Idempotency-Key", "conditional-freeze")
		for _, v := range values {
			req.Header.Add("If-Match", v)
		}
		rec := httptest.NewRecorder()
		server.Handler().ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("invalid revision replay %d bypassed validation: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	approvePath := "/v1/releases/" + id + "/approve"
	approved := postJSONWithIfMatch(t, server, secret, approvePath, "conditional-approve", 2, map[string]any{}, 200)
	if replay := postJSONWithIfMatch(t, server, secret, approvePath, "conditional-approve", 2, map[string]any{}, 200); replay != approved {
		t.Fatal("approval replay changed", replay)
	}
	postJSONWithIfMatch(t, server, secret, approvePath, "conditional-approve", 3, map[string]any{}, 409)
	if replay := postJSONWithIfMatch(t, server, secret, freezePath, "conditional-freeze", 1, map[string]any{}, 200); replay != frozen {
		t.Fatal("historical freeze replay changed after approval", replay)
	}
	current := getJSON(t, server, secret, "/v1/releases/"+id, 200)
	if !strings.Contains(current, `"revision":3`) || !strings.Contains(current, `"state":"approved"`) {
		t.Fatal("replay changed durable lifecycle", fmt.Sprint(current))
	}
	for _, action := range []string{"promote", "reject"} {
		candidate := postJSON(t, server, secret, "/v1/release-candidates", "conditional-candidate-"+action, map[string]any{"release_id": id, "name": "rc-" + action}, 201)
		path := "/v1/release-candidates/" + dataField(t, candidate, "id") + "/" + action
		body := map[string]any{"reason": "reviewed"}
		result := postJSONWithIfMatch(t, server, secret, path, "conditional-"+action, 1, body, 200)
		if replay := postJSONWithIfMatch(t, server, secret, path, "conditional-"+action, 1, body, 200); replay != result {
			t.Fatal("candidate replay changed", replay)
		}
		postJSONWithIfMatch(t, server, secret, path, "conditional-"+action, 2, body, 409)
		postJSON(t, server, secret, path, "conditional-"+action, body, 400)
	}
}
