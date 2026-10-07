package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorHTTPFake struct {
	guards, calls    int
	actor            identitydomain.Actor
	collector        integrationapp.CreateCollectorInput
	release          integrationapp.RecordCollectorReleaseInput
	commercial       integrationapp.CreateCommercialCollectorInput
	guardErr, runErr error
}

func (f *collectorHTTPFake) AuthorizeCreateCollector(_ context.Context, a identitydomain.Actor, in integrationapp.CreateCollectorInput) error {
	f.guards++
	f.actor, f.collector = a, in
	return f.guardErr
}
func (f *collectorHTTPFake) AuthorizeRecordCollectorRelease(_ context.Context, a identitydomain.Actor, in integrationapp.RecordCollectorReleaseInput) error {
	f.guards++
	f.actor, f.release = a, in
	return f.guardErr
}
func (f *collectorHTTPFake) AuthorizeCreateCommercialCollectorDefinition(_ context.Context, a identitydomain.Actor, in integrationapp.CreateCommercialCollectorInput) error {
	f.guards++
	f.actor, f.commercial = a, in
	return f.guardErr
}
func (f *collectorHTTPFake) CreateCollector(_ context.Context, a identitydomain.Actor, in integrationapp.CreateCollectorInput) (integrationdomain.Collector, identitydomain.APIKey, string, error) {
	f.calls++
	f.actor, f.collector = a, in
	status, _ := integrationdomain.ParseCollectorStatus("active")
	return integrationdomain.Collector{ID: "collector", TenantID: a.TenantID, Name: in.Name, Status: status}, identitydomain.APIKey{ID: "key", Hash: "private-hash"}, "fixture-secret", f.runErr
}
func (f *collectorHTTPFake) RecordCollectorRelease(_ context.Context, a identitydomain.Actor, in integrationapp.RecordCollectorReleaseInput) (integrationdomain.CollectorRelease, error) {
	f.calls++
	f.actor, f.release = a, in
	return integrationdomain.CollectorRelease{ID: "release", TenantID: a.TenantID, CollectorID: in.CollectorID, Version: in.Version, Pinned: in.Pinned}, f.runErr
}
func (f *collectorHTTPFake) CreateCommercialCollectorDefinition(_ context.Context, a identitydomain.Actor, in integrationapp.CreateCommercialCollectorInput) (integrationdomain.CommercialCollectorDefinition, error) {
	f.calls++
	f.actor, f.commercial = a, in
	return integrationdomain.CommercialCollectorDefinition{ID: "commercial", TenantID: a.TenantID, Name: in.Name, ManifestHash: in.ManifestHash}, f.runErr
}

func TestCollectorHTTPFocusedCommandsPreserveContractAndRejectInvalidEnvelopes(t *testing.T) {
	base, secret := testServer(t)
	f := &collectorHTTPFake{}
	if _, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{CollectorCommands: f}); err == nil {
		t.Fatal("focused collectors retained Ledger idempotency")
	}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), base.ledger, ServerOptions{CollectorCommands: f, DurableCommandExecutor: &decisionHTTPExecutorFake{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, body string }{
		{"/v1/collectors", `{"name":"Builder","type":"generic_ci","version":"1","scopes":["evidence:write"]}`},
		{"/v1/collectors/collector/releases", `{"version":"1","artifact_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","signature_id":"sig","sbom_id":"sbom","scan_id":"scan","pinned":true}`},
		{"/v1/commercial-collectors", `{"name":"Scanner","provider":"provider","version":"1","manifest_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","allowed_scopes":["evidence:write"]}`},
	} {
		before := f.calls + f.guards
		postRaw(t, s, "", tc.path, "unauth", []byte(tc.body), 401)
		for i, bad := range []string{"null", "[]", tc.body + " {}", strings.Replace(tc.body, "{", `{"unknown":true,`, 1), strings.Replace(tc.body, "{", `{"version":"one","version":"two",`, 1), strings.Repeat(" ", 65537) + tc.body} {
			postRaw(t, s, secret, tc.path, fmt.Sprintf("bad-%d", i), []byte(bad), 400)
		}
		var fields map[string]any
		if err := json.Unmarshal([]byte(tc.body), &fields); err != nil {
			t.Fatal(err)
		}
		for field := range fields {
			var invalid map[string]any
			if err := json.Unmarshal([]byte(tc.body), &invalid); err != nil {
				t.Fatal(err)
			}
			invalid[field] = nil
			body, err := json.Marshal(invalid)
			if err != nil {
				t.Fatal(err)
			}
			postRaw(t, s, secret, tc.path, "null-"+field, body, 400)
		}
		for _, field := range []string{"scopes", "allowed_scopes"} {
			if _, exists := fields[field]; exists {
				postRaw(t, s, secret, tc.path, "null-item", []byte(strings.Replace(tc.body, `["evidence:write"]`, `[null]`, 1)), 400)
			}
		}
		if f.calls+f.guards != before {
			t.Fatal("invalid envelope reached collector commands")
		}
		out := postRaw(t, s, secret, tc.path, "valid", []byte(tc.body), 201)
		if f.calls+f.guards != before+2 || f.actor.TenantID == "" || f.actor.KeyID == "" || strings.Contains(out, "private-hash") {
			t.Fatal("actor/result contract changed")
		}
		switch tc.path {
		case "/v1/collectors":
			if f.collector.Name != "Builder" || f.collector.Type != "generic_ci" || f.collector.Version != "1" || len(f.collector.Scopes) != 1 || f.collector.Scopes[0] != "evidence:write" || !strings.Contains(out, `"collector"`) || !strings.Contains(out, `"api_key"`) || !strings.Contains(out, `"status":"active"`) || !strings.Contains(out, `"secret":"fixture-secret"`) {
				t.Fatal("collector DTO changed")
			}
		case "/v1/collectors/collector/releases":
			if f.release.CollectorID != "collector" || f.release.SignatureID != "sig" || f.release.SBOMID != "sbom" || f.release.ScanID != "scan" || !f.release.Pinned || !strings.Contains(out, `"collector_id":"collector"`) {
				t.Fatal("release references or pin lost")
			}
		case "/v1/commercial-collectors":
			if f.commercial.Name != "Scanner" || f.commercial.Provider != "provider" || f.commercial.Version != "1" || len(f.commercial.AllowedScopes) != 1 || f.commercial.ManifestHash == "" || !strings.Contains(out, `"manifest_hash"`) {
				t.Fatal("commercial collector DTO changed")
			}
		}
		for i, ec := range []struct {
			err  error
			code int
		}{{integrationapp.ErrValidation, 400}, {integrationapp.ErrNotFound, 404}, {integrationapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private collector SQL"), 500}} {
			for _, phase := range []string{"guard", "run"} {
				f.guardErr, f.runErr = nil, nil
				if phase == "guard" {
					f.guardErr = ec.err
				} else {
					f.runErr = ec.err
				}
				calls := f.calls
				out := postRaw(t, s, secret, tc.path, fmt.Sprintf("%s-%d", phase, i), []byte(tc.body), ec.code)
				if strings.Contains(out, "private") || strings.Contains(out, "fixture-secret") || phase == "guard" && f.calls != calls {
					t.Fatal("unsafe denial", out)
				}
			}
		}
		f.guardErr, f.runErr = nil, nil
	}
}
