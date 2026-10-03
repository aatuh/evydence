package httpapi

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

func TestApprovalHTTPAcceptsPublishedEnumWithoutChangingLifecycle(t *testing.T) {
	store := app.NewMemoryStore()
	ledger, err := app.NewLedgerWithContext(t.Context(), app.Config{APIKeyPepper: "test", Store: store})
	if err != nil {
		t.Fatal(err)
	}
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatal(err)
	}
	productID := dataField(t, postJSON(t, server, secret, "/v1/products", "approval-product", map[string]any{"name": "Product", "slug": "product"}, http.StatusCreated), "id")
	releaseID := dataField(t, postJSON(t, server, secret, "/v1/releases", "approval-release", map[string]any{"product_id": productID, "version": "1.0.0"}, http.StatusCreated), "id")
	waiverID := dataField(t, postJSON(t, server, secret, "/v1/waivers", "approval-waiver", map[string]any{"scope_type": "release", "scope_id": releaseID, "owner": "security", "risk": "low", "reason": "temporary", "expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)}, http.StatusCreated), "id")
	before, exists, err := store.LoadState(t.Context())
	if err != nil || !exists || before.Waivers[waiverID].Approved {
		t.Fatal("invalid unapproved fixture", err)
	}
	raw, err := server.OpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	schemas := asStringAnyMap(t, asStringAnyMap(t, spec["components"])["schemas"])
	properties := asStringAnyMap(t, asStringAnyMap(t, schemas["CreateApprovalRequest"])["properties"])
	enum, ok := asStringAnyMap(t, properties["decision"])["enum"].([]any)
	if !ok || !reflect.DeepEqual(enum, []any{"approved", "rejected", "accepted"}) {
		t.Fatal("published approval enum changed", enum)
	}
	decode := func(body string) domain.ApprovalRecord {
		t.Helper()
		var v struct {
			Data domain.ApprovalRecord `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		return v.Data
	}
	for _, subject := range []struct{ typ, id string }{{"release", releaseID}, {"waiver", waiverID}} {
		for _, value := range enum {
			decision := value.(string)
			body := map[string]any{"subject_type": subject.typ, "subject_id": subject.id, "decision": decision, "reason": "Reviewed"}
			key := subject.typ + "-" + decision
			v := decode(postJSON(t, server, secret, "/v1/approvals", key, body, http.StatusCreated))
			if v.ID == "" || v.Decision != decision || v.SubjectType != subject.typ || v.SubjectID != subject.id || v.Reason != "Reviewed" || v.ApproverID == "" || v.SchemaVersion != domain.ApprovalRecordSchemaVersion || v.CreatedAt.IsZero() {
				t.Fatal("published approval record lost fields", v)
			}
			if replay := decode(postJSON(t, server, secret, "/v1/approvals", key, body, http.StatusCreated)); replay != v {
				t.Fatal("approval replay changed record", replay, v)
			}
			body["reason"] = "Changed"
			postJSON(t, server, secret, "/v1/approvals", key, body, http.StatusConflict)
		}
	}
	after, _, err := store.LoadState(t.Context())
	if err != nil || !reflect.DeepEqual(before.Releases, after.Releases) || !reflect.DeepEqual(before.Waivers, after.Waivers) || len(after.Approvals) != 6 {
		t.Fatal("approval changed lifecycle or replay duplicated records", err)
	}
	var summary struct {
		Data domain.ReleaseSecuritySummary `json:"data"`
	}
	if err := json.Unmarshal([]byte(getJSON(t, server, secret, "/v1/releases/"+releaseID+"/security-summary", http.StatusOK)), &summary); err != nil || summary.Data.ApprovalSummary != (domain.ReleaseSecurityApprovalSummary{Total: 3, Approved: 1}) {
		t.Fatal("accepted/rejected records were promoted to approved", summary.Data.ApprovalSummary, err)
	}
}
