package authz

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

func TestCollectorAttributionMatchesOnlyAuthenticatedBindingWithoutMutation(t *testing.T) {
	bound := identitydomain.Actor{TenantID: "tenant", KeyID: "key", CollectorID: "collector", Scopes: []string{"evidence:write"}}
	key := identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"*"}}
	human := identitydomain.Actor{TenantID: "tenant", UserID: "user", SessionID: "session", Scopes: []string{"admin"}}
	for _, tc := range []struct {
		name     string
		actor    identitydomain.Actor
		claim    string
		metadata map[string]any
		want     error
	}{
		{"bound omitted", bound, "", nil, nil},
		{"bound exact", bound, "collector", map[string]any{"collector_id": "collector", "custom": "unchanged"}, nil},
		{"source-only exact", bound, "", map[string]any{"collector_id": "collector"}, nil},
		{"API key no attribution", key, "", map[string]any{"custom": "unchanged"}, nil},
		{"human no attribution", human, "", nil, nil},
		{"foreign claim", bound, "foreign", nil, ErrForbidden},
		{"padded claim", bound, " collector ", nil, ErrForbidden},
		{"conflicting source", bound, "collector", map[string]any{"collector_id": "foreign"}, ErrForbidden},
		{"null source", bound, "", map[string]any{"collector_id": nil}, ErrForbidden},
		{"structured source", bound, "", map[string]any{"collector_id": map[string]any{"id": "collector"}}, ErrForbidden},
		{"empty source", bound, "", map[string]any{"collector_id": ""}, ErrForbidden},
		{"wildcard cannot assert collector", key, "collector", nil, ErrForbidden},
		{"wildcard cannot assert source", key, "", map[string]any{"collector_id": "collector"}, ErrForbidden},
		{"human cannot assert collector", human, "collector", nil, ErrForbidden},
		{"human cannot assert source", human, "", map[string]any{"collector_id": "collector"}, ErrForbidden},
		{"missing identity", identitydomain.Actor{TenantID: "tenant"}, "", nil, ErrUnauthorized},
		{"missing tenant", identitydomain.Actor{KeyID: "key"}, "", nil, ErrUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// This policy only reads the outer map and string. Retain the input
			// references to prove it neither adds nor replaces metadata claims.
			before := make(map[string]any, len(tc.metadata))
			for k, v := range tc.metadata {
				before[k] = v
			}
			err := CheckCollectorAttribution(t.Context(), tc.actor, tc.claim, tc.metadata)
			if !errors.Is(err, tc.want) || len(tc.metadata) != len(before) {
				t.Fatal("attribution constraint or mutation mismatch", err)
			}
			for k, v := range before {
				if !reflect.DeepEqual(tc.metadata[k], v) {
					t.Fatal("source claim was mutated")
				}
			}
		})
	}
	for _, edit := range []func(*identitydomain.Actor){
		func(a *identitydomain.Actor) { a.UserID = "user" },
		func(a *identitydomain.Actor) { a.SessionID = "session" },
		func(a *identitydomain.Actor) { a.KeyID = "" },
		func(a *identitydomain.Actor) { a.KeyID = " key " },
		func(a *identitydomain.Actor) { a.CollectorID = " collector " },
		func(a *identitydomain.Actor) { a.CollectorID = "collector\x00" },
		func(a *identitydomain.Actor) { a.CollectorID = strings.Repeat("x", 1025) },
		func(a *identitydomain.Actor) { a.TenantID = " tenant " },
	} {
		bad := bound
		edit(&bad)
		if err := CheckCollectorAttribution(t.Context(), bad, "", nil); !errors.Is(err, ErrForbidden) {
			t.Fatal("mixed or malformed collector principal accepted", err)
		}
	}
}

func TestCollectorAttributionRejectsMissingAndCanceledContext(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "key", CollectorID: "collector"}
	var missing context.Context
	if err := CheckCollectorAttribution(missing, a, "", nil); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("missing context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := CheckCollectorAttribution(ctx, a, "collector", nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled attribution accepted", err)
	}
}
