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

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type productHTTPFake struct {
	guards   int
	guardErr error
	calls    int
	actor    identitydomain.Actor
	input    releaseapp.CreateProductInput
	err      error
}

func (f *productHTTPFake) AuthorizeProductCreation(context.Context, identitydomain.Actor, releaseapp.CreateProductInput) error {
	f.guards++
	return f.guardErr
}

func (f *productHTTPFake) CreateProduct(_ context.Context, actor identitydomain.Actor, in releaseapp.CreateProductInput) (releasedomain.Product, error) {
	f.calls++
	f.actor, f.input = actor, in
	return releasedomain.Product{ID: "durable-product", TenantID: actor.TenantID, Name: in.Name, Slug: in.Slug, CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}, f.err
}

func TestProductHTTPMapsFocusedDTOReplayValidationAndPrivateErrors(t *testing.T) {
	local, secret := testServer(t)
	commands := &productHTTPFake{}
	server, err := NewServerWithOptions(local.ledger, ServerOptions{ProductCommands: commands, DurableCommandExecutor: newTrustHTTPReplayExecutor(t, local, secret)})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"name":"Product","slug":"product"}`)
	response := postRaw(t, server, secret, "/v1/products", "create-product", body, 201)
	if commands.calls != 1 || commands.actor.TenantID == "" || !reflect.DeepEqual(commands.input, releaseapp.CreateProductInput{Name: "Product", Slug: "product"}) {
		t.Fatal("focused product input changed", commands)
	}
	for _, field := range []string{`"id":"durable-product"`, `"tenant_id":"` + commands.actor.TenantID + `"`, `"name":"Product"`, `"slug":"product"`, `"created_at":"2026-01-02T03:04:05Z"`} {
		if !strings.Contains(response, field) {
			t.Fatal("product DTO lost field", field, response)
		}
	}
	var envelope struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		t.Fatal(err)
	}
	assertProductSchemaFields(t, server, envelope.Data)
	assertTrustHTTPReplay(t, response, postRaw(t, server, secret, "/v1/products", "create-product", body, 201))
	if commands.calls != 1 {
		t.Fatal("product replay repeated command", commands.calls)
	}
	postRaw(t, server, secret, "/v1/products", "create-product", append(body, ' '), 409)
	// Null objects and missing scalar values are application validation, covered
	// by the real command in the live suite. These are decoder-level failures.
	for i, bad := range []string{`{`, `{} {}`, `[]`, `{"name":1,"slug":"product"}`, `{"name":"Product","name":"Other","slug":"product"}`, `{"name":"Product","slug":"product","tenant_id":"other"}`} {
		postRaw(t, server, secret, "/v1/products", fmt.Sprintf("bad-product-%d", i), []byte(bad), 400)
	}
	if commands.calls != 1 {
		t.Fatal("malformed JSON reached product command", commands.calls)
	}
	for i, tc := range []struct {
		err    error
		status int
	}{{releaseapp.ErrValidation, 400}, {releaseapp.ErrNotFound, 404}, {releaseapp.ErrConflict, 409}, {application.ErrForbidden, 403}, {application.ErrUnauthorized, 401}, {errors.New("private product SQL"), 500}} {
		commands.err = tc.err
		failure := postRaw(t, server, secret, "/v1/products", fmt.Sprintf("product-failure-%d", i), body, tc.status)
		if strings.Contains(failure, "private product SQL") || strings.Contains(failure, "durable-product") {
			t.Fatal("product failure exposed internals or result", failure)
		}
	}
}
