package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
)

func TestTenantBootstrapCommandsUseOnlyIdentityCapabilities(t *testing.T) {
	f := newIdentityServiceFixture(t)
	config := TenantBootstrapConfig{Credentials: f.service.credentials, Clock: f.service.clock, IDs: f.service.ids}
	commands, err := NewTenantBootstrapCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	input := BootstrapTenantInput{TenantName: " Tenant ", APIKeyName: " Admin ", Scopes: []string{"evidence:read", "admin"}}
	prepared, err := commands.PrepareTenantBootstrap(t.Context(), input)
	if err != nil || prepared.Tenant.Name != "Tenant" || prepared.APIKey.Name != "Admin" || !reflect.DeepEqual(prepared.APIKey.Scopes, []string{"admin", "evidence:read"}) || input.Scopes[0] != "evidence:read" {
		t.Fatal("bootstrap preparation changed inputs or output", err)
	}
	err = f.transactions.Execute(t.Context(), func(ctx context.Context, tx Transaction) error {
		return commands.CommitTenantBootstrap(ctx, serviceTenantBootstrapTransaction{tx}, prepared)
	})
	if err != nil || len(f.transactions.state.tenants) != 1 || len(f.transactions.state.apiKeys) != 1 || len(f.transactions.state.audit) != 1 {
		t.Fatal("focused identity commit failed", err)
	}
	_, publicKey, _ := prepared.PublicResult()
	publicKey.Scopes[0] = "changed"
	if prepared.APIKey.Scopes[0] != "admin" || publicKey.Hash != "" {
		t.Fatal("public bootstrap DTO aliases stored scopes or exposes credential hash")
	}
	for _, alter := range []func(*TenantBootstrapConfig){func(c *TenantBootstrapConfig) { c.Credentials = nil }, func(c *TenantBootstrapConfig) { c.Clock = nil }, func(c *TenantBootstrapConfig) { c.IDs = nil }} {
		bad := config
		alter(&bad)
		if _, err := NewTenantBootstrapCommands(bad); !errors.Is(err, ErrValidation) {
			t.Fatal("missing bootstrap dependency accepted", err)
		}
	}
}

func TestTenantBootstrapCommandsRejectInvalidInputAndPreparedIdentity(t *testing.T) {
	f := newIdentityServiceFixture(t)
	commands, err := NewTenantBootstrapCommands(TenantBootstrapConfig{Credentials: f.service.credentials, Clock: f.service.clock, IDs: f.service.ids})
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []BootstrapTenantInput{
		{TenantName: " ", APIKeyName: "admin"},
		{TenantName: strings.Repeat(" ", 65536) + "a", APIKeyName: "admin"},
		{TenantName: "tenant\x00", APIKeyName: "admin"},
		{TenantName: "tenant", APIKeyName: string([]byte{0xff})},
		{TenantName: "tenant", APIKeyName: "admin", Scopes: []string{strings.Repeat("x", 129)}},
		{TenantName: "tenant", APIKeyName: "admin", Scopes: make([]string, 1025)},
	} {
		if prepared, err := commands.PrepareTenantBootstrap(t.Context(), input); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(prepared, PreparedTenantBootstrap{}) {
			t.Fatal("invalid bootstrap input was prepared", err)
		}
	}
	prepared, err := commands.PrepareTenantBootstrap(t.Context(), BootstrapTenantInput{TenantName: "tenant", APIKeyName: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	prepared.APIKey.TenantID = "foreign"
	err = f.transactions.Execute(t.Context(), func(ctx context.Context, tx Transaction) error {
		return commands.CommitTenantBootstrap(ctx, serviceTenantBootstrapTransaction{tx}, prepared)
	})
	if !errors.Is(err, ErrValidation) || len(f.transactions.state.tenants) != 0 || len(f.transactions.state.apiKeys) != 0 {
		t.Fatal("foreign prepared key was committed", err)
	}
	config := TenantBootstrapConfig{Credentials: f.service.credentials, Clock: f.service.clock, IDs: application.IDGeneratorFunc(func(string) string { return "" })}
	commands, err = NewTenantBootstrapCommands(config)
	if err != nil {
		t.Fatal(err)
	}
	if prepared, err := commands.PrepareTenantBootstrap(t.Context(), BootstrapTenantInput{TenantName: "tenant", APIKeyName: "admin"}); !errors.Is(err, ErrValidation) || !reflect.DeepEqual(prepared, PreparedTenantBootstrap{}) {
		t.Fatal("invalid generated identity was returned", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := commands.PrepareTenantBootstrap(ctx, BootstrapTenantInput{}); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled bootstrap was prepared", err)
	}
}
