package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/wiring"
)

func TestBootstrapInputPreservesRawOperatorValueForBoundedValidation(t *testing.T) {
	// NUL cannot appear in an OS environment value; the core input test
	// covers that case directly instead.
	for _, raw := range []string{" Tenant ", strings.Repeat(" ", 65536) + "a", string([]byte{0xff})} {
		t.Setenv("EVYDENCE_BOOTSTRAP_TENANT", raw)
		input := tenantBootstrapInputFromEnv()
		if input.TenantName != raw || input.APIKeyName != "local-admin" || len(input.Scopes) != 1 || input.Scopes[0] != "*" {
			t.Fatal("operator bootstrap input was trimmed before its raw byte bound")
		}
	}
	t.Setenv("EVYDENCE_BOOTSTRAP_TENANT", "")
	if input := tenantBootstrapInputFromEnv(); input.TenantName != "Local Tenant" {
		t.Fatal("unset bootstrap name lost its default")
	}
}

func TestBootstrapOutputRequiresExplicitNonProductionSecretPrinting(t *testing.T) {
	result := wiring.TenantBootstrapResult{Created: true, Tenant: identitydomain.Tenant{ID: "ten_1"}, Key: identitydomain.APIKey{ID: "key_1", TenantID: "ten_1"}, Secret: "bootstrap-output-private-canary"}
	for _, tc := range []struct {
		production, printSecret bool
		wantError, wantSecret   bool
	}{{false, false, false, false}, {false, true, false, true}, {true, false, false, false}, {true, true, true, false}} {
		var output bytes.Buffer
		err := writeTenantBootstrapResult(&output, result, tc.production, tc.printSecret)
		if (err != nil) != tc.wantError || strings.Contains(output.String(), result.Secret) != tc.wantSecret {
			t.Fatal("bootstrap secret-printing policy changed", tc)
		}
		if err != nil && strings.Contains(err.Error(), result.Secret) {
			t.Fatal("bootstrap output error exposed secret")
		}
		if tc.wantSecret {
			var document map[string]json.RawMessage
			if err := json.Unmarshal(output.Bytes(), &document); err != nil || len(document) != 3 || document["tenant_id"] == nil || document["api_key"] == nil || document["secret"] == nil {
				t.Fatal("bootstrap output compatibility changed", err)
			}
			var key map[string]json.RawMessage
			if err := json.Unmarshal(document["api_key"], &key); err != nil || key["id"] == nil || key["tenant_id"] == nil || key["created_at"] == nil || key["ID"] != nil || key["Hash"] != nil || key["hash"] != nil {
				t.Fatal("bootstrap key metadata no longer matches the existing wire contract", err)
			}
		}
	}
	var output bytes.Buffer
	if err := writeTenantBootstrapResult(&output, wiring.TenantBootstrapResult{}, false, true); err != nil || output.Len() != 0 {
		t.Fatal("restart/no-op emitted bootstrap output", err)
	}
}

type bootstrapOutputFailure struct{}

func (bootstrapOutputFailure) Write([]byte) (int, error) {
	return 0, errors.New("private-bootstrap-output-error")
}

func TestBootstrapOutputFailureIsReportedWithoutBackendDetails(t *testing.T) {
	result := wiring.TenantBootstrapResult{Created: true, Secret: "private-bootstrap-secret"}
	if err := writeTenantBootstrapResult(bootstrapOutputFailure{}, result, false, true); err == nil || strings.Contains(err.Error(), result.Secret) || strings.Contains(err.Error(), "private-bootstrap-output-error") {
		t.Fatal("committed bootstrap output failure was ignored or leaked details")
	}
}
