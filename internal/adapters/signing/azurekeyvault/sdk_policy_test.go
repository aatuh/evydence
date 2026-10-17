package azurekeyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// SDK environment initialization occurs before tests, so a fresh process is
// required to prove that the project owns an environment-enabled raw listener.
func TestAzureSDKProcessPolicySuppressesRawLogsAndTelemetry(t *testing.T) {
	const helper = "EVYDENCE_TEST_AZURE_POLICY_CHILD"
	if os.Getenv(helper) == "1" {
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		executor, err := New(Config{VaultURL: "https://vault.example.test", KeyName: "key", KeyVersion: "v1"})
		if err != nil {
			t.Fatal("construct fixture Azure credential")
		}
		defer executor.Close()
		token, err := executor.credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://vault.azure.net/.default"}})
		if err != nil || token.Token != "PRIVATE_ACCESS_TOKEN" {
			t.Fatal("retrieve fixture Azure token")
		}
		return
	}
	var calls atomic.Int32
	var telemetry atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if request.Method != http.MethodGet || request.URL.Path != "/PRIVATE_METADATA/token" || request.Header.Get("X-IDENTITY-HEADER") != "PRIVATE_IDENTITY_HEADER" {
			t.Error("native identity request changed its endpoint, method or credential")
		}
		for _, values := range request.Header {
			for _, value := range values {
				if strings.Contains(value, "azsdk-go-") || strings.Contains(value, "PRIVATE_OPERATING_SYSTEM") {
					telemetry.Store(true)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "PRIVATE_ACCESS_TOKEN", "expires_on": fmt.Sprint(time.Now().Add(time.Hour).Unix()), "expires_in": "3600", "resource": "https://vault.azure.net", "token_type": "Bearer"})
	}))
	defer server.Close()
	var environment []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == helper || name == "OS" || strings.HasPrefix(name, "AZURE_") || strings.HasPrefix(name, "MSI_") || strings.HasPrefix(name, "IDENTITY_") || strings.HasPrefix(name, "IMDS_") {
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(environment, helper+"=1", "AZURE_SDK_GO_LOGGING=all", "OS=PRIVATE_OPERATING_SYSTEM", "AZURE_TOKEN_CREDENTIALS=ManagedIdentityCredential", "IDENTITY_ENDPOINT="+server.URL+"/PRIVATE_METADATA/token", "IDENTITY_HEADER=PRIVATE_IDENTITY_HEADER")
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("locate current test executable")
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestAzureSDKProcessPolicySuppressesRawLogsAndTelemetry$", "-test.count=1")
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("Azure policy subprocess failed: %v; output withheld", err)
	}
	if calls.Load() != 1 {
		t.Fatal("fixture identity was not requested exactly once")
	}
	if telemetry.Load() {
		t.Error("SDK telemetry or operator OS metadata escaped credential policy")
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), "PRIVATE") {
		t.Errorf("SDK raw diagnostics escaped process policy (%d stderr bytes)", stderr.Len())
	}
}
