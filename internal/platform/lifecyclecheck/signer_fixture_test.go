//go:build releasebinary

package lifecyclecheck

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/awskms"
)

func TestReleaseFixtureSignerProvidesReadinessWithoutSigning(t *testing.T) {
	server := newReadinessKMSFixture(t)
	for name, value := range map[string]string{"AWS_ACCESS_KEY_ID": "fixture-access", "AWS_SECRET_ACCESS_KEY": "fixture-secret", "AWS_EC2_METADATA_DISABLED": "true", "AWS_CONFIG_FILE": os.DevNull, "AWS_SHARED_CREDENTIALS_FILE": os.DevNull} {
		t.Setenv(name, value)
	}
	executor, err := awskms.New(t.Context(), awskms.Config{Region: "eu-north-1", KeyID: "alias/lifecycle-fixture", Endpoint: server.URL, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = executor.Close() })
	if err := executor.CheckReadiness(t.Context()); err != nil {
		t.Fatal("fixture failed a real SDK metadata request", err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, strings.NewReader(`{"KeyId":"alias/lifecycle-fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Amz-Target", "TrentService.Sign")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatal("fixture accepted a signing operation")
	}
}

func newReadinessKMSFixture(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		var input struct {
			KeyID string `json:"KeyId"`
		}
		if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "TrentService.DescribeKey" || json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&input) != nil || input.KeyID != "alias/lifecycle-fixture" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"InvalidRequestException","message":"fixture permits configured-key metadata only"}`))
			return
		}
		_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyId":"fixture-key","Enabled":true,"KeyState":"Enabled","KeyUsage":"SIGN_VERIFY","SigningAlgorithms":["ECDSA_SHA_256"]}}`))
	}))
	t.Cleanup(server.Close)
	return server
}
