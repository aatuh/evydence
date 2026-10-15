package awskms

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
)

func TestNewAWSProviderClosesItsOwnedTransportAfterRequestFailure(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "local-fixture")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local-fixture-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "absent-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent-credentials"))
	closed := make(chan struct{}, 4)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","message":"fixture denial"}`)
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- struct{}{}
		}
	}
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	provider, err := New(ctx, Config{Region: "us-east-1", Endpoint: server.URL, KeyID: "alias/fixture", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	_, err = provider.Sign(ctx, app.SigningRequest{TenantID: "tenant", ProviderType: "aws_kms", KeyRef: "alias/fixture", SubjectType: "release", SubjectID: "release", CanonicalPayloadHash: "sha256:" + strings.Repeat("a", 64)})
	if err == nil || requests.Load() != 1 {
		t.Fatal("local signing denial was not exercised", err, requests.Load())
	}
	select {
	case <-closed:
		t.Fatal("fixture did not retain an idle connection for cleanup")
	default:
	}
	if err = provider.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("AWS adapter retained owned connection after close")
	}
}
