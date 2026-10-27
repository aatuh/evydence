package awskms

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/aatuh/evydence/internal/app"
)

func TestNewAWSProviderClosesItsOwnedTransportAfterRequestFailure(t *testing.T) {
	for _, closeDenied := range []bool{false, true} {
		name := "denial_keeps_connection"
		if closeDenied {
			name = "denial_closes_connection"
		}
		t.Run(name, func(t *testing.T) { testAWSOwnedTransportAfterFailure(t, closeDenied) })
	}
}

func testAWSOwnedTransportAfterFailure(t *testing.T, closeDenied bool) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "local-fixture")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local-fixture-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "absent-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "absent-credentials"))
	closed := make(chan string, 4)
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 && closeDenied {
			w.Header().Set("Connection", "close")
		}
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("X-Fixture-Connection", r.RemoteAddr)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"__type":"AccessDeniedException","message":"fixture denial"}`)
	}))
	server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateClosed {
			closed <- conn.RemoteAddr().String()
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
	// A failed SDK request may close its connection when its call context is
	// canceled. Establish a known idle connection through the very same owned
	// HTTP client, keeping its context alive until provider shutdown.
	sdk, ok := provider.client.(*kms.Client)
	if !ok || sdk.Options().HTTPClient == nil {
		t.Fatal("fixture did not use the configured SDK HTTP client")
	}
	idle := make(chan error, 1)
	probeContext := httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		PutIdleConn: func(err error) { idle <- err },
	})
	probe, err := http.NewRequestWithContext(probeContext, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := sdk.Options().HTTPClient.Do(probe)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	connection := response.Header.Get("X-Fixture-Connection")
	if readErr != nil || closeErr != nil || connection == "" || requests.Load() != 2 {
		t.Fatal("owned HTTP client probe did not complete", readErr, closeErr)
	}
	select {
	case err := <-idle:
		if err != nil {
			t.Fatal("probe connection was not retained in the owned pool", err)
		}
	default:
		t.Fatal("probe did not establish an idle connection")
	}
	for len(closed) > 0 {
		if <-closed == connection {
			t.Fatal("probe connection closed before provider shutdown")
		}
	}
	if err = provider.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case id := <-closed:
			if id == connection {
				return
			}
		case <-deadline.C:
			t.Fatal("AWS adapter retained owned connection after close")
		}
	}
}
