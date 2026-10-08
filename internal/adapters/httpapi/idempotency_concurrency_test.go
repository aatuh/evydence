package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aatuh/evydence/internal/app"
)

type concurrentHTTPResult struct {
	status int
	body   string
}

// TestCreateProductConcurrentIdempotencyRetriesOneStoredResponse exercises the
// actual HTTP authentication, body hashing, idempotency, and problem-details
// path. The in-memory adapter can truthfully return in-progress to a caller
// that arrives before the owner completes; those callers retry below using the
// same key and receive the one completed response.
func TestCreateProductConcurrentIdempotencyRetriesOneStoredResponse(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: newSerializedHTTPFixtureTransactions()})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Concurrent HTTP", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant: %v", err)
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	// Native authentication avoids the retired aggregate's opposing
	// credential/command lock order while retaining actual key-use writes.
	server.bindAPIKeyFixtureResources("test", nil)

	const callers = 32
	body := []byte(`{"name":"Concurrent Payments","slug":"concurrent-payments"}`)
	ready := make(chan struct{}, callers)
	start := make(chan struct{})
	results := make(chan concurrentHTTPResult, callers)
	for i := 0; i < callers; i++ {
		go func() {
			ready <- struct{}{}
			<-start
			recorder := httptest.NewRecorder()
			request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/v1/products", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+secret)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Idempotency-Key", "http-concurrent-product")
			server.Handler().ServeHTTP(recorder, request)
			results <- concurrentHTTPResult{status: recorder.Code, body: recorder.Body.String()}
		}()
	}
	for i := 0; i < callers; i++ {
		<-ready
	}
	close(start)

	var createdIDs []string
	for i := 0; i < callers; i++ {
		result := <-results
		switch result.status {
		case http.StatusCreated:
			createdIDs = append(createdIDs, productIDFromHTTPResponse(t, result.body))
		case http.StatusConflict:
			if !strings.Contains(result.body, "IDEMPOTENCY_IN_PROGRESS") {
				t.Fatalf("unexpected conflict response: %s", result.body)
			}
		default:
			t.Fatalf("concurrent create status=%d body=%s", result.status, result.body)
		}
	}

	// A definitive retry models callers that received an in-progress response or
	// lost their response while the owner committed. It must replay the one
	// stored response without a second product write.
	retry := httptest.NewRecorder()
	retryRequest := httptest.NewRequest(http.MethodPost, "/v1/products", bytes.NewReader(body))
	retryRequest.Header.Set("Authorization", "Bearer "+secret)
	retryRequest.Header.Set("Content-Type", "application/json")
	retryRequest.Header.Set("Idempotency-Key", "http-concurrent-product")
	server.Handler().ServeHTTP(retry, retryRequest)
	if retry.Code != http.StatusCreated {
		t.Fatalf("retry status=%d body=%s", retry.Code, retry.Body.String())
	}
	replayedID := productIDFromHTTPResponse(t, retry.Body.String())
	for _, id := range createdIDs {
		if id != replayedID {
			t.Fatalf("concurrent created response id=%q, replay id=%q", id, replayedID)
		}
	}

	list := httptest.NewRecorder()
	listRequest := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
	listRequest.Header.Set("Authorization", "Bearer "+secret)
	server.Handler().ServeHTTP(list, listRequest)
	if list.Code != http.StatusOK {
		t.Fatalf("list products status=%d body=%s", list.Code, list.Body.String())
	}
	var products struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &products); err != nil {
		t.Fatalf("decode product list: %v", err)
	}
	if len(products.Data) != 1 || products.Data[0].ID != replayedID {
		t.Fatalf("concurrent HTTP create produced products=%#v, replayed id=%q", products.Data, replayedID)
	}
}

func productIDFromHTTPResponse(t *testing.T, body string) string {
	t.Helper()
	var response struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		t.Fatalf("decode product response: %v", err)
	}
	if response.Data.ID == "" {
		t.Fatalf("product response did not contain id: %s", body)
	}
	return response.Data.ID
}

// Memory uses optimistic whole-snapshot commits, unlike SQL row locks. This
// fixture serializes transaction admission, not HTTP callers, so real native
// credential-use writes cannot conflict with unrelated read-only commits.
// All 32 concurrent requests and the original exact-once assertions remain.
// This does not prove PostgreSQL parallel transaction behavior.
type serializedHTTPFixtureTransactions struct {
	base      *app.MemoryUnitOfWorkFactory
	admission chan struct{}
}

func newSerializedHTTPFixtureTransactions() *serializedHTTPFixtureTransactions {
	return &serializedHTTPFixtureTransactions{base: app.NewMemoryUnitOfWorkFactory(), admission: make(chan struct{}, 1)}
}
func (f *serializedHTTPFixtureTransactions) BeginUnitOfWork(ctx context.Context) (app.UnitOfWork, error) {
	if ctx == nil {
		return nil, app.ErrValidation
	}
	select {
	case f.admission <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	u, err := f.base.BeginUnitOfWork(ctx)
	if err != nil {
		<-f.admission
		return nil, err
	}
	return &serializedHTTPFixtureTransaction{UnitOfWork: u, factory: f}, nil
}

type serializedHTTPFixtureTransaction struct {
	app.UnitOfWork
	factory  *serializedHTTPFixtureTransactions
	released sync.Once
}

func (u *serializedHTTPFixtureTransaction) release() { u.released.Do(func() { <-u.factory.admission }) }
func (u *serializedHTTPFixtureTransaction) Commit(ctx context.Context) error {
	defer u.release()
	return u.UnitOfWork.Commit(ctx)
}
func (u *serializedHTTPFixtureTransaction) Rollback(ctx context.Context) error {
	defer u.release()
	return u.UnitOfWork.Rollback(ctx)
}
func TestSerializedHTTPFixtureTransactionsCancelAdmissionAndRelease(t *testing.T) {
	f := newSerializedHTTPFixtureTransactions()
	u, err := f.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if next, err := f.BeginUnitOfWork(ctx); !errors.Is(err, context.Canceled) || next != nil {
		t.Fatal("cancelled admission opened a transaction", err)
	}
	if err := u.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, err = f.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal("rollback did not release admission", err)
	}
	if err := u.Commit(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled commit was accepted", err)
	}
	if err := u.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, err = f.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal("failed commit did not release admission", err)
	}
	if err := u.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	u, err = f.BeginUnitOfWork(t.Context())
	if err != nil {
		t.Fatal("successful commit did not release admission", err)
	}
	if err := u.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
}
