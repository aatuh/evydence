package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	ledger := app.NewLedger(app.Config{APIKeyPepper: "test"})
	_, _, secret, err := ledger.BootstrapTenant(t.Context(), "Concurrent HTTP", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant: %v", err)
	}
	server, err := NewServer(ledger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

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
