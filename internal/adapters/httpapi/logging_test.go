package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/platform/logging"
	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func TestRequestLoggingOmitsSecretsAndCorrelatesAuthorizedCommand(t *testing.T) {
	var out bytes.Buffer
	logger, err := logging.New(&out, "api", runtimeinfo.Current(), logging.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server, token := testServer(t)
	server.logger = logger
	const canary = "CANARY_EVIDENCE_BODY_AND_QUERY_19cd"
	request := httptest.NewRequest(http.MethodPost, "/v1/products?token="+canary, strings.NewReader(`{"name":"`+canary+`","slug":"safe"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Cookie", "private="+canary)
	request.Header.Set("X-Request-ID", canary)
	request.Header.Set("Idempotency-Key", canary)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d", response.Code)
	}
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), canary) || strings.Contains(out.String(), token) || strings.Contains(out.String(), "/v1/products") {
		t.Fatal("request content or credential leaked")
	}
	if record["request_id"] != logging.Reference("request", canary) || record["operation_id"] != logging.Reference("operation", "createProduct") || record["tenant_id"] == "" || record["status"] != float64(201) || record["result_code"] != "succeeded" {
		t.Fatal("request correlation, tenant binding or result missing", record)
	}
	if response.Header().Get("X-Request-ID") != canary {
		t.Fatal("public request ID contract changed")
	}
}

func TestRequestLoggingCoversEarlyRejectionAndPanicWithoutFalseSuccess(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		panicValue bool
	}{
		{"early-rejection", http.StatusTooManyRequests, false}, {"panic", 0, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out bytes.Buffer
			l, err := logging.New(&out, "api", runtimeinfo.Current(), logging.Config{})
			if err != nil {
				t.Fatal(err)
			}
			s := &Server{logger: l, mux: http.NewServeMux()}
			h := requestIDMiddleware(s.observeRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if test.panicValue {
					panic("CANARY_SECRET_PANIC")
				}
				w.WriteHeader(test.status)
			})))
			func() {
				defer func() {
					if p := recover(); p != nil && !test.panicValue {
						t.Fatal(p)
					}
				}()
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/CANARY_SECRET_PATH?token=CANARY_SECRET_QUERY", nil))
			}()
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "CANARY_SECRET") || record["request_id"] == "" || record["status"] != float64(test.status) || record["retry_class"] != "transient" {
				t.Fatal("unsafe or missing edge event", record)
			}
			if test.panicValue && record["result_code"] != "uncertain" || !test.panicValue && record["result_code"] != "rejected" {
				t.Fatal("failure marked successful")
			}
		})
	}
}

func TestRequestLoggerOptionReachesNativeConstructor(t *testing.T) {
	var out bytes.Buffer
	l, err := logging.New(&out, "api", runtimeinfo.Current(), logging.Config{})
	if err != nil {
		t.Fatal(err)
	}
	opts := nativeConstructorOptions()
	opts.Logger = l
	s, err := NewNativeServerWithOptionsContext(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/v1/health", nil))
	if response.Code != 200 || !strings.Contains(out.String(), `"msg":"http_request"`) || !strings.Contains(out.String(), logging.Reference("operation", "health")) {
		t.Fatal("native logger option was not installed")
	}
}

func TestRequestLoggingUsesProblemRetryPolicy(t *testing.T) {
	for _, tc := range []struct {
		err   error
		retry string
	}{{app.NewVersionConflict(2), "transient"}, {app.ErrConflict, "none"}, {app.ErrRateLimited, "transient"}, {app.ErrIdempotencyInProgress, "transient"}} {
		var out bytes.Buffer
		l, err := logging.New(&out, "api", runtimeinfo.Current(), logging.Config{})
		if err != nil {
			t.Fatal(err)
		}
		s := &Server{logger: l, mux: http.NewServeMux()}
		s.observeRequest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeProblem(w, r, tc.err) })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/test", nil))
		var record map[string]any
		if err := json.Unmarshal(out.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record["retry_class"] != tc.retry {
			t.Fatalf("retry=%v want %s", record["retry_class"], tc.retry)
		}
	}
}
