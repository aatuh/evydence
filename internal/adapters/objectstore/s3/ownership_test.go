package s3

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOwnedS3TransportClosesAfterSuccessAndPartialStartupFailure(t *testing.T) {
	for _, allowed := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "bucket-denied"}[allowed], func(t *testing.T) {
			closed := make(chan struct{}, 4)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodHead || strings.TrimSuffix(r.URL.Path, "/") != "/evidence" {
					t.Error("unexpected bucket probe", r.Method, r.URL.Path)
				}
				if !allowed {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateClosed {
					closed <- struct{}{}
				}
			}
			server.Start()
			defer server.Close()
			store, err := New(t.Context(), Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "evidence", AccessKeyID: "access", SecretAccessKey: "secret"})
			if allowed {
				if err != nil {
					t.Fatal(err)
				}
				if err = store.Close(); err != nil {
					t.Fatal(err)
				}
				if err = store.Close(); err != nil {
					t.Fatal("repeat close failed", err)
				}
			} else if err == nil || store != nil {
				t.Fatal("bucket denial did not fail startup")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("owned constructor transport leaked an idle connection")
			}
		})
	}
}
