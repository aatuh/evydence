package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/runtimeinfo"
)

func testIdentity() runtimeinfo.Identity {
	return runtimeinfo.Identity{Version: "v1.2.3-rc.4", Commit: strings.Repeat("a", 40), BuildTime: "2026-10-16T05:00:00Z", Dirty: true, GoVersion: "go1.26.9", ReleaseManifestDigest: "sha256:" + strings.Repeat("b", 64)}
}

func TestConfigurationRejectsUntrustedValuesWithoutEcho(t *testing.T) {
	for _, bad := range []string{"CANARY_OPERATOR_SECRET", "info\nerror", "trace", "-4", "json\x00", strings.Repeat("x", 10000)} {
		for _, c := range []Config{{Level: bad}, {Format: bad}} {
			var out bytes.Buffer
			if _, err := New(&out, "api", testIdentity(), c); err == nil || strings.Contains(err.Error(), bad) || out.Len() != 0 {
				t.Fatalf("invalid configuration was accepted or disclosed")
			}
		}
	}
	for _, service := range []string{"", "CANARY_OPERATOR_SECRET", "API"} {
		if _, err := New(&bytes.Buffer{}, service, testIdentity(), Config{}); err == nil || strings.Contains(err.Error(), service) && service != "" {
			t.Fatal("invalid service accepted or echoed")
		}
	}
	if _, err := New(nil, "api", testIdentity(), Config{}); err == nil {
		t.Fatal("nil writer accepted")
	}
}

func TestAllEventsOmitSecretCanariesAndPreserveStructuredIdentity(t *testing.T) {
	canary := "CANARY_RAW_BEARER_AND_EVIDENCE_7b3c"
	for event := Startup; event <= Cleanup; event++ {
		t.Run(fmt.Sprint(event), func(t *testing.T) {
			var out bytes.Buffer
			logger, err := New(&out, "api", testIdentity(), Config{Level: "debug"})
			if err != nil {
				t.Fatal(err)
			}
			logger.Log(context.Background(), event, Fields{RequestID: canary, TenantID: canary, ResourceID: canary, JobID: canary, ReceiptID: canary, OperationID: canary, Duration: 2 * time.Millisecond, Status: 201, Attempt: 2, Result: Succeeded, Retry: Transient})
			raw := out.String()
			if strings.Contains(raw, canary) || strings.Count(raw, "\n") != 1 {
				t.Fatal("raw input or multiline record leaked")
			}
			var record map[string]any
			if err := json.Unmarshal(out.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"time", "level", "msg", "service", "version", "commit", "build_time", "dirty", "go_version", "release_manifest_digest", "request_id", "tenant_id", "resource_id", "job_id", "receipt_id", "operation_id", "duration_ms", "status", "attempt", "result_code", "retry_class"} {
				if _, ok := record[key]; !ok {
					t.Errorf("missing %s", key)
				}
			}
			id := testIdentity()
			if record["version"] != id.Version || record["commit"] != id.Commit || record["build_time"] != id.BuildTime || record["dirty"] != true || record["go_version"] != id.GoVersion || record["release_manifest_digest"] != id.ReleaseManifestDigest {
				t.Fatal("build identity changed")
			}
			if record["duration_ms"] != float64(2) || record["status"] != float64(201) || record["result_code"] != "succeeded" || record["retry_class"] != "transient" {
				t.Fatal("semantic fields changed")
			}
			if record["request_id"] == record["tenant_id"] {
				t.Fatal("reference domains collide")
			}
		})
	}
}

func TestFormatsAndLevelsRetainSemanticFields(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		for _, level := range []string{"debug", "info", "warn", "error"} {
			var out bytes.Buffer
			l, err := New(&out, "worker", testIdentity(), Config{Format: format, Level: level})
			if err != nil {
				t.Fatal(err)
			}
			l.Log(t.Context(), Startup, Fields{Result: Started})
			l.Log(t.Context(), Shutdown, Fields{Result: Failed, Retry: Permanent})
			lines := strings.Split(strings.TrimSpace(out.String()), "\n")
			want := 2
			if level == "warn" || level == "error" {
				want = 1
			}
			if len(lines) != want {
				t.Fatalf("format=%s level=%s records=%d want=%d", format, level, len(lines), want)
			}
			for _, field := range []string{"service", "version", "commit", "request_id", "tenant_id", "operation_id", "duration_ms", "result_code", "retry_class"} {
				if !strings.Contains(out.String(), field) {
					t.Errorf("%s missing %s", format, field)
				}
			}
			if !strings.Contains(out.String(), "failed") || !strings.Contains(out.String(), "permanent") {
				t.Fatal("result lost")
			}
		}
	}
}

func TestInvalidEventsAndFieldsFailClosed(t *testing.T) {
	var out bytes.Buffer
	l, err := New(&out, "migrate", runtimeinfo.Identity{Version: "CANARY_SECRET", Commit: "CANARY_SECRET", BuildTime: "CANARY_SECRET", GoVersion: "CANARY_SECRET", ReleaseManifestDigest: "CANARY_SECRET"}, Config{})
	if err != nil {
		t.Fatal(err)
	}
	l.Log(t.Context(), Event(255), Fields{})
	if out.Len() != 0 {
		t.Fatal("unknown event emitted")
	}
	l.Log(t.Context(), Shutdown, Fields{Result: Result(255), Retry: RetryClass(255), Status: -1, Duration: -time.Second, Attempt: -1, ResourceID: strings.Repeat("CANARY_SECRET", 10000)})
	if strings.Contains(out.String(), "CANARY_SECRET") {
		t.Fatal("untrusted build metadata leaked")
	}
	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record["result_code"] != "unknown" || record["retry_class"] != "unknown" || record["status"] != float64(0) || record["duration_ms"] != float64(0) || record["attempt"] != float64(0) {
		t.Fatal("invalid fields were not bounded")
	}
	var absent *Logger
	absent.Log(t.Context(), Startup, Fields{})
}

func TestConcurrentRecordsAreCompleteAndContextIsIsolated(t *testing.T) {
	var out bytes.Buffer
	l, err := New(&out, "api", testIdentity(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Go(func() { l.Log(context.Background(), Command, Fields{RequestID: fmt.Sprint(i), Result: Succeeded}) })
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 30 {
		t.Fatalf("records=%d", len(lines))
	}
	seen := map[any]bool{}
	for _, line := range lines {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if seen[r["request_id"]] {
			t.Fatal("request correlation collided")
		}
		seen[r["request_id"]] = true
	}
}

func TestEnvironmentConfigurationDefaultsAndCase(t *testing.T) {
	if _, err := ConfigFromEnv(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
	c, err := ConfigFromEnv(func(name string) string {
		if name == "EVYDENCE_LOG_LEVEL" {
			return " WARN "
		}
		return " TEXT "
	})
	if err != nil {
		t.Fatal(err)
	}
	level, format, err := c.options()
	if err != nil || level.String() != "WARN" || format != "text" {
		t.Fatal("environment mapping failed")
	}
	if Reference("request", "") != "" || Reference("request", "one") != "sha256:4a8d04a7b5c79d038150459069f0ffe7e852a5d0869dd769453d5d8a2fbe5fdb" || Reference("request", "one") == Reference("tenant", "one") {
		t.Fatal("reference contract failed")
	}
}
