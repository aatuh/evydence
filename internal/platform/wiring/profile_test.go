package wiring

import (
	"strings"
	"testing"
)

func TestResolveRuntimeProfileRequiresExplicitSafeSelection(t *testing.T) {
	const databaseURL = "postgres://operator:private-password@database.example.test/evydence"
	tests := []struct {
		name       string
		raw        string
		production bool
		database   string
		process    Process
		want       Profile
		wantError  bool
	}{
		{name: "retired local API memory", raw: "local_memory", process: API, wantError: true},
		{name: "local API postgres", raw: "postgres", database: databaseURL, process: API, want: PostgreSQL},
		{name: "production API postgres", raw: "postgres", production: true, database: databaseURL, process: API, want: PostgreSQL},
		{name: "worker postgres", raw: "postgres", database: databaseURL, process: Worker, want: PostgreSQL},
		{name: "missing profile", database: databaseURL, process: API, wantError: true},
		{name: "unknown profile", raw: "hybrid", database: databaseURL, process: API, wantError: true},
		{name: "local memory with database", raw: "local_memory", database: databaseURL, process: API, wantError: true},
		{name: "production memory", raw: "local_memory", production: true, process: API, wantError: true},
		{name: "worker memory", raw: "local_memory", process: Worker, wantError: true},
		{name: "postgres without database", raw: "postgres", process: API, wantError: true},
		{name: "worker postgres without database", raw: "postgres", process: Worker, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := ResolveRuntimeProfile(tt.raw, tt.production, tt.database, tt.process)
			if tt.wantError {
				if err == nil {
					t.Fatalf("unsafe profile combination accepted: %q", profile)
				}
				if strings.Contains(err.Error(), "private-password") || strings.Contains(err.Error(), databaseURL) {
					t.Fatalf("configuration error exposed database credentials: %v", err)
				}
				return
			}
			if err != nil || profile != tt.want {
				t.Fatalf("profile = %q, error = %v, want %q", profile, err, tt.want)
			}
		})
	}
}

func TestRetiredMemoryProfileProvidesSafePostgresMigrationHint(t *testing.T) {
	for _, process := range []Process{API, Worker} {
		for _, production := range []bool{false, true} {
			for _, databaseURL := range []string{"", "postgres://operator:private-password@database.example.test/evydence"} {
				profile, err := ResolveRuntimeProfile("local_memory", production, databaseURL, process)
				if profile != "" || err == nil || !strings.Contains(err.Error(), "retired") || !strings.Contains(err.Error(), "postgres") || !strings.Contains(err.Error(), "EVYDENCE_DATABASE_URL") {
					t.Fatalf("retired profile accepted or missing migration hint: process=%s production=%t profile=%s err=%v", process, production, profile, err)
				}
				if strings.Contains(err.Error(), "private-password") || databaseURL != "" && strings.Contains(err.Error(), databaseURL) {
					t.Fatal("retirement error exposed connection credentials")
				}
			}
		}
	}
}

// The retired value is test input, not a supported production profile.
const retiredMemoryProfile Profile = "local_memory"

func TestLocalMemoryProfileDeclaresRetirementAndPostgresRemainsSupported(t *testing.T) {
	profile, err := ResolveRuntimeProfile(string(retiredMemoryProfile), false, "", API)
	if profile != "" || err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("retirement notice missing: profile=%q err=%v", profile, err)
	}
	profile, err = ResolveRuntimeProfile(string(PostgreSQL), false, "postgres://database.example.test/evydence", API)
	if err != nil || profile != PostgreSQL {
		t.Fatalf("supported PostgreSQL profile rejected: profile=%q err=%v", profile, err)
	}
}
