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
		{name: "local API memory", raw: "local_memory", process: API, want: LocalMemory},
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

func TestLocalMemoryProfileDeclaresNonDurableLimitations(t *testing.T) {
	limitations := LocalMemory.Limitations()
	if len(limitations) == 0 || !strings.Contains(strings.ToLower(strings.Join(limitations, " ")), "lost") {
		t.Fatalf("local-memory limitations do not warn about data loss: %#v", limitations)
	}
	if len(PostgreSQL.Limitations()) != 0 {
		t.Fatalf("postgres profile unexpectedly inherits local-memory limitations: %#v", PostgreSQL.Limitations())
	}
}
