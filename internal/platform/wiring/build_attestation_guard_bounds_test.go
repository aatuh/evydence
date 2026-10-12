package wiring

import (
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func TestPostgresBuildAttestationGuardRejectsMalformedOrOversizedStoredOutputIDs(t *testing.T) {
	store, p := openHTMLReportWiringStore(t)
	seedBuildCreationNative(t, p)
	o := subjectVerificationOptions(t, store, nil)
	a := domain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{"build:write"}}
	for _, sql := range []string{`'null'::jsonb`, `'{}'::jsonb`, `'[null]'::jsonb`, `'[{"artifact_id":null}]'::jsonb`, `'[{"artifact_id":17}]'::jsonb`, `jsonb_build_array(jsonb_build_object('artifact_id',repeat('x',1025)))`, `(SELECT jsonb_agg(jsonb_build_object('artifact_id','artifact'))FROM generate_series(1,4097))`, `(SELECT jsonb_agg(jsonb_build_object('artifact_id',repeat('x',1024)))FROM generate_series(1,2000))`} {
		if _, err := p.Exec(t.Context(), "UPDATE build_runs SET outputs="+sql+" WHERE id='linked-build'"); err != nil {
			t.Fatal(err)
		}
		if err := o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(t.Context(), a, "linked-build"); !errors.Is(err, releaseapp.ErrConflict) {
			t.Fatal("malformed selected output coordinates escaped bounds", sql, err)
		}
	}
	if _, err := p.Exec(t.Context(), `UPDATE build_runs SET outputs='[{"digest":"private-historical-metadata"}]'`); err != nil {
		t.Fatal(err)
	}
	if err := o.BuildAttestationCommands.AuthorizeBuildAttestationCreation(t.Context(), a, "linked-build"); err != nil {
		t.Fatal("ownership guard reverified historical digest-only output", err)
	}
	if got := attestationNativeCounts(t, p); got != [7]int{} {
		t.Fatal("read-only guard wrote effects", got)
	}
}
