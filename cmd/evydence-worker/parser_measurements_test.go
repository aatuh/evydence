package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/adapters/postgres"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

func TestWorkerParserMeasurementsFollowActualReplayAndTenantFence(t *testing.T) {
	for _, phase := range []string{"success", "malformed", "foreign-subject", "projection-mismatch"} {
		t.Run(phase, func(t *testing.T) {
			body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"PRIVATE_COMPONENT"}]}`)
			if phase == "malformed" {
				body = []byte(`{"PRIVATE_INVALID`)
			}
			hash := digestBytes(body)
			job := postgres.ClaimedJob{
				ID: "PRIVATE_JOB", TenantID: "ten_test", Kind: "parse_sbom", SubjectType: "sbom",
				SubjectID: "sbom_test", LeaseToken: "PRIVATE_LEASE",
				Payload: map[string]any{"payload_ref": "object://tenants/ten_test/payloads/sbom.json", "payload_hash": hash},
			}
			subjectTenant := job.TenantID
			if phase == "foreign-subject" {
				subjectTenant = "other_tenant"
			}
			store := &fakeFocusedParserStateStore{state: app.PersistedState{SBOMs: map[string]domain.SBOM{
				job.SubjectID: {ID: job.SubjectID, TenantID: subjectTenant},
			}}}
			if phase == "projection-mismatch" {
				store.state.SBOMs[job.SubjectID] = domain.SBOM{ID: job.SubjectID, TenantID: subjectTenant, SpecVersion: "1.5"}
			}
			object := app.Object{Key: "tenants/ten_test/payloads/sbom.json", TenantID: job.TenantID, Digest: hash, Bytes: body}
			o := &workerObservationFixture{}
			err := processJobWithObjects(telemetry.WithObserver(t.Context(), o), store, fakeObjectGetter{object: object}, job)
			if (err == nil) != (phase == "success") || store.loadCalls != 0 || o.active != 0 {
				t.Fatal("parser/tenant fence or focused state access changed", err)
			}
			if phase == "foreign-subject" {
				if len(o.events) != 0 || len(store.mutation.SBOMs) != 0 {
					t.Fatal("foreign subject reached parsing or mutation", o.events)
				}
				return
			}
			parseOutcome := telemetry.OutcomeSucceeded
			if phase == "malformed" {
				parseOutcome = telemetry.OutcomeFailed
			}
			if len(o.events) != 1 || o.events[0].Operation != telemetry.OperationParseSBOM || o.events[0].Outcome != parseOutcome {
				t.Fatal("actual replay result was not measured", o.events)
			}
			if phase == "success" && (store.jobID != job.ID || store.leaseToken != job.LeaseToken || len(store.mutation.SBOMs) != 1 || store.mutation.SBOMs[0].Components[0].Name != "PRIVATE_COMPONENT") {
				t.Fatal("measurement changed claimed replay mutation")
			}
			if phase != "success" && len(store.mutation.SBOMs) != 0 {
				t.Fatal("invalid replay published a mutation")
			}
			encoded, _ := json.Marshal(o.events)
			if strings.Contains(string(encoded), "PRIVATE") {
				t.Fatal("replay metrics disclosed evidence, job or lease")
			}
		})
	}
}
