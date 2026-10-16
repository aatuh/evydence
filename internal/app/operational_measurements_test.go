package app

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

type operationalObserverFixture struct {
	events []telemetry.Event
	active int
}

func (o *operationalObserverFixture) Observe(_ context.Context, event telemetry.Event) {
	o.events = append(o.events, event)
}
func (o *operationalObserverFixture) Begin(telemetry.Operation) func() {
	o.active++
	return func() { o.active-- }
}

func TestParserMeasurementsCoverActualNormalizationAndFailure(t *testing.T) {
	vex, err := os.ReadFile("parsers/vex/testdata/openvex/openvex-spec-minimal.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		operation telemetry.Operation
		valid     []byte
		parse     func(context.Context, evidenceapp.PayloadSource) error
	}{
		{telemetry.OperationParseSBOM, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]}`), func(ctx context.Context, source evidenceapp.PayloadSource) error {
			_, err := (SBOMPayloadParser{}).ParseSBOM(ctx, "cyclonedx", source)
			return err
		}},
		{telemetry.OperationParseVulnerabilityScan, []byte(`{"release_id":"rel_private","scanner":"generic","target_ref":"pkg:oci/api","findings":[]}`), func(ctx context.Context, source evidenceapp.PayloadSource) error {
			_, err := (VulnerabilityScanPayloadParser{}).ParseVulnerabilityScan(ctx, source)
			return err
		}},
		{telemetry.OperationParseOpenAPI, []byte(`{"openapi":"3.0.3","info":{"title":"PRIVATE_TITLE","version":"1"},"paths":{}}`), func(ctx context.Context, source evidenceapp.PayloadSource) error {
			_, err := (OpenAPIContractPayloadParser{}).ParseOpenAPIContract(ctx, source)
			return err
		}},
		{telemetry.OperationParseVEX, vex, func(ctx context.Context, source evidenceapp.PayloadSource) error {
			_, err := (VEXPayloadParser{}).ParseVEX(ctx, "openvex", source)
			return err
		}},
	} {
		t.Run(string(tc.operation), func(t *testing.T) {
			for _, valid := range []bool{true, false} {
				o := &operationalObserverFixture{}
				ctx := telemetry.WithObserver(t.Context(), o)
				raw := tc.valid
				if !valid {
					raw = []byte(`{"PRIVATE_INVALID`)
				}
				err := tc.parse(ctx, evidenceapp.BytesPayloadSource(raw))
				if (err == nil) != valid {
					t.Fatal("parser acceptance changed", valid, err)
				}
				if len(o.events) != 1 || o.events[0].Operation != tc.operation || o.events[0].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
					t.Fatal("normalization observation missing or unbalanced", o.events)
				}
				encoded, _ := json.Marshal(o.events)
				if strings.Contains(string(encoded), "PRIVATE") {
					t.Fatal("parser telemetry exposed payload/title")
				}
			}
		})
	}
}

func TestReconciliationMeasurementPreservesReadOnlyReceiptAndValidation(t *testing.T) {
	for _, valid := range []bool{true, false} {
		o := &operationalObserverFixture{}
		ctx := telemetry.WithObserver(t.Context(), o)
		f := &reconciliationFixture{}
		request := ObjectReconciliationRequest{TenantID: "ten_private", Limit: 10}
		if !valid {
			request.Limit = -1
		}
		receipt, err := ReconcileObjectPayloads(ctx, f, f, f, request)
		if (err == nil) != valid {
			t.Fatal("reconciliation acceptance changed", err)
		}
		if valid && (!receipt.DryRun || receipt.ScannedPayloads != 0) {
			t.Fatal("empty read-only reconciliation changed", receipt)
		}
		if len(o.events) != 1 || o.events[0].Operation != telemetry.OperationObjectReconciliation || o.events[0].Outcome != telemetry.OutcomeForError(err) || o.active != 0 {
			t.Fatal("reconciliation measurement lost its result", o.events)
		}
	}
}
