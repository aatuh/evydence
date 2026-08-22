package domain

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestContextCompatibilityMappersPreserveLegacyContracts(t *testing.T) {
	now := time.Date(2026, time.August, 22, 12, 0, 0, 0, time.UTC)
	reviewedAt := now.Add(time.Minute)
	values := []struct {
		name      string
		legacy    any
		roundTrip func() (any, error)
	}{
		{
			name:   "release",
			legacy: Release{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", Version: "1.0.0", Revision: 2, State: "frozen", CreatedAt: now, FrozenAt: &reviewedAt},
			roundTrip: func() (any, error) {
				model, err := ReleaseToContextModel(Release{ID: "rel_1", TenantID: "ten_1", ProductID: "prod_1", Version: "1.0.0", Revision: 2, State: "frozen", CreatedAt: now, FrozenAt: &reviewedAt})
				return ReleaseFromContextModel(model), err
			},
		},
		{
			name:   "decision",
			legacy: VulnerabilityDecision{ID: "vud_1", TenantID: "ten_1", FindingID: "finding_1", ScanID: "scan_1", Vulnerability: "CVE-1", Status: "affected", Justification: "reachable", EvidenceIDs: []string{"evi_1"}, SupportingRefs: []SubjectRef{{Type: "artifact", ID: "art_1", Digest: "sha256:abc"}}, ReviewedAt: &reviewedAt, SchemaVersion: VulnerabilityDecisionVersion, CreatedAt: now},
			roundTrip: func() (any, error) {
				legacy := VulnerabilityDecision{ID: "vud_1", TenantID: "ten_1", FindingID: "finding_1", ScanID: "scan_1", Vulnerability: "CVE-1", Status: "affected", Justification: "reachable", EvidenceIDs: []string{"evi_1"}, SupportingRefs: []SubjectRef{{Type: "artifact", ID: "art_1", Digest: "sha256:abc"}}, ReviewedAt: &reviewedAt, SchemaVersion: VulnerabilityDecisionVersion, CreatedAt: now}
				model, err := VulnerabilityDecisionToContextModel(legacy)
				return VulnerabilityDecisionFromContextModel(model), err
			},
		},
		{
			name:   "bundle",
			legacy: ReleaseBundle{ID: "bun_1", TenantID: "ten_1", ReleaseID: "rel_1", State: "generated", Manifest: map[string]any{"release_id": "rel_1", "members": []any{"evi_1"}}, ManifestHash: "sha256:manifest", SignatureRefs: []string{"sig_1"}, CreatedAt: now},
			roundTrip: func() (any, error) {
				legacy := ReleaseBundle{ID: "bun_1", TenantID: "ten_1", ReleaseID: "rel_1", State: "generated", Manifest: map[string]any{"release_id": "rel_1", "members": []any{"evi_1"}}, ManifestHash: "sha256:manifest", SignatureRefs: []string{"sig_1"}, CreatedAt: now}
				model, err := ReleaseBundleToContextModel(legacy)
				return ReleaseBundleFromContextModel(model), err
			},
		},
		{
			name:   "verification",
			legacy: VerificationResult{ID: "ver_1", TenantID: "ten_1", SubjectType: "artifact", SubjectID: "art_1", Result: "passed", Checks: []VerifyCheck{{Name: "digest", Result: "passed"}}, Profile: VerificationProfile{ID: "profile", RequiredChecks: []string{"digest"}}, Limitations: []string{"offline"}, SchemaVersion: VerificationResultSchemaVersion, VerifiedAt: now},
			roundTrip: func() (any, error) {
				legacy := VerificationResult{ID: "ver_1", TenantID: "ten_1", SubjectType: "artifact", SubjectID: "art_1", Result: "passed", Checks: []VerifyCheck{{Name: "digest", Result: "passed"}}, Profile: VerificationProfile{ID: "profile", RequiredChecks: []string{"digest"}}, Limitations: []string{"offline"}, SchemaVersion: VerificationResultSchemaVersion, VerifiedAt: now}
				model, err := VerificationResultToContextModel(legacy)
				return VerificationResultFromContextModel(model), err
			},
		},
		{
			name:   "incident",
			legacy: Incident{ID: "inc_1", TenantID: "ten_1", ProductID: "prod_1", Title: "incident", Severity: "high", Status: "open", OpenedAt: now, SchemaVersion: IncidentSchemaVersion, CreatedAt: now},
			roundTrip: func() (any, error) {
				legacy := Incident{ID: "inc_1", TenantID: "ten_1", ProductID: "prod_1", Title: "incident", Severity: "high", Status: "open", OpenedAt: now, SchemaVersion: IncidentSchemaVersion, CreatedAt: now}
				model, err := IncidentToContextModel(legacy)
				return IncidentFromContextModel(model), err
			},
		},
		{
			name:   "collector",
			legacy: Collector{ID: "col_1", TenantID: "ten_1", Name: "collector", Type: "github_actions", Version: "1", Status: "active", AllowedScopes: []string{"evidence:write"}, SchemaVersion: CollectorSchemaVersion, CreatedAt: now},
			roundTrip: func() (any, error) {
				legacy := Collector{ID: "col_1", TenantID: "ten_1", Name: "collector", Type: "github_actions", Version: "1", Status: "active", AllowedScopes: []string{"evidence:write"}, SchemaVersion: CollectorSchemaVersion, CreatedAt: now}
				model, err := CollectorToContextModel(legacy)
				return CollectorFromContextModel(model), err
			},
		},
	}
	for _, test := range values {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.roundTrip()
			if err != nil {
				t.Fatalf("round trip: %v", err)
			}
			wantJSON, _ := json.Marshal(test.legacy)
			gotJSON, _ := json.Marshal(got)
			if !reflect.DeepEqual(gotJSON, wantJSON) {
				t.Fatalf("JSON contract changed:\n got %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestContextCompatibilityMappersRejectUnknownPersistedStates(t *testing.T) {
	if _, err := ReleaseToContextModel(Release{State: "unknown"}); err == nil {
		t.Fatal("unknown release state was accepted")
	}
	if _, err := VulnerabilityDecisionToContextModel(VulnerabilityDecision{Status: "unknown"}); err == nil {
		t.Fatal("unknown decision status was accepted")
	}
	if _, err := ReleaseBundleToContextModel(ReleaseBundle{State: "unknown"}); err == nil {
		t.Fatal("unknown bundle state was accepted")
	}
	if _, err := VerificationResultToContextModel(VerificationResult{Result: "unknown"}); err == nil {
		t.Fatal("unknown verification result was accepted")
	}
	if _, err := IncidentToContextModel(Incident{Status: "unknown"}); err == nil {
		t.Fatal("unknown incident status was accepted")
	}
	if _, err := CollectorToContextModel(Collector{Status: "unknown"}); err == nil {
		t.Fatal("unknown collector status was accepted")
	}
}

func TestContextCompatibilityMappersCopyMutableValues(t *testing.T) {
	legacy := ReleaseBundle{State: "generated", Manifest: map[string]any{"nested": []any{"original"}}, SignatureRefs: []string{"sig_1"}}
	model, err := ReleaseBundleToContextModel(legacy)
	if err != nil {
		t.Fatalf("ReleaseBundleToContextModel: %v", err)
	}
	model.Manifest["nested"].([]any)[0] = "changed"
	model.SignatureRefs[0] = "changed"
	if legacy.Manifest["nested"].([]any)[0] != "original" || legacy.SignatureRefs[0] != "sig_1" {
		t.Fatalf("mapper aliased mutable legacy values: %#v", legacy)
	}
}

func TestIdentityAndEvidenceCompatibilityMappersPreserveValues(t *testing.T) {
	actor := Actor{
		TenantID: "ten_1",
		UserID:   "usr_1",
		Scopes:   []string{"evidence:read"},
		ResourceGrants: []ResourceGrant{{
			Role: "reviewer", ResourceType: "release", ResourceID: "rel_1",
			Scopes: []string{"release:read"},
		}},
	}
	actorModel := ActorToIdentityModel(actor)
	actorRoundTrip := ActorFromIdentityModel(actorModel)
	if !reflect.DeepEqual(actorRoundTrip, actor) {
		t.Fatalf("actor round trip changed values: got %#v want %#v", actorRoundTrip, actor)
	}
	actorModel.Scopes[0] = "changed"
	actorModel.ResourceGrants[0].Scopes[0] = "changed"
	if actor.Scopes[0] != "evidence:read" || actor.ResourceGrants[0].Scopes[0] != "release:read" {
		t.Fatalf("actor mapper aliased mutable values: %#v", actor)
	}

	reference := SubjectRef{Type: "artifact", ID: "art_1", Digest: "sha256:abc"}
	referenceModel, err := SubjectRefToEvidenceModel(reference)
	if err != nil {
		t.Fatalf("SubjectRefToEvidenceModel: %v", err)
	}
	if got := SubjectRefFromEvidenceModel(referenceModel); !reflect.DeepEqual(got, reference) {
		t.Fatalf("subject reference round trip changed values: got %#v want %#v", got, reference)
	}
	if _, err := SubjectRefToEvidenceModel(SubjectRef{Type: "artifact"}); err == nil {
		t.Fatal("subject reference mapper accepted an empty identifier and digest")
	}
}
