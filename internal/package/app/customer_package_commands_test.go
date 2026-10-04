package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type customerCreationFake struct {
	view                                                       CustomerPackageCreationSnapshot
	packages                                                   []packagedomain.CustomerSecurityPackage
	audit                                                      []application.AuditEvent
	reads, executions, profileReads, hashes, ids               int
	readErr, insertErr, auditErr, commitErr, guardErr, hashErr error
	beforeExecute                                              func()
	beforeAudit                                                func()
	hashed                                                     map[string]any
	clock                                                      time.Time
}

type customerCreationAuthorizerFunc func(context.Context, identitydomain.Actor, application.AuthorizationRequest) error

type customerChangingMetadata struct{ calls *int }

type customerTextMetadata struct{ Name string }

func (customerTextMetadata) MarshalText() ([]byte, error) { return []byte("public text"), nil }

func (m customerChangingMetadata) MarshalJSON() ([]byte, error) {
	*m.calls++
	if *m.calls == 1 {
		return []byte(`{"name":"safe"}`), nil
	}
	return []byte(`{"token":"changing-secret-marker"}`), nil
}

func (f customerCreationAuthorizerFunc) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	return f(ctx, a, r)
}

func (f *customerCreationFake) ReadCustomerPackageCreationSnapshot(_ context.Context, tenant, product, release, profile string, _ time.Time) (CustomerPackageCreationSnapshot, error) {
	f.reads++
	if tenant != "ten_1" || product != "prod_1" || release != "rel_1" || profile != "rp_1" {
		return CustomerPackageCreationSnapshot{}, ErrNotFound
	}
	return f.view, f.readErr
}
func (f *customerCreationFake) ExecuteCustomerPackageCreation(ctx context.Context, fn func(context.Context, CustomerPackageCreationTransaction) error) error {
	f.executions++
	if f.beforeExecute != nil {
		f.beforeExecute()
	}
	working := *f
	working.packages = append([]packagedomain.CustomerSecurityPackage(nil), f.packages...)
	working.audit = append([]application.AuditEvent(nil), f.audit...)
	if err := fn(ctx, &working); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.commitErr != nil {
		return f.commitErr
	}
	f.packages, f.audit, f.profileReads = working.packages, working.audit, working.profileReads
	return nil
}
func (f *customerCreationFake) GetRedactionProfile(_ context.Context, tenant, id string) (packagedomain.RedactionProfile, error) {
	f.profileReads++
	if f.view.Profile.TenantID != tenant || f.view.Profile.ID != id {
		return packagedomain.RedactionProfile{}, ErrNotFound
	}
	return f.view.Profile, nil
}
func (f *customerCreationFake) Authorize(_ context.Context, _ identitydomain.Actor, _ application.AuthorizationRequest) error {
	return f.guardErr
}
func (f *customerCreationFake) InsertCustomerSecurityPackage(_ context.Context, v packagedomain.CustomerSecurityPackage) error {
	if f.insertErr != nil {
		return f.insertErr
	}
	f.packages = append(f.packages, v)
	return nil
}
func (f *customerCreationFake) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.beforeAudit != nil {
		f.beforeAudit()
	}
	if f.auditErr != nil {
		return application.AuditReceipt{}, f.auditErr
	}
	f.audit = append(f.audit, v)
	return application.AuditReceipt{ID: v.ID}, nil
}
func (f *customerCreationFake) HashPackageManifest(_ context.Context, v map[string]any) (string, error) {
	f.hashes++
	f.hashed = cloneMap(v)
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), f.hashErr
}
func customerCreationFixture(t *testing.T) (*CustomerPackageCommands, *customerCreationFake, CreateCustomerPackageInput) {
	t.Helper()
	f := &customerCreationFake{clock: packageTestNow()}
	f.view = CustomerPackageCreationSnapshot{
		Profile: packagedomain.RedactionProfile{ID: "rp_1", TenantID: "ten_1", Name: "customer", AllowedTypes: []string{"sbom", "vulnerability_decision"}, ExcludedFields: []string{"internal_comment"}, SchemaVersion: packagedomain.RedactionProfileSchemaVersion},
		Snapshot: PackageSnapshot{SnapshotVersion: "snapshot.v1", TenantID: "ten_1", ProductID: "prod_1", ReleaseID: "rel_1", Tenant: map[string]any{"id": "ten_1", "token": "hidden"}, Product: map[string]any{"id": "prod_1"}, Release: map[string]any{"id": "rel_1"},
			Evidence:  []EvidenceReference{{ID: "ev_2", Type: "sbom"}, {ID: "ev_private", Type: "private"}, {ID: "ev_1", Type: "sbom"}},
			SBOMs:     []map[string]any{{"id": "sbom_1", "nested": map[string]any{"private_key": "hidden", "internal_comment": "hidden", "name": "safe"}}},
			Decisions: []map[string]any{{"id": "decision_1", "status": "fixed", "internal_notes": "hidden"}}, VulnerabilityScans: []map[string]any{{"id": "scan_private"}},
			ReadinessChecks: []packagedomain.PolicyCheckSnapshot{{Name: "requires_sbom", Result: "passed"}}, VerificationMaterial: map[string]any{"hash_algorithm": "sha256"}},
	}
	s, err := NewCustomerPackageCommands(CustomerPackageCommandConfig{Reader: f, Transactions: f, Authorizer: customerCreationAuthorizerFunc(func(context.Context, identitydomain.Actor, application.AuthorizationRequest) error { return nil }), Hasher: f, Clock: application.ClockFunc(func() time.Time { return f.clock }), IDs: application.IDGeneratorFunc(func(prefix string) string { f.ids++; return prefix + "_generated" })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, CreateCustomerPackageInput{ProductID: "prod_1", ReleaseID: "rel_1", RedactionProfileID: "rp_1", Title: "Review", ExpiresAt: f.clock.Add(time.Hour)}
}

func TestFocusedCustomerCreationUsesOneSnapshotAndHashesFinalRedactedManifest(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	pkg, err := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
	if err != nil {
		t.Fatal(err)
	}
	if f.reads != 1 || f.executions != 1 || f.hashes != 1 || len(f.packages) != 1 || len(f.audit) != 1 {
		t.Fatalf("effects: reads=%d transactions=%d hashes=%d packages=%d audit=%d", f.reads, f.executions, f.hashes, len(f.packages), len(f.audit))
	}
	if !reflect.DeepEqual(pkg.Manifest, f.hashed) || !reflect.DeepEqual(pkg.Manifest["evidence_ids"], []string{"ev_1", "ev_2"}) {
		t.Fatalf("final manifest not hashed: %#v", pkg.Manifest)
	}
	if _, ok := pkg.Manifest["vulnerability_scans"]; ok {
		t.Fatal("disallowed section exposed")
	}
	assertNoSensitivePackageKeys(t, pkg.Manifest)
	if strings.Contains(string(mustCustomerJSON(t, pkg.Manifest)), "hidden") {
		t.Fatal("excluded nested metadata exposed")
	}
	if f.audit[0].PayloadHash != pkg.ManifestHash || f.audit[0].SubjectID != pkg.ID || f.audit[0].EntryType != "customer_package.generated" || f.audit[0].ActorType != "human_user" {
		t.Fatalf("audit=%#v", f.audit)
	}
	pkg.Manifest["product"].(map[string]any)["id"] = "mutated"
	if f.packages[0].Manifest["product"].(map[string]any)["id"] != "prod_1" || f.view.Snapshot.Product["id"] != "prod_1" {
		t.Fatal("result aliases persisted or snapshot data")
	}
	f.view.Profile.AllowedTypes[0] = "mutated"
	if f.packages[0].Manifest["redaction_profile"].(map[string]any)["allowed_types"].([]string)[0] == "mutated" {
		t.Fatal("manifest aliases profile")
	}
}
func mustCustomerJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func TestFocusedCustomerCreationRejectsBeforePrivateSnapshotRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*CustomerPackageCommands, *customerCreationFake, *CreateCustomerPackageInput)
		want   error
	}{
		{"scope denied", func(s *CustomerPackageCommands, _ *customerCreationFake, _ *CreateCustomerPackageInput) {
			s.config.Authorizer = customerCreationAuthorizerFunc(func(context.Context, identitydomain.Actor, application.AuthorizationRequest) error {
				return ErrForbidden
			})
		}, ErrForbidden},
		{"resource denied", func(s *CustomerPackageCommands, _ *customerCreationFake, _ *CreateCustomerPackageInput) {
			s.config.Authorizer = customerCreationAuthorizerFunc(func(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
				if !r.ScopeOnly {
					return ErrForbidden
				}
				return nil
			})
		}, ErrForbidden},
		{"raw overlong product", func(_ *CustomerPackageCommands, _ *customerCreationFake, in *CreateCustomerPackageInput) {
			in.ProductID = strings.Repeat(" ", MaxCustomerPackageIDBytes) + "prod_1"
		}, ErrValidation},
		{"overlong title", func(_ *CustomerPackageCommands, _ *customerCreationFake, in *CreateCustomerPackageInput) {
			in.Title = strings.Repeat("x", MaxCustomerPackageTitleBytes+1)
		}, ErrValidation},
		{"invalid UTF8", func(_ *CustomerPackageCommands, _ *customerCreationFake, in *CreateCustomerPackageInput) {
			in.Title = string([]byte{0xff})
		}, ErrValidation},
		{"NUL identifier", func(_ *CustomerPackageCommands, _ *customerCreationFake, in *CreateCustomerPackageInput) {
			in.RedactionProfileID = "rp_1\x00"
		}, ErrValidation},
		{"blank title", func(_ *CustomerPackageCommands, _ *customerCreationFake, in *CreateCustomerPackageInput) {
			in.Title = " "
		}, ErrValidation},
		{"expired", func(_ *CustomerPackageCommands, f *customerCreationFake, in *CreateCustomerPackageInput) {
			in.ExpiresAt = f.clock
		}, ErrValidation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, in := customerCreationFixture(t)
			tc.change(s, f, &in)
			v, e := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
			if !errors.Is(e, tc.want) || v.ID != "" || f.reads != 0 || f.executions != 0 || f.ids != 0 {
				t.Fatalf("result=%#v err=%v reads=%d transactions=%d ids=%d", v, e, f.reads, f.executions, f.ids)
			}
		})
	}
}

func TestFocusedCustomerCreationRejectsIncompleteOrOversizedReadViews(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*customerCreationFake)
		want   error
	}{
		{"wrong tenant", func(f *customerCreationFake) { f.view.Snapshot.TenantID = "foreign" }, ErrConflict},
		{"wrong product", func(f *customerCreationFake) { f.view.Snapshot.Product["id"] = "foreign" }, ErrConflict},
		{"wrong release", func(f *customerCreationFake) { f.view.Snapshot.Release["id"] = "foreign" }, ErrConflict},
		{"missing version", func(f *customerCreationFake) { f.view.Snapshot.SnapshotVersion = "" }, ErrConflict},
		{"foreign profile", func(f *customerCreationFake) { f.view.Profile.TenantID = "foreign" }, ErrNotFound},
		{"too many evidence rows", func(f *customerCreationFake) {
			f.view.Snapshot.Evidence = make([]EvidenceReference, MaxSecurityReviewEvidenceIDs+1)
		}, ErrConflict},
		{"oversized snapshot", func(f *customerCreationFake) {
			f.view.Snapshot.Product["name"] = strings.Repeat("x", MaxCustomerPackageManifestBytes+1)
		}, ErrConflict},
		{"invalid snapshot JSON", func(f *customerCreationFake) { f.view.Snapshot.Product["invalid"] = make(chan int) }, ErrConflict},
		{"deep snapshot", func(f *customerCreationFake) {
			var nested any = "leaf"
			for i := 0; i < 40; i++ {
				nested = map[string]any{"child": nested}
			}
			f.view.Snapshot.Product["nested"] = nested
		}, ErrConflict},
		{"cyclic snapshot", func(f *customerCreationFake) { f.view.Snapshot.Product["cycle"] = f.view.Snapshot.Product }, ErrConflict},
		{"too many nested rows", func(f *customerCreationFake) {
			f.view.Snapshot.SBOMs = make([]map[string]any, MaxSecurityReviewEvidenceIDs+1)
		}, ErrConflict},
		{"reader failure", func(f *customerCreationFake) { f.readErr = errPackageTestFailure }, errPackageTestFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, in := customerCreationFixture(t)
			tc.change(f)
			v, e := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
			if !errors.Is(e, tc.want) || v.ID != "" || f.executions != 0 || f.hashes != 0 || f.ids != 0 {
				t.Fatalf("result ID=%q err=%v transactions=%d hashes=%d ids=%d", v.ID, e, f.executions, f.hashes, f.ids)
			}
		})
	}
}

func TestFocusedCustomerCreationRollsBackEveryWriteFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*customerCreationFake)
		want   error
	}{
		{"insert", func(f *customerCreationFake) { f.insertErr = errPackageTestFailure }, errPackageTestFailure},
		{"audit", func(f *customerCreationFake) { f.auditErr = errPackageTestFailure }, errPackageTestFailure},
		{"commit", func(f *customerCreationFake) { f.commitErr = errPackageTestFailure }, errPackageTestFailure},
		{"authority changed", func(f *customerCreationFake) { f.guardErr = ErrForbidden }, ErrForbidden},
		{"profile changed", func(f *customerCreationFake) {
			f.beforeExecute = func() { f.view.Profile.ExcludedFields = append(f.view.Profile.ExcludedFields, "title") }
		}, ErrConflict},
		{"expired during lock wait", func(f *customerCreationFake) { f.beforeExecute = func() { f.clock = f.clock.Add(2 * time.Hour) } }, ErrValidation},
		{"hash", func(f *customerCreationFake) { f.hashErr = errPackageTestFailure }, errPackageTestFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, in := customerCreationFixture(t)
			tc.change(f)
			v, e := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
			if !errors.Is(e, tc.want) || v.ID != "" || len(f.packages) != 0 || len(f.audit) != 0 {
				t.Fatalf("result=%#v err=%v packages=%#v audit=%#v", v, e, f.packages, f.audit)
			}
		})
	}
}

func TestFocusedCustomerCreationReplayGuardDoesNotRegenerateOrRejectExpiredOriginal(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	in.ExpiresAt = f.clock.Add(-time.Hour)
	if e := s.AuthorizeCreateCustomerSecurityPackage(t.Context(), packageTestActor(), in); e != nil {
		t.Fatal(e)
	}
	if f.executions != 1 || f.reads != 0 || f.hashes != 0 || f.ids != 0 || len(f.packages) != 0 || len(f.audit) != 0 {
		t.Fatalf("replay guard generated effects: %#v", f)
	}
	f.guardErr = ErrForbidden
	if e := s.AuthorizeCreateCustomerSecurityPackage(t.Context(), packageTestActor(), in); !errors.Is(e, ErrForbidden) {
		t.Fatalf("revoked authority: %v", e)
	}
}

func TestFocusedCustomerCreationCancellationCannotPublishEffects(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	f.beforeAudit = cancel
	v, e := s.CreateCustomerSecurityPackage(ctx, packageTestActor(), in)
	if !errors.Is(e, context.Canceled) || v.ID != "" || len(f.packages) != 0 || len(f.audit) != 0 {
		t.Fatalf("result=%#v err=%v effects=%#v/%#v", v, e, f.packages, f.audit)
	}
	s, f, in = customerCreationFixture(t)
	if _, e = s.CreateCustomerSecurityPackage(ctx, packageTestActor(), in); !errors.Is(e, context.Canceled) || f.reads != 0 || f.executions != 0 {
		t.Fatalf("canceled command err=%v reads=%d transactions=%d", e, f.reads, f.executions)
	}
}

func TestFocusedCustomerCreationPolicyCASComparesTimestampInstantsAndEmptyLists(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	f.view.Profile.CreatedAt = packageTestNow()
	f.view.Profile.ExcludedFields = nil
	f.beforeExecute = func() {
		f.view.Profile.CreatedAt = f.view.Profile.CreatedAt.In(time.FixedZone("fixture", 2*60*60))
		f.view.Profile.ExcludedFields = []string{}
	}
	v, err := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
	if err != nil || v.ID == "" || len(f.packages) != 1 || len(f.audit) != 1 {
		t.Fatal("equivalent policy rejected", err)
	}
}

func TestFocusedCustomerCreationRedactsTypedJSONWithoutLosingIntegerPrecision(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	f.view.Snapshot.Product["typed_map"] = map[string]string{"token": "typed-secret-marker", "name": "safe"}
	f.view.Snapshot.Product["typed_rows"] = []map[string]string{{"secret": "typed-secret-marker", "name": "safe"}}
	f.view.Snapshot.Product["typed_struct"] = struct {
		Token string `json:"token"`
		Size  int64  `json:"size"`
	}{"typed-secret-marker", 4611686018427387907}
	v, err := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(mustCustomerJSON(t, v.Manifest))
	if strings.Contains(raw, "typed-secret-marker") || !strings.Contains(raw, "4611686018427387907") {
		t.Fatal("typed metadata bypassed redaction or lost integer precision")
	}
	f.view.Snapshot.Product["typed_map"].(map[string]string)["name"] = "mutated"
	if strings.Contains(string(mustCustomerJSON(t, v.Manifest)), "mutated") {
		t.Fatal("manifest aliases typed snapshot data")
	}
}

func TestFocusedCustomerCreationPreservesEstablishedManifestCollectionShapes(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	type publicProfile struct {
		ID             string
		RequiredChecks []string
	}
	f.view.Snapshot.VerificationMaterial["verification_results"] = []map[string]any{{"id": "verification", "checks": []map[string]any{{"name": "check", "result": "passed"}}, "profile": map[string]any{"required_checks": []string{"check"}}}}
	f.view.Snapshot.VerificationMaterial["verification_results"].([]map[string]any)[0]["public_profile"] = publicProfile{ID: "profile", RequiredChecks: []string{"check"}}
	f.view.Snapshot.VulnerabilityScans = []map[string]any{{"summary": map[string]int{"high": 2}}}
	f.view.Profile.AllowedTypes = append(f.view.Profile.AllowedTypes, "vulnerability_scan")
	v, err := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
	if err != nil {
		t.Fatal(err)
	}
	results, ok := v.Manifest["verification_material"].(map[string]any)["verification_results"].([]map[string]any)
	if !ok || len(results) != 1 {
		t.Fatalf("verification result shape=%T", v.Manifest["verification_material"].(map[string]any)["verification_results"])
	}
	if _, ok := results[0]["checks"].([]map[string]any); !ok {
		t.Fatal("verification checks shape changed")
	}
	if _, ok := results[0]["profile"].(map[string]any)["required_checks"].([]string); !ok {
		t.Fatal("profile list shape changed")
	}
	scans := v.Manifest["vulnerability_scans"].([]map[string]any)
	if _, ok := scans[0]["summary"].(map[string]int); !ok {
		t.Fatal("scan summary shape changed")
	}
	results[0]["checks"].([]map[string]any)[0]["result"] = "changed"
	if f.packages[0].Manifest["verification_material"].(map[string]any)["verification_results"].([]map[string]any)[0]["checks"].([]map[string]any)[0]["result"] != "passed" {
		t.Fatal("restored collections alias stored record")
	}
	profile, ok := results[0]["public_profile"].(publicProfile)
	if !ok || profile.ID != "profile" {
		t.Fatal("public value struct shape changed")
	}
	profile.RequiredChecks[0] = "mutated"
	stored := f.packages[0].Manifest["verification_material"].(map[string]any)["verification_results"].([]map[string]any)[0]["public_profile"].(publicProfile)
	if stored.RequiredChecks[0] != "check" {
		t.Fatal("public profile slice aliases stored record")
	}
}

func TestFocusedCustomerCreationDoesNotRetainHiddenOrCustomMetadata(t *testing.T) {
	s, f, in := customerCreationFixture(t)
	calls := 0
	f.view.Snapshot.Product["custom"] = customerChangingMetadata{calls: &calls}
	f.view.Snapshot.Product["custom_text"] = customerTextMetadata{Name: "hidden Go field"}
	f.view.Snapshot.Product["hidden"] = struct {
		Name   string
		Secret string `json:"-"`
	}{"safe", "hidden-secret-marker"}
	v, err := s.CreateCustomerSecurityPackage(t.Context(), packageTestActor(), in)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("custom metadata marshaler retained after normalization", calls)
	}
	product := v.Manifest["product"].(map[string]any)
	if text, ok := product["custom_text"].(string); !ok || text != "public text" {
		t.Fatal("custom text encoder retained after JSON normalization")
	}
	if _, ok := product["hidden"].(map[string]any); !ok {
		t.Fatal("nonserialized hidden fields retained in public record")
	}
	if strings.Contains(string(mustCustomerJSON(t, v.Manifest)), "secret-marker") {
		t.Fatal("custom or hidden metadata leaked")
	}
}
