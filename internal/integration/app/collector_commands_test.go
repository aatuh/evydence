package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

type collectorCommandFixture struct {
	collector                 integrationdomain.Collector
	keys                      []identitydomain.APIKey
	releases                  []integrationdomain.CollectorRelease
	commercial                []integrationdomain.CommercialCollectorDefinition
	audits                    []application.AuditEvent
	refs                      map[string]CollectorReference
	fail                      string
	transactions, generations int
	duplicate                 bool
}

func (f *collectorCommandFixture) ExecuteCollector(ctx context.Context, fn func(context.Context, CollectorTransaction) error) error {
	f.transactions++
	tx := *f
	tx.releases = append([]integrationdomain.CollectorRelease(nil), f.releases...)
	if err := fn(ctx, &tx); err != nil {
		return err
	}
	if f.fail == "commit" {
		return ErrConflict
	}
	f.collector, f.keys, f.releases, f.commercial, f.audits = tx.collector, tx.keys, tx.releases, tx.commercial, tx.audits
	return nil
}
func (f *collectorCommandFixture) GenerateCollectorCredential(context.Context) (CollectorCredential, error) {
	f.generations++
	if f.fail == "credential" {
		return CollectorCredential{}, ErrConflict
	}
	return CollectorCredential{Secret: "evy_fake_one_time_secret", Prefix: "evy_fake_one", Hash: strings.Repeat("a", 64)}, nil
}
func (f *collectorCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.fail == "auth" {
		return application.ErrForbidden
	}
	return NewCollectorWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *collectorCommandFixture) LockCollectorWrites(_ context.Context, tenant string) error {
	if f.fail == "lock" {
		return ErrConflict
	}
	if tenant != "tenant" {
		return ErrNotFound
	}
	return nil
}
func (f *collectorCommandFixture) CollectorNameExists(context.Context, string, string) (bool, error) {
	return f.duplicate, nil
}
func (f *collectorCommandFixture) CommercialCollectorIdentityExists(context.Context, string, string, string, string) (bool, error) {
	return f.duplicate, nil
}
func (f *collectorCommandFixture) ReadCollectorReleaseReference(_ context.Context, tenant, kind, id string) (CollectorReference, error) {
	if f.fail == "read" {
		return CollectorReference{}, ErrConflict
	}
	v, ok := f.refs[kind+":"+id]
	if !ok || v.TenantID != tenant {
		return CollectorReference{}, ErrNotFound
	}
	return v, nil
}
func (f *collectorCommandFixture) InsertCollector(_ context.Context, v integrationdomain.Collector) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.collector = v
	return nil
}
func (f *collectorCommandFixture) InsertCollectorAPIKey(_ context.Context, v identitydomain.APIKey) error {
	if f.fail == "key" {
		return ErrConflict
	}
	f.keys = append(f.keys, v)
	return nil
}
func (f *collectorCommandFixture) InsertCollectorRelease(_ context.Context, v integrationdomain.CollectorRelease) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	if v.Pinned {
		for i := range f.releases {
			f.releases[i].Pinned = false
		}
	}
	f.releases = append(f.releases, v)
	return nil
}
func (f *collectorCommandFixture) InsertCommercialCollectorDefinition(_ context.Context, v integrationdomain.CommercialCollectorDefinition) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.commercial = append(f.commercial, v)
	return nil
}
func (f *collectorCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, ErrConflict
	}
	f.audits = append(f.audits, v)
	return application.AuditReceipt{}, nil
}
func collectorFixture(t *testing.T) (*CollectorCommands, *collectorCommandFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 3, 12, 20, 30, 123456789, time.FixedZone("offset", 3600))
	f := &collectorCommandFixture{refs: map[string]CollectorReference{}}
	for _, kind := range []string{"collector", "signature", "sbom", "scan"} {
		digest := ""
		if kind == "signature" {
			digest = "sha256:" + strings.Repeat("a", 64)
		}
		f.refs[kind+":"+kind] = CollectorReference{ID: kind, TenantID: "tenant", Type: kind, Digest: digest}
	}
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"collector:admin"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"collector:admin"}}}}
	c, err := NewCollectorCommands(CollectorCommandConfig{Transactions: f, Credentials: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, a, now.UTC().Truncate(time.Microsecond)
}
func TestCollectorCommandsKeepCredentialPrivateAndDefaultsAtomic(t *testing.T) {
	c, f, a, now := collectorFixture(t)
	in := CreateCollectorInput{Name: " Builder ", Type: " generic_ci ", Version: " 1 "}
	if err := c.AuthorizeCreateCollector(t.Context(), a, in); err != nil || f.generations != 0 || len(f.audits) != 0 {
		t.Fatal("guard generated credentials or wrote", err)
	}
	v, key, secret, err := c.CreateCollector(t.Context(), a, in)
	if err != nil || v.ID != "col_new" || v.Name != "Builder" || v.Version != "1" || v.Type != "generic_ci" || v.Status.String() != "active" || v.APIKeyID != key.ID || v.CreatedAt != now || v.SchemaVersion != integrationdomain.CollectorSchemaVersion || secret != "evy_fake_one_time_secret" || key.Hash != "" || key.Name != "collector:Builder" || key.CreatedAt != now || len(f.keys) != 1 || f.keys[0].Hash == "" || !reflect.DeepEqual(v.AllowedScopes, []string{"build:write", "evidence:write"}) || !reflect.DeepEqual(v.AllowedScopes, key.Scopes) || len(f.audits) != 1 {
		t.Fatal("collector creation contract changed", err)
	}
	key.Scopes[0] = "admin"
	v.AllowedScopes[0] = "admin"
	if f.keys[0].Scopes[0] != "build:write" || f.collector.AllowedScopes[0] != "build:write" {
		t.Fatal("returned scopes alias persisted authority")
	}
	if f.audits[0].ActorType != "human_user" || f.audits[0].ActorID != "human" || f.audits[0].EntryType != "collector.created" || f.audits[0].SubjectID != "col_new" || f.audits[0].PayloadHash != "" {
		t.Fatal(f.audits)
	}
}
func TestCollectorCommandsPreserveReleaseHealthPinAndCommercialMetadata(t *testing.T) {
	c, f, a, now := collectorFixture(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	f.releases = []integrationdomain.CollectorRelease{{ID: "old", Pinned: true}}
	in := RecordCollectorReleaseInput{CollectorID: " collector ", Version: " 2 ", ArtifactDigest: " " + digest + " ", SignatureID: " signature ", SBOMID: " sbom ", ScanID: " scan ", Pinned: true}
	if err := c.AuthorizeRecordCollectorRelease(t.Context(), a, in); err != nil || len(f.releases) != 1 {
		t.Fatal(err)
	}
	v, err := c.RecordCollectorRelease(t.Context(), a, in)
	if err != nil || v.CollectorID != "collector" || v.Version != "2" || v.ArtifactDigest != digest || v.VerificationStatus != "evidence_complete" || v.HealthStatus != "healthy" || !v.Pinned || v.CreatedAt != now || v.SchemaVersion != integrationdomain.CollectorReleaseSchemaVersion || len(v.Limitations) != 1 || len(f.releases) != 2 || f.releases[0].Pinned {
		t.Fatal(v, err)
	}
	v.Limitations[0] = "changed"
	if f.releases[1].Limitations[0] == "changed" {
		t.Fatal("limitations alias persisted release")
	}
	scopes := []string{" evidence:write ", "build:read"}
	commercial := CreateCommercialCollectorInput{Name: " Scanner ", Provider: " Provider ", Version: " 1 ", ManifestHash: digest, AllowedScopes: scopes}
	if err := c.AuthorizeCreateCommercialCollectorDefinition(t.Context(), a, commercial); err != nil {
		t.Fatal(err)
	}
	d, err := c.CreateCommercialCollectorDefinition(t.Context(), a, commercial)
	if err != nil || d.Name != "Scanner" || d.Provider != "Provider" || d.Version != "1" || d.Status != "available" || d.CreatedAt != now || d.SchemaVersion != integrationdomain.CommercialCollectorVersion || len(f.commercial) != 1 || len(f.audits) != 2 || !reflect.DeepEqual(d.AllowedScopes, []string{"build:read", "evidence:write"}) {
		t.Fatal(d, err)
	}
	scopes[0] = "admin"
	d.AllowedScopes[0] = "admin"
	if f.commercial[0].AllowedScopes[0] != "build:read" {
		t.Fatal("commercial scopes alias input/output")
	}
}
func TestCollectorCommandsRejectForeignReferencesTenantGrantsAndRollback(t *testing.T) {
	for _, kind := range []string{"collector", "signature", "sbom", "scan"} {
		c, f, a, _ := collectorFixture(t)
		v := f.refs[kind+":"+kind]
		v.TenantID = "other"
		f.refs[kind+":"+kind] = v
		if _, err := c.RecordCollectorRelease(t.Context(), a, RecordCollectorReleaseInput{CollectorID: "collector", Version: "1", ArtifactDigest: "sha256:" + strings.Repeat("a", 64), SignatureID: "signature", SBOMID: "sbom", ScanID: "scan"}); !errors.Is(err, ErrNotFound) || len(f.audits) != 0 {
			t.Fatal(kind, err)
		}
	}
	for _, command := range []string{"create", "release", "commercial"} {
		for _, fail := range []string{"auth", "lock", "insert", "audit", "commit", "credential", "key", "duplicate"} {
			if (fail == "credential" || fail == "key") && command != "create" || fail == "duplicate" && command == "release" {
				continue
			}
			t.Run(command+"/"+fail, func(t *testing.T) {
				c, f, a, _ := collectorFixture(t)
				f.fail = fail
				f.duplicate = fail == "duplicate"
				var err error
				digest := "sha256:" + strings.Repeat("a", 64)
				switch command {
				case "create":
					_, _, secret, e := c.CreateCollector(t.Context(), a, CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1"})
					err = e
					if secret != "" {
						t.Fatal("failed command exposed a secret")
					}
				case "release":
					_, err = c.RecordCollectorRelease(t.Context(), a, RecordCollectorReleaseInput{CollectorID: "collector", Version: "1", ArtifactDigest: digest})
				case "commercial":
					_, err = c.CreateCommercialCollectorDefinition(t.Context(), a, CreateCommercialCollectorInput{Name: "Scanner", Provider: "provider", Version: "1", ManifestHash: digest, AllowedScopes: []string{"evidence:write"}})
				}
				if err == nil || f.collector.ID != "" || len(f.keys)+len(f.releases)+len(f.commercial)+len(f.audits) != 0 {
					t.Fatal("failure leaked effects", err)
				}
			})
		}
	}
	c, f, a, _ := collectorFixture(t)
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"collector:admin"}}}
	if _, _, _, err := c.CreateCollector(t.Context(), a, CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1"}); !errors.Is(err, application.ErrForbidden) || f.transactions != 0 {
		t.Fatal("project grant issued tenant credential", err)
	}
	a.KeyID = "credential"
	if _, _, _, err := c.CreateCollector(t.Context(), a, CreateCollectorInput{Name: "Builder", Type: "generic_ci", Version: "1"}); err != nil {
		t.Fatal("issued credential lost scope authority", err)
	}
}
func TestCollectorCommandsRejectInvalidInputBeforeStorage(t *testing.T) {
	for _, in := range []CreateCollectorInput{{Name: " ", Type: "generic_ci", Version: "1"}, {Name: "Builder", Type: "unknown", Version: "1"}, {Name: "Builder", Type: "generic_ci", Version: "1", Scopes: []string{"admin"}}, {Name: "Builder", Type: "generic_ci", Version: "1", Scopes: []string{""}}, {Name: "bad\x00", Type: "generic_ci", Version: "1"}, {Name: strings.Repeat("x", 2305), Type: "generic_ci", Version: "1"}, {Name: "Builder", Type: "generic_ci", Version: "\xff"}} {
		c, f, a, _ := collectorFixture(t)
		if _, _, _, err := c.CreateCollector(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions+f.generations != 0 {
			t.Fatal(in, err)
		}
	}
	c, f, a, _ := collectorFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, _, err := c.CreateCollector(ctx, a, CreateCollectorInput{}); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
	if _, err := NewCollectorCommands(CollectorCommandConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
}

func TestCollectorDigestRejectsOversizedInputWithoutAllocation(t *testing.T) {
	oversized := "sha256:" + strings.Repeat("a", 2*1024*1024)
	if allocations := testing.AllocsPerRun(5, func() {
		if collectorDigest(oversized) {
			t.Fatal("oversized digest accepted")
		}
	}); allocations != 0 {
		t.Fatal("oversized digest allocated before its size was rejected", allocations)
	}
	for _, v := range []string{"sha256:" + strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64)} {
		if !collectorDigest(v) {
			t.Fatal("compatible SHA-256 digest rejected")
		}
	}
}

func TestCollectorCommandsRejectReleaseAndCommercialBudgetsBeforeStorage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []string{"collector-id", "signature-id", "sbom-id", "scan-id", "version", "digest", "nul", "utf8"} {
		c, f, a, _ := collectorFixture(t)
		in := RecordCollectorReleaseInput{CollectorID: "collector", Version: "1", ArtifactDigest: digest}
		switch tc {
		case "collector-id":
			in.CollectorID = strings.Repeat("x", 1025)
		case "signature-id":
			in.SignatureID = strings.Repeat("x", 1025)
		case "sbom-id":
			in.SBOMID = strings.Repeat("x", 1025)
		case "scan-id":
			in.ScanID = strings.Repeat("x", 1025)
		case "version":
			in.Version = strings.Repeat("x", MaxSourceTextBytes+1)
		case "digest":
			in.ArtifactDigest = "sha256:" + strings.Repeat("a", 65)
		case "nul":
			in.Version = "bad\x00"
		case "utf8":
			in.ScanID = "\xff"
		}
		if v, err := c.RecordCollectorRelease(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions != 0 {
			t.Fatal("invalid release reached storage", tc, err)
		}
	}
	for _, tc := range []string{"name", "provider", "version", "digest", "empty-scopes", "many-scopes", "large-scope", "bad-scope", "nul", "utf8"} {
		c, f, a, _ := collectorFixture(t)
		in := CreateCommercialCollectorInput{Name: "Scanner", Provider: "provider", Version: "1", ManifestHash: digest, AllowedScopes: []string{"evidence:write"}}
		switch tc {
		case "name":
			in.Name = strings.Repeat("x", MaxCollectorKeyBytes)
		case "provider":
			in.Provider = strings.Repeat("x", MaxCollectorKeyBytes)
		case "version":
			in.Version = strings.Repeat("x", MaxCollectorKeyBytes)
		case "digest":
			in.ManifestHash = " " + digest
		case "empty-scopes":
			in.AllowedScopes = nil
		case "many-scopes":
			in.AllowedScopes = make([]string, 1025)
		case "large-scope":
			in.AllowedScopes = []string{strings.Repeat(" ", 129) + "evidence:write"}
		case "bad-scope":
			in.AllowedScopes = []string{"collector:admin"}
		case "nul":
			in.Provider = "bad\x00"
		case "utf8":
			in.Name = "\xff"
		}
		if v, err := c.CreateCommercialCollectorDefinition(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || f.transactions != 0 {
			t.Fatal("invalid commercial definition reached storage", tc, err)
		}
	}
}
