package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

type securityDocumentFixtureRunner struct {
	base *fakeEvidenceTransactions
	fail string
}

func (r securityDocumentFixtureRunner) ExecuteSecurityDocument(ctx context.Context, fn func(context.Context, SecurityDocumentTransaction) error) error {
	return r.base.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		return fn(ctx, securityDocumentFixtureTx{failingCreationTransaction{evidenceCreationTransaction{tx}, r.fail}, tx.Ingestion()})
	})
}

type securityDocumentFixtureTx struct {
	EvidenceCreationTransaction
	ingestion IngestionRepository
}

type absentSecurityDocumentObjects struct{ ObjectIngestion }

func (absentSecurityDocumentObjects) StagePayload(context.Context, string, string, string, []byte) (StagedPayload, error) {
	return StagedPayload{}, nil
}

func (t securityDocumentFixtureTx) InsertSecurityScan(ctx context.Context, v evidencedomain.SecurityScan) error {
	return t.ingestion.InsertSecurityScan(ctx, v)
}
func (t securityDocumentFixtureTx) InsertManualSecurityDocument(ctx context.Context, v evidencedomain.ManualSecurityDocument) error {
	return t.ingestion.InsertManualSecurityDocument(ctx, v)
}
func newSecurityDocumentFixture(t *testing.T) (*SecurityDocumentCommands, *evidenceServiceFixture) {
	t.Helper()
	f := newEvidenceServiceFixture(t)
	f.reader.artifacts["artifact"] = f.actor.TenantID
	f.transactions.state.artifactTenants["artifact"] = f.actor.TenantID
	c, err := NewSecurityDocumentCommands(SecurityDocumentCommandConfig{Authorizer: f.authorizer, Transactions: securityDocumentFixtureRunner{base: f.transactions}, Objects: f.objects, Canonicalizer: f.canonicalizer, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: f.service.clock, IDs: f.service.ids})
	if err != nil {
		t.Fatal(err)
	}
	return c, f
}

func TestSecurityDocumentCommandsPreserveMetadataAtomicityAndReplayGuards(t *testing.T) {
	for _, kind := range []string{"scan", "api", "manual", "without-object"} {
		t.Run(kind, func(t *testing.T) {
			c, f := newSecurityDocumentFixture(t)
			f.actor.KeyID, f.actor.UserID = "", "human"
			if kind == "without-object" {
				c.config.Objects = absentSecurityDocumentObjects{f.objects}
			}
			in := UploadSecurityScanInput{ProductID: " prod_1 ", ReleaseID: " rel_1 ", ArtifactID: " artifact ", Category: " secret_scan ", Scanner: " scanner ", TargetRef: " target ", Raw: []byte(`{"findings":[{"severity":"critical"},{"severity":""}]}`)}
			manual := UploadManualSecurityDocumentInput{ProductID: " prod_1 ", ReleaseID: " rel_1 ", DocumentType: " security_review ", Title: " Review ", Sensitivity: " restricted ", Raw: []byte("private review")}
			var id, evidence, digest string
			var err error
			if kind == "manual" {
				if err := c.AuthorizeUploadManualSecurityDocument(t.Context(), f.actor, manual); err != nil || f.objects.stageCalls != 0 {
					t.Fatal("replay staged", err)
				}
				v, e := c.UploadManualSecurityDocument(t.Context(), f.actor, manual)
				err = e
				id, evidence, digest = v.ID, v.EvidenceID, v.PayloadHash
				if v.DocumentType != "security_review" || v.Title != "Review" || v.Sensitivity != "restricted" || v.CreatedAt != f.now {
					t.Fatal(v, e)
				}
			} else {
				if kind == "api" {
					in.Category = "api_security"
				}
				if err := c.AuthorizeUploadSecurityScan(t.Context(), f.actor, in); err != nil || f.objects.stageCalls != 0 {
					t.Fatal("replay staged", err)
				}
				v, e := c.UploadSecurityScan(t.Context(), f.actor, in)
				err = e
				id, evidence, digest = v.ID, v.EvidenceID, v.PayloadHash
				if v.Format != "generic" || v.FindingCount != 2 || v.Summary["critical"] != 1 || v.Summary["unknown"] != 1 || v.CreatedAt != f.now || v.Redacted != (kind != "api") || v.Quarantined != (kind != "api") {
					t.Fatal(v, e)
				}
				v.Summary["critical"] = 9
				if f.transactions.state.securityScans[id].Summary["critical"] != 1 {
					t.Fatal("summary aliases durable state")
				}
			}
			s := f.transactions.state
			if err != nil || id == "" || len(s.evidence) != 1 || len(s.securityScans)+len(s.manualDocs) != 1 || len(s.audit) != 2 {
				t.Fatal("partial effects", id, err, s)
			}
			payloads, jobs := 1, 1
			if kind == "without-object" {
				payloads, jobs = 0, 0
			}
			if len(s.payloads) != payloads || len(s.outbox) != jobs || s.evidence[evidence].PayloadHash != digest || s.evidence[evidence].CanonicalHash != testDigest('c') {
				t.Fatal("payload/evidence effects", s)
			}
			for _, a := range s.audit {
				if a.ActorID != "human" || a.ActorType != "human_user" || a.PayloadHash != digest {
					t.Fatal("audit identity", a)
				}
			}
			for _, r := range f.authorizer.requests {
				if r.Scope != ScopeSecurityWrite {
					t.Fatal("undocumented scope", r)
				}
			}
		})
	}
}

func TestSecurityDocumentCommandsRollbackEveryWriteAndDenyBeforeStaging(t *testing.T) {
	for _, manual := range []bool{false, true} {
		for _, point := range []string{"scope", "artifact", "authorization", "stager", "payload", "outbox", "audit", "second-audit", "insert", "record", "commit"} {
			if manual && point == "artifact" {
				continue
			}
			t.Run(strings.Join([]string{map[bool]string{false: "scan", true: "manual"}[manual], point}, "/"), func(t *testing.T) {
				c, f := newSecurityDocumentFixture(t)
				c.config.Transactions = securityDocumentFixtureRunner{f.transactions, point}
				switch point {
				case "authorization":
					f.authorizer.authorize = func(r application.AuthorizationRequest) error {
						if !r.ScopeOnly {
							return application.ErrForbidden
						}
						return nil
					}
				case "stager":
					f.objects.stageErr = ErrConflict
				case "second-audit":
					f.transactions.auditFailAt = 2
				case "record":
					f.transactions.ingestionWriteErr = ErrConflict
				case "commit":
					f.transactions.commitErr = ErrConflict
				}
				var id string
				var err error
				if manual {
					v, e := c.UploadManualSecurityDocument(t.Context(), f.actor, UploadManualSecurityDocumentInput{ProductID: "prod_1", DocumentType: "threat_model", Title: "Model", Sensitivity: "internal", Raw: []byte("model")})
					id, err = v.ID, e
				} else {
					v, e := c.UploadSecurityScan(t.Context(), f.actor, UploadSecurityScanInput{ProductID: "prod_1", ArtifactID: "artifact", Category: "sast", Scanner: "scanner", TargetRef: "target", Raw: []byte(`{"findings":[]}`)})
					id, err = v.ID, e
				}
				s := f.transactions.state
				if err == nil || id != "" || len(s.evidence)+len(s.securityScans)+len(s.manualDocs)+len(s.payloads)+len(s.outbox)+len(s.audit) != 0 {
					t.Fatal("failed command leaked effects", id, err, s)
				}
				if (point == "scope" || point == "artifact" || point == "authorization") && f.objects.stageCalls != 0 {
					t.Fatal("denied upload staged")
				}
			})
		}
	}
}

func TestSecurityDocumentCommandsRejectInvalidMetadataAndParserProjection(t *testing.T) {
	for _, bad := range []UploadSecurityScanInput{
		{Category: "unknown", Scanner: "scan", TargetRef: "target", Raw: []byte(`{}`)},
		{Category: "sast", Scanner: "bad\x00", TargetRef: "target", Raw: []byte(`{}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", ProductID: strings.Repeat("x", 1025), Raw: []byte(`{}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Raw: []byte(`{"findings":[{"severity":"bad\u0000"}]}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Format: "sarif", Raw: []byte(`{"version":"2.1.0","runs":[{"results":[{"level":"bad\u0000"}]}]}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Raw: []byte(`{} {}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Raw: []byte(`null`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Raw: []byte(`{"findings":[],"findings":[{"severity":"critical"}]}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Raw: []byte(`{"findings":[{"severity":"high","severity":"low"}]}`)},
		{Category: "sast", Scanner: "scan", TargetRef: "target", Raw: []byte("{\"findings\":[{\"severity\":\"\xff\"}]}")},
	} {
		c, f := newSecurityDocumentFixture(t)
		if v, err := c.UploadSecurityScan(t.Context(), f.actor, bad); !errors.Is(err, ErrValidation) || v.ID != "" || f.objects.stageCalls != 0 {
			t.Fatal("invalid scan staged", v, err)
		}
	}
	c, f := newSecurityDocumentFixture(t)
	if v, err := c.UploadManualSecurityDocument(t.Context(), f.actor, UploadManualSecurityDocumentInput{DocumentType: "threat_model", Title: "bad\x00", Sensitivity: "internal", Raw: []byte("model")}); !errors.Is(err, ErrValidation) || v.ID != "" || f.objects.stageCalls != 0 {
		t.Fatal("invalid document staged", v, err)
	}
	if _, err := NewSecurityDocumentCommands(SecurityDocumentCommandConfig{}); err == nil {
		t.Fatal("missing ports accepted")
	}
}

func TestSecurityDocumentCommandsRejectInvalidContextIdentityClockIDsAndSize(t *testing.T) {
	for _, manual := range []bool{false, true} {
		for _, bad := range []string{"nil-command", "nil-context", "canceled", "tenant", "actor", "empty", "oversize", "zero-clock", "clock-range", "id"} {
			t.Run(strings.Join([]string{map[bool]string{false: "scan", true: "manual"}[manual], bad}, "/"), func(t *testing.T) {
				c, f := newSecurityDocumentFixture(t)
				f.actor.KeyID, f.actor.UserID = "", "human"
				ctx, raw, want := t.Context(), []byte(`{"findings":[]}`), error(ErrValidation)
				switch bad {
				case "nil-command":
					c = nil
				case "nil-context":
					ctx = nil
				case "canceled":
					cancelled, cancel := context.WithCancel(ctx)
					cancel()
					ctx, want = cancelled, context.Canceled
				case "tenant":
					f.actor.TenantID = "bad\x00"
				case "actor":
					f.actor.UserID = "bad\x00"
				case "empty":
					raw = nil
				case "oversize":
					raw = make([]byte, EvidenceDocumentLimit+1)
				case "zero-clock":
					c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
				case "clock-range":
					c.config.Clock = application.ClockFunc(func() time.Time { return time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) })
				case "id":
					c.config.IDs = application.IDGeneratorFunc(func(string) string { return "bad\x00" })
				}
				var id string
				var err error
				if manual {
					v, e := c.UploadManualSecurityDocument(ctx, f.actor, UploadManualSecurityDocumentInput{ProductID: "prod_1", DocumentType: "threat_model", Title: "Model", Sensitivity: "internal", Raw: raw})
					id, err = v.ID, e
				} else {
					v, e := c.UploadSecurityScan(ctx, f.actor, UploadSecurityScanInput{ProductID: "prod_1", Category: "sast", Scanner: "scanner", TargetRef: "target", Raw: raw})
					id, err = v.ID, e
				}
				s := f.transactions.state
				if !errors.Is(err, want) || id != "" || len(s.evidence)+len(s.securityScans)+len(s.manualDocs)+len(s.payloads)+len(s.outbox)+len(s.audit) != 0 {
					t.Fatal("invalid command leaked effects", id, err)
				}
				if bad != "id" && f.objects.stageCalls != 0 {
					t.Fatal("invalid command staged bytes")
				}
			})
		}
	}
}

func TestSecurityDocumentProjectionBounds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value parsedSecurityScan
		valid bool
	}{
		{"empty", parsedSecurityScan{Format: "generic", Summary: map[string]int{}}, true},
		{"finding-limit", parsedSecurityScan{Format: "generic", FindingCount: SecurityDocumentFindingLimit, Summary: map[string]int{"high": SecurityDocumentFindingLimit}}, true},
		{"too-many", parsedSecurityScan{Format: "generic", FindingCount: SecurityDocumentFindingLimit + 1}, false},
		{"negative", parsedSecurityScan{Format: "generic", FindingCount: -1}, false},
		{"missing-count", parsedSecurityScan{Format: "generic", FindingCount: 1}, false},
		{"over-count", parsedSecurityScan{Format: "generic", FindingCount: 1, Summary: map[string]int{"high": 2}}, false},
		{"zero-count", parsedSecurityScan{Format: "generic", Summary: map[string]int{"high": 0}}, false},
		{"negative-count", parsedSecurityScan{Format: "generic", Summary: map[string]int{"high": -1}}, false},
		{"empty-format", parsedSecurityScan{}, false},
		{"nul-format", parsedSecurityScan{Format: "bad\x00"}, false},
		{"empty-label", parsedSecurityScan{Format: "generic", FindingCount: 1, Summary: map[string]int{"": 1}}, false},
		{"invalid-label", parsedSecurityScan{Format: "generic", FindingCount: 1, Summary: map[string]int{"\xff": 1}}, false},
		{"label-limit", parsedSecurityScan{Format: "generic", FindingCount: 1, Summary: map[string]int{strings.Repeat("a", 1<<20): 1}}, true},
		{"label-over-limit", parsedSecurityScan{Format: "generic", FindingCount: 1, Summary: map[string]int{strings.Repeat("a", (1<<20)+1): 1}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validSecurityDocumentProjection(tc.value); got != tc.valid {
				t.Fatal("projection bound", got, tc.valid)
			}
		})
	}
	labels := make(map[string]int, 9)
	for i := range 8 {
		labels[strings.Repeat(string(rune('a'+i)), 1<<20)] = 1
	}
	if !validSecurityDocumentProjection(parsedSecurityScan{Format: "generic", FindingCount: 8, Summary: labels}) {
		t.Fatal("exact summary budget rejected")
	}
	labels["overflow"] = 1
	if validSecurityDocumentProjection(parsedSecurityScan{Format: "generic", FindingCount: 9, Summary: labels}) {
		t.Fatal("summary over budget accepted")
	}
}

func TestSecurityDocumentReducedParserRejectsNullEntries(t *testing.T) {
	for _, tc := range []struct{ format, raw string }{
		{"generic", `{"findings":[null]}`},
		{"sarif", `{"version":"2.1.0","runs":[null]}`},
		{"sarif", `{"version":"2.1.0","runs":[{"results":[null]}]}`},
	} {
		if _, err := parseSecurityScan(tc.format, []byte(tc.raw)); !errors.Is(err, ErrValidation) {
			t.Fatal("null entry became a finding or run", tc.raw, err)
		}
	}
	for _, tc := range []struct{ format, raw, label string }{
		{"generic", `{"findings":[{}]}`, "unknown"},
		{"sarif", `{"version":"2.1.0","runs":[{"results":[{}]}]}`, "warning"},
	} {
		v, err := parseSecurityScan(tc.format, []byte(tc.raw))
		if err != nil || v.FindingCount != 1 || v.Summary[tc.label] != 1 {
			t.Fatal("omitted severity default changed", v, err)
		}
	}
}
