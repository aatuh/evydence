package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type marketplaceFixture struct {
	refs                MarketplaceReferences
	phase               string
	reads, transactions int
	collectors          []experimentaldomain.MarketplaceCollector
	audits              []application.AuditEvent
	cancel              context.CancelFunc
}

var errMarketplaceFixture = errors.New("marketplace fixture failure")

func (f *marketplaceFixture) ExecuteMarketplaceCollector(ctx context.Context, _ string, fn func(context.Context, MarketplaceCollectorTransaction) error) error {
	f.transactions++
	n, m := len(f.collectors), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errMarketplaceFixture
	}
	if err != nil {
		f.collectors, f.audits = f.collectors[:n], f.audits[:m]
	}
	return err
}
func (f *marketplaceFixture) ReadMarketplaceReferences(context.Context, string, MarketplaceReferenceIDs) (MarketplaceReferences, error) {
	f.reads++
	if f.phase == "read" {
		return MarketplaceReferences{}, errMarketplaceFixture
	}
	return f.refs, nil
}
func (f *marketplaceFixture) InsertMarketplaceCollector(_ context.Context, v experimentaldomain.MarketplaceCollector) error {
	if f.phase == "insert" {
		return errMarketplaceFixture
	}
	f.collectors = append(f.collectors, v)
	return nil
}
func (f *marketplaceFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errMarketplaceFixture
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func marketplaceCommandFixture(t *testing.T) (*MarketplaceCollectorCommands, *marketplaceFixture, identitydomain.Actor, MarketplaceCollectorInput) {
	t.Helper()
	f := &marketplaceFixture{refs: MarketplaceReferences{TenantID: "tenant", SignatureID: "signature", SBOMID: "sbom", ScanID: "scan"}}
	n := 0
	c, err := NewMarketplaceCollectorCommands(MarketplaceCollectorConfig{Transactions: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"collector:admin"}}, MarketplaceCollectorInput{Name: " Scanner ", Provider: " scanner ", Version: " 1.0 ", Publisher: " publisher ", ManifestHash: " sha256:" + strings.Repeat("A", 64) + " ", SignatureID: " signature ", SBOMID: " sbom ", ScanID: " scan "}
}
func TestMarketplaceCreationCommandsPreserveMetadataAndGuardWithoutWrites(t *testing.T) {
	c, f, a, in := marketplaceCommandFixture(t)
	if err := c.AuthorizeCreateMarketplaceCollector(t.Context(), a, in); err != nil || f.reads != 1 || len(f.collectors)+len(f.audits) != 0 {
		t.Fatal("guard wrote collector", err)
	}
	v, err := c.CreateMarketplaceCollector(t.Context(), a, in)
	if err != nil || v.Name != "Scanner" || v.ManifestHash != strings.TrimSpace(in.ManifestHash) || v.State != "registered" || v.SchemaVersion != experimentaldomain.MarketplaceCollectorVersion || v.CreatedAt.Nanosecond() != 123456000 || len(f.collectors) != 1 || len(f.audits) != 1 {
		t.Fatal("registration contract changed", v, err)
	}
	e := f.audits[0]
	if e.TenantID != a.TenantID || e.EntryType != "marketplace_collector.created" || e.SubjectType != "marketplace_collector" || e.SubjectID != v.ID || e.PayloadHash != v.ManifestHash || e.ActorID != a.KeyID || e.OccurredAt != v.CreatedAt {
		t.Fatal("collector audit binding changed", e)
	}
	v.Limitations[0] = "changed"
	if f.collectors[0].Limitations[0] == "changed" {
		t.Fatal("collector exposes mutable storage")
	}
	in.SignatureID, in.SBOMID, in.ScanID = "", "", ""
	f.refs.SignatureID, f.refs.SBOMID, f.refs.ScanID = "", "", ""
	v, err = c.CreateMarketplaceCollector(t.Context(), a, in)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeMarketplaceCollector(v)
	if err != nil || strings.Contains(string(raw), `"SignatureID"`) || strings.Contains(string(raw), `"signature_id"`) || strings.Contains(string(raw), `"sbom_id"`) || strings.Contains(string(raw), `"scan_id"`) || !strings.Contains(string(raw), `"state":"registered"`) {
		t.Fatal("collector response casing or omission changed", string(raw), err)
	}
}
func TestMarketplaceCreationCommandsRejectUnsafeInputBeforeReads(t *testing.T) {
	for _, mode := range []string{"anonymous", "scope", "human", "name", "provider", "version", "publisher", "hash", "id", "blank-id", "nul", "utf8", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a, in := marketplaceCommandFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := ErrValidation
			switch mode {
			case "anonymous":
				a.KeyID = ""
				want = application.ErrUnauthorized
			case "scope":
				a.Scopes = []string{"collector:read"}
				want = application.ErrForbidden
			case "human":
				a.KeyID, a.UserID = "", "user"
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"collector:admin"}}}
				want = application.ErrForbidden
			case "name":
				in.Name = strings.Repeat(" ", 257) + "n"
			case "provider":
				in.Provider = strings.Repeat("p", 257)
			case "version":
				in.Version = strings.Repeat("v", 129)
			case "publisher":
				in.Publisher = strings.Repeat("p", 257)
			case "hash":
				in.ManifestHash = "sha256:bad"
			case "id":
				in.SBOMID = strings.Repeat(" ", 1025) + "s"
			case "blank-id":
				in.SignatureID = " "
			case "nul":
				in.Name = "label\x00"
			case "utf8":
				in.Name = string([]byte{255})
			case "canceled":
				cancel()
				want = context.Canceled
			}
			v, err := c.CreateMarketplaceCollector(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || f.reads+f.transactions != 0 {
				t.Fatal("unsafe registration reached persistence", v, err)
			}
		})
	}
}
func TestMarketplaceCreationCommandsFailureRollsBackCollectorAndAudit(t *testing.T) {
	for _, phase := range []string{"read", "tenant", "signature", "sbom", "scan", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := marketplaceCommandFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.phase, f.cancel = phase, cancel
			switch phase {
			case "tenant":
				f.refs.TenantID = "foreign"
			case "signature":
				f.refs.SignatureID = "foreign"
			case "sbom":
				f.refs.SBOMID = "foreign"
			case "scan":
				f.refs.ScanID = "foreign"
			}
			v, err := c.CreateMarketplaceCollector(ctx, a, in)
			if err == nil || !reflect.DeepEqual(v, experimentaldomain.MarketplaceCollector{}) || len(f.collectors)+len(f.audits) != 0 {
				t.Fatal("partial collector published", v, err)
			}
		})
	}
}

func TestMarketplaceCreationCommandsRequirePortsAndRejectInvalidGeneratedRecords(t *testing.T) {
	for _, missing := range []string{"transactions", "clock", "ids"} {
		c, _, _, _ := marketplaceCommandFixture(t)
		config := c.config
		switch missing {
		case "transactions":
			config.Transactions = nil
		case "clock":
			config.Clock = nil
		case "ids":
			config.IDs = nil
		}
		if out, err := NewMarketplaceCollectorCommands(config); !errors.Is(err, ErrValidation) || out != nil {
			t.Fatal("missing required port accepted", missing)
		}
	}
	for _, bad := range []string{"collector-id", "audit-id", "time"} {
		c, f, a, in := marketplaceCommandFixture(t)
		if bad == "time" {
			c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		} else {
			c.config.IDs = application.IDGeneratorFunc(func(p string) string {
				if bad == "collector-id" && p == "mpc" || bad == "audit-id" && p == "ace" {
					return "bad\x00"
				}
				return p + "-safe"
			})
		}
		v, err := c.CreateMarketplaceCollector(t.Context(), a, in)
		if !errors.Is(err, ErrValidation) || v.ID != "" || len(f.collectors)+len(f.audits) != 0 {
			t.Fatal("invalid generated data reached storage", bad, v, err)
		}
	}
}
func TestMarketplaceCreationCommandsRawByteBoundaryAndHumanTenantGrant(t *testing.T) {
	c, f, a, in := marketplaceCommandFixture(t)
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{"collector:admin"}}}
	in.Name = strings.Repeat("é", 128)
	if out, err := c.CreateMarketplaceCollector(t.Context(), a, in); err != nil || out.Name != in.Name || f.audits[0].ActorType != "human_user" {
		t.Fatal("bounded UTF-8 or human grant rejected", err)
	}
	before := f.reads
	in.Name += "é"
	if out, err := c.CreateMarketplaceCollector(t.Context(), a, in); !errors.Is(err, ErrValidation) || out.ID != "" || f.reads != before {
		t.Fatal("byte limit became a character limit", err)
	}
}
