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

type saasFixture struct {
	roots               SaaSProfileTenants
	phase               string
	reads, transactions int
	profiles            []experimentaldomain.SaaSEditionProfile
	audits              []application.AuditEvent
	cancel              context.CancelFunc
}

var errSaaSFixture = errors.New("SaaS fixture failure")

func (f *saasFixture) ExecuteSaaSProfile(ctx context.Context, _ string, fn func(context.Context, SaaSProfileTransaction) error) error {
	f.transactions++
	p, a := len(f.profiles), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errSaaSFixture
	}
	if err != nil {
		f.profiles, f.audits = f.profiles[:p], f.audits[:a]
	}
	return err
}
func (f *saasFixture) ReadSaaSProfileTenants(context.Context, string, string) (SaaSProfileTenants, error) {
	f.reads++
	if f.phase == "read" {
		return SaaSProfileTenants{}, errSaaSFixture
	}
	return f.roots, nil
}
func (f *saasFixture) InsertSaaSProfile(_ context.Context, v experimentaldomain.SaaSEditionProfile) error {
	if f.phase == "insert" {
		return errSaaSFixture
	}
	f.profiles = append(f.profiles, v)
	return nil
}
func (f *saasFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errSaaSFixture
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func saasCommandFixture(t *testing.T) (*SaaSProfileCommands, *saasFixture, identitydomain.Actor, SaaSProfileInput) {
	t.Helper()
	f := &saasFixture{roots: SaaSProfileTenants{TenantID: "tenant", AdminTenantID: "other"}}
	n := 0
	c, err := NewSaaSProfileCommands(SaaSProfileConfig{Transactions: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"instance:admin"}}, SaaSProfileInput{Name: " hosted ", Region: " eu ", AdminTenantID: " other ", IsolationModel: " shared-control-plane "}
}
func TestSaaSProfileCommandsPreserveRawHashAndGuardWithoutWrites(t *testing.T) {
	c, f, a, in := saasCommandFixture(t)
	if err := c.AuthorizeCreateSaaSProfile(t.Context(), a, in); err != nil || f.reads != 1 || len(f.profiles)+len(f.audits) != 0 {
		t.Fatal("guard performed writes", err)
	}
	v, err := c.CreateSaaSProfile(t.Context(), a, in)
	// This independent map preserves the legacy untagged input's raw values,
	// rather than hashing normalized stored fields or a new snake-case schema.
	wantHash, hashErr := application.NormalizedJSONHash(map[string]any{"Name": in.Name, "Region": in.Region, "AdminTenantID": in.AdminTenantID, "IsolationModel": in.IsolationModel})
	if err != nil || hashErr != nil || v.ConfigHash != wantHash || v.Name != "hosted" || v.AdminTenantID != "other" || v.TenantID != "tenant" || v.Status != "proposed" || v.SchemaVersion != experimentaldomain.SaaSEditionProfileVersion || v.CreatedAt.Nanosecond() != 123456000 || len(f.profiles) != 1 || len(f.audits) != 1 {
		t.Fatal("profile contract changed", v, err)
	}
	e := f.audits[0]
	if e.EntryType != "saas_profile.created" || e.SubjectType != "saas_profile" || e.SubjectID != v.ID || e.TenantID != a.TenantID || e.PayloadHash != v.ConfigHash || e.ActorID != a.KeyID || e.OccurredAt != v.CreatedAt {
		t.Fatal("audit not bound", e)
	}
	v.Limitations[0] = "changed"
	if f.profiles[0].Limitations[0] == "changed" {
		t.Fatal("mutable profile escaped")
	}
	raw, err := EncodeSaaSProfile(f.profiles[0])
	if err != nil || strings.Contains(string(raw), `"AdminTenantID"`) || !strings.Contains(string(raw), `"admin_tenant_id":"other"`) || !strings.Contains(string(raw), `"status":"proposed"`) {
		t.Fatal("profile casing changed", string(raw), err)
	}
}
func TestSaaSProfileCommandsRejectUnauthorizedAndInvalidInputsBeforeReads(t *testing.T) {
	for _, mode := range []string{"wildcard", "tenant-admin", "anonymous", "name", "region", "admin", "isolation", "utf8", "blank", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a, in := saasCommandFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := ErrValidation
			switch mode {
			case "wildcard":
				a.Scopes = []string{"*"}
				want = application.ErrForbidden
			case "tenant-admin":
				a.Scopes = []string{"admin"}
				want = application.ErrForbidden
			case "anonymous":
				a.KeyID = ""
				want = application.ErrUnauthorized
			case "name":
				in.Name = strings.Repeat(" ", 257) + "n"
			case "region":
				in.Region = strings.Repeat(" ", 129) + "r"
			case "admin":
				in.AdminTenantID = strings.Repeat(" ", 1025) + "a"
			case "isolation":
				in.IsolationModel = "model\x00"
			case "utf8":
				in.Name = string([]byte{255})
			case "blank":
				in.Region = " "
			case "canceled":
				cancel()
				want = context.Canceled
			}
			v, err := c.CreateSaaSProfile(ctx, a, in)
			if !errors.Is(err, want) || v.ID != "" || f.transactions+f.reads != 0 {
				t.Fatal("invalid input reached persistence", v, err)
			}
		})
	}
}
func TestSaaSProfileCommandsFailuresReturnNoPublishedProfile(t *testing.T) {
	for _, phase := range []string{"read", "foreign", "missing-admin", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a, in := saasCommandFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.cancel = cancel
			f.phase = phase
			switch phase {
			case "foreign":
				f.roots.TenantID = "other"
			case "missing-admin":
				f.roots.AdminTenantID = "missing"
			}
			v, err := c.CreateSaaSProfile(ctx, a, in)
			if err == nil || !reflect.DeepEqual(v, experimentaldomain.SaaSEditionProfile{}) || len(f.profiles)+len(f.audits) != 0 {
				t.Fatal("partial profile published", v, err)
			}
		})
	}
}

func TestSaaSProfileCommandsRequirePortsAndValidGeneratedCoordinates(t *testing.T) {
	c, _, _, _ := saasCommandFixture(t)
	for _, missing := range []string{"transactions", "clock", "ids"} {
		config := c.config
		switch missing {
		case "transactions":
			config.Transactions = nil
		case "clock":
			config.Clock = nil
		case "ids":
			config.IDs = nil
		}
		if v, err := NewSaaSProfileCommands(config); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("missing required port accepted", missing, err)
		}
	}
	for _, invalid := range []string{"clock", "ids"} {
		c, f, a, in := saasCommandFixture(t)
		if invalid == "clock" {
			c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		} else {
			c.config.IDs = application.IDGeneratorFunc(func(string) string { return "" })
		}
		v, err := c.CreateSaaSProfile(t.Context(), a, in)
		if !errors.Is(err, ErrValidation) || v.ID != "" || len(f.profiles)+len(f.audits) != 0 {
			t.Fatal("invalid generated coordinate published profile", v, err)
		}
	}
}
