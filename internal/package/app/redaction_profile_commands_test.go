package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var errRedactionWrite = errors.New("private redaction storage failure")

type redactionFixture struct {
	phase        string
	profiles     []packagedomain.RedactionProfile
	audits       []application.AuditEvent
	transactions int
	cancel       context.CancelFunc
}

func (f *redactionFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopePackageWrite || !r.ScopeOnly || r.TenantWide || r.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, a, r.Scope)
}

func (f *redactionFixture) ExecuteRedactionProfile(ctx context.Context, tenant string, fn func(context.Context, RedactionProfileTransaction) error) error {
	f.transactions++
	if tenant != "tenant" || f.phase == "tenant" {
		return ErrNotFound
	}
	p, a := len(f.profiles), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errRedactionWrite
	}
	if err != nil {
		f.profiles, f.audits = f.profiles[:p], f.audits[:a]
	}
	return err
}

func (f *redactionFixture) InsertRedactionProfile(_ context.Context, v packagedomain.RedactionProfile) error {
	if f.phase == "insert" {
		return errRedactionWrite
	}
	f.profiles = append(f.profiles, v)
	return nil
}

func (f *redactionFixture) AppendAudit(_ context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errRedactionWrite
	}
	f.audits = append(f.audits, e)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}

func newRedactionFixture(t *testing.T) (*RedactionProfileCommands, *redactionFixture, identitydomain.Actor) {
	t.Helper()
	f := &redactionFixture{}
	n := 0
	c, err := NewRedactionProfileCommands(RedactionProfileCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { n++; return fmt.Sprintf("%s-%d", p, n) })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{ScopePackageWrite}}
}

func TestRedactionCommandPreservesPresetRulesAndAtomicAudit(t *testing.T) {
	for _, preset := range []string{"customer_safe", "security_review"} {
		t.Run(preset, func(t *testing.T) {
			c, f, a := newRedactionFixture(t)
			v, err := c.CreateRedactionProfile(t.Context(), a, CreateRedactionProfileInput{Preset: " " + preset + " ", Name: "ignored", Description: "ignored"})
			p := redactionProfilePresets[preset]
			p.allowedTypes = append([]string(nil), p.allowedTypes...)
			p.excludedFields = append([]string(nil), p.excludedFields...)
			sort.Strings(p.allowedTypes)
			sort.Strings(p.excludedFields)
			if err != nil || v.Name != p.name || v.Description != p.description || !reflect.DeepEqual(v.AllowedTypes, p.allowedTypes) || !reflect.DeepEqual(v.ExcludedFields, p.excludedFields) || v.SchemaVersion != packagedomain.RedactionProfileSchemaVersion || v.CreatedAt.Nanosecond() != 123456000 {
				t.Fatal("preset or timestamp compatibility changed", err)
			}
			if len(f.profiles) != 1 || len(f.audits) != 1 || f.audits[0].EntryType != "redaction_profile.created" || f.audits[0].SubjectType != "redaction_profile" || f.audits[0].SubjectID != v.ID || f.audits[0].ActorID != "key" || f.audits[0].ActorType != "api_key" || f.audits[0].PayloadHash != "" || !f.audits[0].OccurredAt.Equal(v.CreatedAt) {
				t.Fatal("profile/audit identity differs")
			}
			v.AllowedTypes[0] = "mutation"
			v.ExcludedFields[0] = "mutation"
			if f.profiles[0].AllowedTypes[0] != p.allowedTypes[0] || f.profiles[0].ExcludedFields[0] != p.excludedFields[0] {
				t.Fatal("mutable output aliases durable/preset data")
			}
		})
	}
	c, f, a := newRedactionFixture(t)
	in := CreateRedactionProfileInput{Name: " Custom ", Description: " notes ", AllowedTypes: []string{" z ", "a", "a"}, ExcludedFields: []string{" token ", " ", "token"}}
	v, err := c.CreateRedactionProfile(t.Context(), a, in)
	if err != nil || v.Name != "Custom" || v.Description != "notes" || !reflect.DeepEqual(v.AllowedTypes, []string{"a", "z"}) || !reflect.DeepEqual(v.ExcludedFields, []string{"token"}) {
		t.Fatal("custom normalization changed", v, err)
	}
	in.AllowedTypes[0] = "mutated input"
	v.ExcludedFields[0] = "mutated output"
	if f.profiles[0].AllowedTypes[1] != "z" || f.profiles[0].ExcludedFields[0] != "token" {
		t.Fatal("caller aliases stored profile")
	}
}

func TestRedactionCommandRollbackAndReplayAuthority(t *testing.T) {
	for _, phase := range []string{"tenant", "insert", "audit", "commit", "cancel"} {
		t.Run(phase, func(t *testing.T) {
			c, f, a := newRedactionFixture(t)
			f.phase = phase
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.cancel = cancel
			want := errRedactionWrite
			if phase == "tenant" {
				want = ErrNotFound
			}
			if phase == "cancel" {
				want = context.Canceled
			}
			v, err := c.CreateRedactionProfile(ctx, a, CreateRedactionProfileInput{Preset: "customer_safe"})
			if !errors.Is(err, want) || v.ID != "" || len(f.profiles)+len(f.audits) != 0 {
				t.Fatal("failed command published profile", err)
			}
		})
	}
	c, f, a := newRedactionFixture(t)
	in := CreateRedactionProfileInput{Preset: "customer_safe"}
	if err := c.AuthorizeCreateRedactionProfile(t.Context(), a, in); err != nil || f.transactions != 1 || len(f.profiles)+len(f.audits) != 0 {
		t.Fatal("replay guard mutated", err)
	}
	a.KeyID, a.UserID = "", "user"
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{ScopePackageWrite}}}
	if err := c.AuthorizeCreateRedactionProfile(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) || f.transactions != 1 {
		t.Fatal("product grant authorized tenant policy", err)
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{ScopePackageWrite}}}
	if _, err := c.CreateRedactionProfile(t.Context(), a, in); err != nil || f.audits[0].ActorType != "human_user" || f.audits[0].ActorID != "user" {
		t.Fatal("tenant grant rejected", err)
	}
	a.ResourceGrants[0].ResourceID = "other"
	if err := c.AuthorizeCreateRedactionProfile(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("foreign tenant grant replayed", err)
	}
	a.ResourceGrants = nil
	if err := c.AuthorizeCreateRedactionProfile(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("revoked grant replayed", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := f.transactions
	if _, err := c.CreateRedactionProfile(ctx, a, in); !errors.Is(err, context.Canceled) || f.transactions != before {
		t.Fatal("cancelled request reached persistence", err)
	}
}

func TestRedactionCommandValidatesRawBoundsBeforePersistence(t *testing.T) {
	for _, kind := range []string{"name", "description", "preset", "unknown preset", "override", "empty allowlist", "blank type", "type count", "field count", "entry", "nul", "utf8", "raw whitespace"} {
		t.Run(kind, func(t *testing.T) {
			c, f, a := newRedactionFixture(t)
			in := CreateRedactionProfileInput{Name: "Custom", AllowedTypes: []string{"sbom"}}
			switch kind {
			case "name":
				in.Name = strings.Repeat("x", MaxRedactionProfileTextBytes+1)
			case "description":
				in.Description = strings.Repeat("x", MaxRedactionProfileTextBytes+1)
			case "preset":
				in.Preset = strings.Repeat(" ", MaxRedactionProfileTextBytes+1)
			case "unknown preset":
				in.Preset = "unreviewed"
			case "override":
				in.Preset = "customer_safe"
			case "empty allowlist":
				in.AllowedTypes = nil
			case "blank type":
				in.AllowedTypes = []string{" "}
			case "type count":
				in.AllowedTypes = make([]string, MaxRedactionProfileEntries+1)
			case "field count":
				in.ExcludedFields = make([]string, MaxRedactionProfileEntries+1)
			case "entry":
				in.AllowedTypes = []string{strings.Repeat("x", MaxRedactionProfileEntryBytes+1)}
			case "nul":
				in.Description = "note\x00"
			case "utf8":
				in.AllowedTypes = []string{string([]byte{0xff})}
			case "raw whitespace":
				in.Name = strings.Repeat(" ", MaxRedactionProfileTextBytes) + "n"
			}
			if _, err := c.CreateRedactionProfile(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
				t.Fatal("invalid input reached transaction", err)
			}
		})
	}
	c, _, a := newRedactionFixture(t)
	in := CreateRedactionProfileInput{Name: strings.Repeat("n", MaxRedactionProfileTextBytes), Description: strings.Repeat("d", MaxRedactionProfileTextBytes), AllowedTypes: make([]string, MaxRedactionProfileEntries), ExcludedFields: make([]string, MaxRedactionProfileEntries)}
	for i := range in.AllowedTypes {
		in.AllowedTypes[i] = fmt.Sprintf("%04d", i) + strings.Repeat("a", MaxRedactionProfileEntryBytes-4)
		in.ExcludedFields[i] = fmt.Sprintf("%04d", i) + strings.Repeat("b", MaxRedactionProfileEntryBytes-4)
	}
	if _, err := c.CreateRedactionProfile(t.Context(), a, in); err != nil {
		t.Fatal("exact raw bounds rejected", err)
	}
}

func TestRedactionRecordRejectsNoncanonicalAndForgedData(t *testing.T) {
	c, _, a := newRedactionFixture(t)
	v, err := c.CreateRedactionProfile(t.Context(), a, CreateRedactionProfileInput{Name: "Customer", AllowedTypes: []string{"sbom", "vex"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"id", "tenant", "schema", "time", "name", "unsorted", "duplicate", "blank field", "encoded budget"} {
		t.Run(kind, func(t *testing.T) {
			bad := cloneRedactionProfile(v)
			switch kind {
			case "id":
				bad.ID = ""
			case "tenant":
				bad.TenantID = " foreign "
			case "schema":
				bad.SchemaVersion = "wrong"
			case "time":
				bad.CreatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "name":
				bad.Name = " Customer "
			case "unsorted":
				bad.AllowedTypes = []string{"vex", "sbom"}
			case "duplicate":
				bad.AllowedTypes = []string{"sbom", "sbom"}
			case "blank field":
				bad.ExcludedFields = []string{""}
			case "encoded budget":
				bad.AllowedTypes = make([]string, MaxRedactionProfileEntries)
				for i := range bad.AllowedTypes {
					bad.AllowedTypes[i] = fmt.Sprintf("%04d", i) + strings.Repeat("<", MaxRedactionProfileEntryBytes-4)
				}
			}
			if err := ValidateRedactionProfileRecord(bad); !errors.Is(err, ErrValidation) {
				t.Fatal("invalid durable profile accepted", err)
			}
		})
	}
	for _, missing := range []string{"transactions", "authorizer", "clock", "ids"} {
		c, _, _ := newRedactionFixture(t)
		cfg := c.config
		switch missing {
		case "transactions":
			cfg.Transactions = nil
		case "authorizer":
			cfg.Authorizer = nil
		case "clock":
			cfg.Clock = nil
		case "ids":
			cfg.IDs = nil
		}
		if _, err := NewRedactionProfileCommands(cfg); !errors.Is(err, ErrValidation) {
			t.Fatal("incomplete config accepted", missing)
		}
	}
}

func TestRedactionNormalizationCanRepeatAcrossBoundaries(t *testing.T) {
	for _, in := range []CreateRedactionProfileInput{{Preset: " customer_safe "}, {Preset: "security_review"}, {Name: " Customer ", AllowedTypes: []string{" sbom ", "sbom"}, ExcludedFields: []string{" ", " token "}}} {
		one, err := NormalizeRedactionProfileInput(in)
		if err != nil {
			t.Fatal(err)
		}
		two, err := NormalizeRedactionProfileInput(one)
		if err != nil || !reflect.DeepEqual(one, two) {
			t.Fatal("normalization is not stable", err)
		}
	}
}

func TestRedactionGeneratedMetadataFailsBeforeWrites(t *testing.T) {
	for _, kind := range []string{"profile-id", "audit-id", "time"} {
		c, f, a := newRedactionFixture(t)
		switch kind {
		case "profile-id":
			c.config.IDs = application.IDGeneratorFunc(func(string) string { return "\x00" })
		case "audit-id":
			c.config.IDs = application.IDGeneratorFunc(func(p string) string {
				if p == "ace" {
					return ""
				}
				return "profile"
			})
		case "time":
			c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		}
		v, err := c.CreateRedactionProfile(t.Context(), a, CreateRedactionProfileInput{Preset: "customer_safe"})
		if !errors.Is(err, ErrValidation) || v.ID != "" || len(f.profiles)+len(f.audits) != 0 {
			t.Fatal("invalid generated metadata wrote profile", kind, err)
		}
	}
}
