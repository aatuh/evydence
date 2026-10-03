package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type sbomDiffFixture struct {
	subjects   map[string]SBOMDiffSubject
	components map[string][]evidencedomain.SBOMComponent
	writes     []evidencedomain.SBOMDiff
	audits     []application.AuditEvent
	reads      int
	fail       string
}

func (f *sbomDiffFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeEvidenceRead || f.fail == "authorization" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *sbomDiffFixture) ReadSBOMDiffSubject(_ context.Context, tenant, id string) (SBOMDiffSubject, error) {
	v, ok := f.subjects[id]
	if !ok || v.TenantID != tenant {
		return SBOMDiffSubject{}, ErrNotFound
	}
	return v, nil
}
func (f *sbomDiffFixture) ReadSBOMDiffComponents(_ context.Context, _, id string) ([]evidencedomain.SBOMComponent, error) {
	f.reads++
	if f.fail == "read" {
		return nil, errors.New("read failure")
	}
	return append([]evidencedomain.SBOMComponent(nil), f.components[id]...), nil
}
func (f *sbomDiffFixture) InsertSBOMDiff(_ context.Context, v evidencedomain.SBOMDiff) error {
	if f.fail == "insert" {
		return errors.New("insert failure")
	}
	f.writes = append(f.writes, v)
	return nil
}
func (f *sbomDiffFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, errors.New("audit failure")
	}
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, nil
}
func (f *sbomDiffFixture) ExecuteSBOMDiff(ctx context.Context, fn func(context.Context, SBOMDiffTransaction) error) error {
	w, a := len(f.writes), len(f.audits)
	err := fn(ctx, f)
	if f.fail == "commit" && err == nil {
		err = errors.New("commit failure")
	}
	if err != nil {
		f.writes = f.writes[:w]
		f.audits = f.audits[:a]
	}
	return err
}
func newSBOMDiffFixture(t *testing.T) (*SBOMDiffCommands, *sbomDiffFixture, identitydomain.Actor, CreateSBOMDiffInput) {
	t.Helper()
	f := &sbomDiffFixture{subjects: map[string]SBOMDiffSubject{}, components: map[string][]evidencedomain.SBOMComponent{}}
	for _, id := range []string{"base", "target"} {
		f.subjects[id] = SBOMDiffSubject{ID: id, TenantID: "tenant", EvidenceID: "ev-" + id, Resources: application.ResourceReferences{ProductID: "product", ReleaseID: id + "-release"}}
	}
	f.components["base"] = []evidencedomain.SBOMComponent{{Identity: "same", Name: "original"}, {Name: "gone", Version: "1"}, {PURL: "pkg:generic/b@1", Name: "b"}}
	f.components["target"] = []evidencedomain.SBOMComponent{{Identity: "same", Name: "renamed"}, {Name: "new", Version: "2"}, {PURL: "pkg:generic/b@1", Name: "b"}, {Name: "new", Version: "2"}}
	i := 0
	s, err := NewSBOMDiffCommands(SBOMDiffCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 1, 2, 3, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { i++; return p + strings.Repeat("x", i) })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeEvidenceRead}}, CreateSBOMDiffInput{BaseSBOMID: " base ", TargetSBOMID: "target", ReleaseID: "target-release"}
}
func TestSBOMDiffCommandsPreserveCanonicalDiffAndAtomicEffects(t *testing.T) {
	s, f, a, in := newSBOMDiffFixture(t)
	if err := s.AuthorizeCreateSBOMDiff(t.Context(), a, in); err != nil || f.reads != 0 || len(f.writes) != 0 {
		t.Fatal("replay authorization read component payloads", err, f.reads)
	}
	v, err := s.CreateSBOMDiff(t.Context(), a, in)
	if err != nil || v.ID == "" || v.TenantID != "tenant" || v.BaseSBOMID != "base" || v.TargetSBOMID != "target" || v.ReleaseID != "target-release" || v.UnchangedCount != 2 || v.SchemaVersion != evidencedomain.SBOMDiffSchemaVersion || v.CreatedAt.Nanosecond() != 123456000 {
		t.Fatal("diff contract changed", v, err)
	}
	if !reflect.DeepEqual(v.AddedComponents, []evidencedomain.SBOMComponent{{Name: "new", Version: "2"}}) || !reflect.DeepEqual(v.RemovedComponents, []evidencedomain.SBOMComponent{{Name: "gone", Version: "1"}}) || len(v.DependencyChanges) != 2 || len(f.writes) != 1 || len(f.audits) != 1 {
		t.Fatal("diff effects changed", v, f.audits)
	}
	for i, c := range v.DependencyChanges {
		want := "added"
		if i == 1 {
			want = "removed"
		}
		if c.ID == "" || c.SBOMDiffID != v.ID || c.TenantID != a.TenantID || c.ChangeType != want || c.SchemaVersion != evidencedomain.DependencyChangeSchemaVersion || c.CreatedAt != v.CreatedAt {
			t.Fatal("dependency contract changed", c)
		}
	}
	au := f.audits[0]
	if au.EntryType != "sbom.diffed" || au.SubjectType != "sbom_diff" || au.SubjectID != v.ID || au.ActorID != "human" || au.ActorType != "human_user" || au.OccurredAt != v.CreatedAt {
		t.Fatal("audit changed", au)
	}
	v.AddedComponents[0].Name = "mutated"
	if f.writes[0].AddedComponents[0].Name != "new" {
		t.Fatal("returned diff aliases stored data")
	}
}
func TestSBOMDiffCommandsRejectInvalidInputsAndRollback(t *testing.T) {
	for _, stage := range []string{"authorization", "read", "insert", "audit", "commit"} {
		t.Run(stage, func(t *testing.T) {
			s, f, a, in := newSBOMDiffFixture(t)
			f.fail = stage
			v, err := s.CreateSBOMDiff(t.Context(), a, in)
			if err == nil || v.ID != "" || len(f.writes) != 0 || len(f.audits) != 0 {
				t.Fatal("failure leaked effects", v, err)
			}
			if stage == "authorization" && f.reads != 0 {
				t.Fatal("denied actor read components")
			}
		})
	}
	for _, bad := range []CreateSBOMDiffInput{{}, {BaseSBOMID: "base", TargetSBOMID: "base"}, {BaseSBOMID: "base", TargetSBOMID: "target", ReleaseID: "unrelated"}, {BaseSBOMID: "base\x00", TargetSBOMID: "target"}, {BaseSBOMID: strings.Repeat("x", 1025), TargetSBOMID: "target"}} {
		s, f, a, _ := newSBOMDiffFixture(t)
		v, err := s.CreateSBOMDiff(t.Context(), a, bad)
		if !errors.Is(err, ErrValidation) || v.ID != "" || f.reads != 0 {
			t.Fatal("invalid input read components", bad, err)
		}
	}
	for _, bad := range [][]evidencedomain.SBOMComponent{{{Name: " "}}, {{Name: "bad\x00"}}, {{Name: strings.Repeat("x", (1<<20)+1)}}, make([]evidencedomain.SBOMComponent, 100001)} {
		s, f, a, in := newSBOMDiffFixture(t)
		f.components["base"] = bad
		if v, err := s.CreateSBOMDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes) != 0 {
			t.Fatal("malformed projection accepted", v.ID, err)
		}
	}
	s, f, a, in := newSBOMDiffFixture(t)
	v := f.subjects["base"]
	v.ID = "wrong"
	f.subjects["base"] = v
	if _, err := s.CreateSBOMDiff(t.Context(), a, in); !errors.Is(err, ErrNotFound) || f.reads != 0 {
		t.Fatal("subject drift accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateSBOMDiff(ctx, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := NewSBOMDiffCommands(SBOMDiffCommandConfig{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
}

func TestSBOMDiffCommandsRejectInvalidGeneratedEffectsAndProjectionBudget(t *testing.T) {
	for _, prefix := range []string{"sdiff", "depchg", "ace"} {
		t.Run(prefix, func(t *testing.T) {
			s, f, a, in := newSBOMDiffFixture(t)
			original := s.config.IDs
			s.config.IDs = application.IDGeneratorFunc(func(p string) string {
				if p == prefix {
					return ""
				}
				return original.NewID(p)
			})
			if v, err := s.CreateSBOMDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes) != 0 || len(f.audits) != 0 {
				t.Fatal("invalid generated effect committed", v, err)
			}
		})
	}
	for _, at := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		s, f, a, in := newSBOMDiffFixture(t)
		s.config.Clock = application.ClockFunc(func() time.Time { return at })
		if v, err := s.CreateSBOMDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes) != 0 {
			t.Fatal("invalid clock accepted", v, err)
		}
	}
	s, f, a, in := newSBOMDiffFixture(t)
	name := strings.Repeat("x", SBOMDiffStringByteLimit)
	f.components["base"] = make([]evidencedomain.SBOMComponent, 65)
	for i := range f.components["base"] {
		f.components["base"][i].Name = name
	}
	if v, err := s.CreateSBOMDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes) != 0 {
		t.Fatal("oversized aggregate projection accepted", v, err)
	}
}
