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

type contractDiffFixture struct {
	subjects  map[string]ContractDiffSubject
	contracts map[string]evidencedomain.OpenAPIContract
	releases  map[string]ContractDiffRelease
	writes    []evidencedomain.ContractDiff
	audits    []application.AuditEvent
	reads     int
	fail      string
}

func (f *contractDiffFixture) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeEvidenceRead || f.fail == "authorization" && !r.ScopeOnly {
		return application.ErrForbidden
	}
	return nil
}
func (f *contractDiffFixture) ReadContractDiffSubject(_ context.Context, tenant, id string) (ContractDiffSubject, error) {
	v, ok := f.subjects[id]
	if !ok || v.TenantID != tenant {
		return ContractDiffSubject{}, ErrNotFound
	}
	return v, nil
}
func (f *contractDiffFixture) ReadContractDiffRelease(_ context.Context, tenant, id string) (ContractDiffRelease, error) {
	v, ok := f.releases[id]
	if !ok || v.TenantID != tenant {
		return ContractDiffRelease{}, ErrNotFound
	}
	return v, nil
}
func (f *contractDiffFixture) ReadContractDiffProjection(_ context.Context, _, id string) (evidencedomain.OpenAPIContract, error) {
	f.reads++
	if f.fail == "read" {
		return evidencedomain.OpenAPIContract{}, errors.New("read failure")
	}
	return cloneOpenAPIContract(f.contracts[id]), nil
}
func (f *contractDiffFixture) InsertContractDiff(_ context.Context, v evidencedomain.ContractDiff) error {
	if f.fail == "insert" {
		return errors.New("insert failure")
	}
	f.writes = append(f.writes, v)
	return nil
}
func (f *contractDiffFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, errors.New("audit failure")
	}
	f.audits = append(f.audits, v)
	return application.AuditReceipt{ID: v.ID}, nil
}
func (f *contractDiffFixture) ExecuteContractDiff(ctx context.Context, fn func(context.Context, ContractDiffTransaction) error) error {
	w, a := len(f.writes), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.fail == "commit" {
		err = errors.New("commit failure")
	}
	if err != nil {
		f.writes = f.writes[:w]
		f.audits = f.audits[:a]
	}
	return err
}
func newContractDiffFixture(t *testing.T) (*ContractDiffCommands, *contractDiffFixture, identitydomain.Actor, CreateContractDiffInput) {
	t.Helper()
	f := &contractDiffFixture{subjects: map[string]ContractDiffSubject{}, contracts: map[string]evidencedomain.OpenAPIContract{}, releases: map[string]ContractDiffRelease{"requested": {ID: "requested", TenantID: "tenant", ProductID: "product"}}}
	for i, id := range []string{"base", "target"} {
		f.subjects[id] = ContractDiffSubject{ID: id, TenantID: "tenant", ProductID: "product", ReleaseID: id + "-release", EvidenceID: "ev-" + id}
		f.contracts[id] = evidencedomain.OpenAPIContract{ID: id, TenantID: "tenant", ProductID: "product", ReleaseID: id + "-release", EvidenceID: "ev-" + id, Hash: "sha256:" + strings.Repeat(string(rune('a'+i)), 64), PathCount: 1, Operations: []evidencedomain.OpenAPIOperation{{Path: "/a", Method: "GET", ResponseStatuses: []string{"200"}}}}
	}
	i := 0
	s, err := NewContractDiffCommands(ContractDiffCommandConfig{Authorizer: f, Transactions: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 3, 1, 2, 3, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(p string) string { i++; return p + strings.Repeat("x", i) })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{ScopeEvidenceRead}}, CreateContractDiffInput{BaseContractID: " base ", TargetContractID: "target", ReleaseID: "requested"}
}
func TestContractDiffCommandsPreserveSemanticsAndAtomicEffects(t *testing.T) {
	s, f, a, in := newContractDiffFixture(t)
	if err := s.AuthorizeCreateContractDiff(t.Context(), a, in); err != nil || f.reads != 0 || len(f.writes) != 0 {
		t.Fatal("replay authorization read operations", err)
	}
	v := f.contracts["base"]
	v.Operations = append(v.Operations, evidencedomain.OpenAPIOperation{Path: "/gone", Method: "post"})
	f.contracts["base"] = v
	v = f.contracts["target"]
	v.Operations = []evidencedomain.OpenAPIOperation{{Path: "/a", Method: " get ", Deprecated: true, RequestBodyRequired: true, RequiredRequestFields: []string{" z ", "a"}, ResponseStatuses: []string{"201"}}, {Path: "/new", Method: "put"}}
	f.contracts["target"] = v
	diff, err := s.CreateContractDiff(t.Context(), a, in)
	if err != nil || diff.ID == "" || diff.TenantID != "tenant" || diff.BaseContractID != "base" || diff.TargetContractID != "target" || diff.ProductID != "product" || diff.ReleaseID != "requested" || diff.Result != "breaking" || diff.SchemaVersion != evidencedomain.ContractDiffSchemaVersion || diff.CreatedAt.Nanosecond() != 123456000 {
		t.Fatal(diff, err)
	}
	breaking := []string{"operation removed: POST /gone", "request body became required: GET /a", "required request fields added for GET /a: a,z", "response statuses removed for GET /a: 200"}
	nonBreaking := []string{"operation added: PUT /new", "operation deprecated: GET /a", "response statuses added for GET /a: 201"}
	if !reflect.DeepEqual(diff.BreakingChanges, breaking) || !reflect.DeepEqual(diff.NonBreakingChanges, nonBreaking) || len(f.writes) != 1 || len(f.audits) != 1 {
		t.Fatal(diff, f.audits)
	}
	au := f.audits[0]
	if au.EntryType != "openapi_contract.diffed" || au.SubjectType != "contract_diff" || au.SubjectID != diff.ID || au.ActorID != "human" || au.ActorType != "human_user" || au.OccurredAt != diff.CreatedAt {
		t.Fatal(au)
	}
	diff.BreakingChanges[0] = "mutated"
	if f.writes[0].BreakingChanges[0] != breaking[0] {
		t.Fatal("returned changes alias persisted diff")
	}
}
func TestContractDiffCommandsHashFallbackAndDuplicateCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name          string
		mutate        func(*contractDiffFixture)
		result        string
		breaking, non []string
	}{
		{"equal hash", func(f *contractDiffFixture) {
			v := f.contracts["target"]
			v.Hash = f.contracts["base"].Hash
			v.Operations = nil
			f.contracts["target"] = v
		}, "unchanged", nil, nil},
		{"fewer paths", func(f *contractDiffFixture) {
			v := f.contracts["target"]
			v.Operations = nil
			v.PathCount = 0
			f.contracts["target"] = v
		}, "breaking", []string{"target contract has fewer paths than base contract"}, nil},
		{"more paths", func(f *contractDiffFixture) {
			v := f.contracts["target"]
			v.Operations = nil
			v.PathCount = 2
			f.contracts["target"] = v
		}, "changed", nil, []string{"target contract has additional paths"}},
		{"last operation wins", func(f *contractDiffFixture) {
			v := f.contracts["target"]
			v.Operations = append([]evidencedomain.OpenAPIOperation{{Path: "/a", Method: "GET", RequestBodyRequired: true}}, v.Operations...)
			f.contracts["target"] = v
		}, "changed", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, a, in := newContractDiffFixture(t)
			tc.mutate(f)
			v, err := s.CreateContractDiff(t.Context(), a, in)
			if err != nil || v.Result != tc.result || !reflect.DeepEqual(v.BreakingChanges, tc.breaking) || !reflect.DeepEqual(v.NonBreakingChanges, tc.non) {
				t.Fatal(v, err)
			}
		})
	}
}
func TestContractDiffCommandsRejectInvalidInputsAndRollback(t *testing.T) {
	for _, stage := range []string{"authorization", "read", "insert", "audit", "commit"} {
		t.Run(stage, func(t *testing.T) {
			s, f, a, in := newContractDiffFixture(t)
			f.fail = stage
			v, err := s.CreateContractDiff(t.Context(), a, in)
			if err == nil || v.ID != "" || len(f.writes) != 0 || len(f.audits) != 0 {
				t.Fatal("partial effects", v, err)
			}
			if stage == "authorization" && f.reads != 0 {
				t.Fatal("denied operation read")
			}
		})
	}
	for _, bad := range []CreateContractDiffInput{{}, {BaseContractID: "base", TargetContractID: "base"}, {BaseContractID: "base\x00", TargetContractID: "target"}, {BaseContractID: strings.Repeat("x", 1025), TargetContractID: "target"}} {
		s, f, a, _ := newContractDiffFixture(t)
		if v, err := s.CreateContractDiff(t.Context(), a, bad); !errors.Is(err, ErrValidation) || v.ID != "" || f.reads != 0 {
			t.Fatal("invalid input reached operations", err)
		}
	}
	for _, field := range []string{"tenant", "product", "evidence", "release", "projection"} {
		t.Run(field, func(t *testing.T) {
			s, f, a, in := newContractDiffFixture(t)
			v := f.subjects["target"]
			switch field {
			case "tenant":
				v.TenantID = "other"
			case "product":
				v.ProductID = "other"
			case "evidence":
				v.EvidenceID = ""
			case "release":
				f.releases["requested"] = ContractDiffRelease{ID: "requested", TenantID: "tenant", ProductID: "other"}
			case "projection":
				c := f.contracts["target"]
				c.ProductID = "other"
				f.contracts["target"] = c
			}
			f.subjects["target"] = v
			if got, err := s.CreateContractDiff(t.Context(), a, in); !errors.Is(err, ErrNotFound) || got.ID != "" || len(f.writes) != 0 {
				t.Fatal("foreign/drift accepted", got, err)
			}
			if field != "projection" && f.reads != 0 {
				t.Fatal("foreign subject operations fetched")
			}
		})
	}
	for _, mutate := range []func(*evidencedomain.OpenAPIContract){func(v *evidencedomain.OpenAPIContract) { v.Hash = "sha256:bad" }, func(v *evidencedomain.OpenAPIContract) { v.PathCount = -1 }, func(v *evidencedomain.OpenAPIContract) { v.Operations[0].Path = "bad\x00" }, func(v *evidencedomain.OpenAPIContract) {
		v.Operations[0].RequiredRequestFields = []string{string([]byte{255})}
	}, func(v *evidencedomain.OpenAPIContract) {
		v.Operations[0].Path = strings.Repeat("x", ContractDiffProjectionByteLimit+1)
	}} {
		s, f, a, in := newContractDiffFixture(t)
		v := f.contracts["target"]
		mutate(&v)
		f.contracts["target"] = v
		if got, err := s.CreateContractDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || got.ID != "" || len(f.writes) != 0 {
			t.Fatal("malformed projection accepted", err)
		}
	}
	for _, prefix := range []string{"cdiff", "ace"} {
		s, f, a, in := newContractDiffFixture(t)
		s.config.IDs = application.IDGeneratorFunc(func(p string) string {
			if p == prefix {
				return ""
			}
			return p
		})
		if v, err := s.CreateContractDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || v.ID != "" || len(f.writes) != 0 || len(f.audits) != 0 {
			t.Fatal("bad generated ID committed", err)
		}
	}
	for _, at := range []time.Time{{}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		s, f, a, in := newContractDiffFixture(t)
		s.config.Clock = application.ClockFunc(func() time.Time { return at })
		if _, err := s.CreateContractDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || len(f.writes) != 0 {
			t.Fatal("invalid time accepted", err)
		}
	}
	s, _, a, in := newContractDiffFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateContractDiff(ctx, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := NewContractDiffCommands(ContractDiffCommandConfig{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
}

func TestContractDiffCommandsBoundAggregateOperationsAndSampleTimeAfterReads(t *testing.T) {
	s, f, a, in := newContractDiffFixture(t)
	s.config.Clock = application.ClockFunc(func() time.Time {
		if f.reads != 2 {
			t.Fatal("time sampled before authoritative reads")
		}
		return time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC)
	})
	if _, err := s.CreateContractDiff(t.Context(), a, in); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"strings", "structure", "nested"} {
		t.Run(kind, func(t *testing.T) {
			s, f, a, in := newContractDiffFixture(t)
			v := f.contracts["target"]
			switch kind {
			case "strings":
				v.Operations[0].RequiredRequestFields = []string{strings.Repeat("a", 16<<20), strings.Repeat("b", 16<<20)}
			case "structure":
				v.Operations = make([]evidencedomain.OpenAPIOperation, ContractDiffProjectionByteLimit/64+1)
				for i := range v.Operations {
					v.Operations[i] = evidencedomain.OpenAPIOperation{Path: "/a", Method: "GET"}
				}
			case "nested":
				v.Operations[0].ResponseStatuses = make([]string, ContractDiffProjectionByteLimit/8+1)
			}
			f.contracts["target"] = v
			if got, err := s.CreateContractDiff(t.Context(), a, in); !errors.Is(err, ErrValidation) || got.ID != "" || len(f.writes) != 0 || len(f.audits) != 0 {
				t.Fatal("aggregate projection budget escaped", err)
			}
		})
	}
}
