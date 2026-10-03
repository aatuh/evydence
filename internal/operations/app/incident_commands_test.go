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
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

type incidentCommandFixture struct {
	subjects            map[string]IncidentSubject
	incidents           []operationsdomain.Incident
	timeline            []operationsdomain.IncidentTimelineEvent
	tasks               []operationsdomain.RemediationTask
	audits              []application.AuditEvent
	fail                string
	reads, transactions int
}

func (f *incidentCommandFixture) ExecuteIncident(ctx context.Context, fn func(context.Context, IncidentTransaction) error) error {
	f.transactions++
	tx := *f
	if err := fn(ctx, &tx); err != nil {
		return err
	}
	if f.fail == "commit" {
		return ErrConflict
	}
	f.incidents, f.timeline, f.tasks, f.audits = tx.incidents, tx.timeline, tx.tasks, tx.audits
	f.reads = tx.reads
	return nil
}
func (f *incidentCommandFixture) ReadIncidentSubject(_ context.Context, tenant, kind, id string) (IncidentSubject, error) {
	f.reads++
	if f.fail == "read" {
		return IncidentSubject{}, ErrConflict
	}
	v, ok := f.subjects[kind+":"+id]
	if !ok || v.TenantID != tenant {
		return IncidentSubject{}, ErrNotFound
	}
	return v, nil
}
func (f *incidentCommandFixture) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if f.fail == "scope" || f.fail == "grant" && !r.ScopeOnly || f.fail == "evidence-grant" && r.Resources.ProjectID != "" {
		return application.ErrForbidden
	}
	return NewIncidentWriteAuthorizer().Authorize(ctx, a, r)
}
func (f *incidentCommandFixture) InsertIncident(_ context.Context, v operationsdomain.Incident) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.incidents = append(f.incidents, v)
	return nil
}
func (f *incidentCommandFixture) InsertIncidentTimelineEvent(_ context.Context, v operationsdomain.IncidentTimelineEvent) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.timeline = append(f.timeline, v)
	return nil
}
func (f *incidentCommandFixture) InsertRemediationTask(_ context.Context, v operationsdomain.RemediationTask) error {
	if f.fail == "insert" {
		return ErrConflict
	}
	f.tasks = append(f.tasks, v)
	return nil
}
func (f *incidentCommandFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.fail == "audit" {
		return application.AuditReceipt{}, ErrConflict
	}
	f.audits = append(f.audits, v)
	return application.AuditReceipt{}, nil
}
func incidentFixture(t *testing.T) (*IncidentCommands, *incidentCommandFixture, identitydomain.Actor, time.Time) {
	t.Helper()
	a := identitydomain.Actor{TenantID: "tenant", UserID: "human", Scopes: []string{"incident:write"}, ResourceGrants: []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: []string{"incident:write"}}}}
	now := time.Date(2026, 10, 3, 10, 20, 30, 123456789, time.FixedZone("offset", 3600))
	f := &incidentCommandFixture{subjects: map[string]IncidentSubject{
		"product:product":   {ID: "product", TenantID: "tenant", Type: "product", Resources: application.ResourceReferences{ProductID: "product"}},
		"release:release":   {ID: "release", TenantID: "tenant", Type: "release", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}},
		"incident:incident": {ID: "incident", TenantID: "tenant", Type: "incident", Resources: application.ResourceReferences{ProductID: "product", ReleaseID: "release"}},
		"evidence:evidence": {ID: "evidence", TenantID: "tenant", Type: "evidence", Resources: application.ResourceReferences{ProductID: "product", ProjectID: "project", ReleaseID: "release"}},
	}}
	c, err := NewIncidentCommands(IncidentCommandConfig{Transactions: f, Authorizer: f, Clock: application.ClockFunc(func() time.Time { return now }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "_new" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, a, now.UTC().Truncate(time.Microsecond)
}
func TestIncidentCommandsPreserveDefaultsReferencesAndAtomicAudits(t *testing.T) {
	c, f, a, now := incidentFixture(t)
	in := CreateIncidentInput{ProductID: " product ", ReleaseID: " release ", Title: " Incident ", Severity: " HIGH "}
	if err := c.AuthorizeCreateIncident(t.Context(), a, in); err != nil || len(f.incidents)+len(f.audits) != 0 {
		t.Fatal("replay guard wrote", err)
	}
	v, err := c.CreateIncident(t.Context(), a, in)
	if err != nil || v.ID != "inc_new" || v.ProductID != "product" || v.ReleaseID != "release" || v.Title != "Incident" || v.Severity != "high" || v.Status.String() != "open" || v.CreatedAt != now || v.OpenedAt != now || v.SchemaVersion != operationsdomain.IncidentSchemaVersion || len(f.incidents) != 1 || len(f.audits) != 1 {
		t.Fatal(v, err)
	}
	timeline := RecordIncidentTimelineInput{EventType: " contained ", Summary: " Containment noted ", EvidenceID: " evidence "}
	if err := c.AuthorizeRecordIncidentTimelineEvent(t.Context(), a, " incident ", timeline); err != nil || len(f.audits) != 1 {
		t.Fatal(err)
	}
	e, err := c.RecordIncidentTimelineEvent(t.Context(), a, " incident ", timeline)
	if err != nil || e.IncidentID != "incident" || e.EventType != "contained" || e.Summary != "Containment noted" || e.EvidenceID != "evidence" || e.OccurredAt != now || e.CreatedAt != now || e.SchemaVersion != operationsdomain.IncidentTimelineSchemaVersion || len(f.timeline) != 1 {
		t.Fatal(e, err)
	}
	due := now.Add(time.Hour)
	task := CreateRemediationTaskInput{IncidentID: " incident ", ReleaseID: " release ", Title: " Fix ", Owner: " Team ", EvidenceID: " evidence ", DueAt: &due}
	if err := c.AuthorizeCreateRemediationTask(t.Context(), a, task); err != nil || len(f.tasks) != 0 {
		t.Fatal(err)
	}
	r, err := c.CreateRemediationTask(t.Context(), a, task)
	if err != nil || r.Title != "Fix" || r.Owner != "Team" || r.Status != "open" || r.IncidentID != "incident" || r.ReleaseID != "release" || r.EvidenceID != "evidence" || r.CreatedAt != now || r.DueAt == nil || *r.DueAt != due || r.SchemaVersion != operationsdomain.RemediationTaskSchemaVersion || len(f.tasks) != 1 || len(f.audits) != 3 {
		t.Fatal(r, err)
	}
	*r.DueAt = now.Add(2 * time.Hour)
	due = now.Add(3 * time.Hour)
	if *f.tasks[0].DueAt != now.Add(time.Hour) {
		t.Fatal("task timestamp aliases caller/result")
	}
	for i, audit := range f.audits {
		if audit.ActorID != "human" || audit.ActorType != "human_user" || audit.TenantID != "tenant" || audit.OccurredAt != now || audit.EntryType != []string{"incident.created", "incident.timeline_recorded", "remediation_task.created"}[i] {
			t.Fatal(audit)
		}
	}
}
func TestIncidentCommandsRollbackAndRequireEveryResourceGrant(t *testing.T) {
	for _, kind := range []string{"incident", "timeline", "task"} {
		for _, failure := range []string{"scope", "grant", "read", "evidence-grant", "insert", "audit", "commit"} {
			if kind == "incident" && failure == "evidence-grant" {
				continue
			}
			t.Run(kind+"/"+failure, func(t *testing.T) {
				c, f, a, _ := incidentFixture(t)
				f.fail = failure
				var id string
				var err error
				switch kind {
				case "incident":
					v, e := c.CreateIncident(t.Context(), a, CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Incident", Severity: "high"})
					id, err = v.ID, e
				case "timeline":
					v, e := c.RecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "evidence"})
					id, err = v.ID, e
				case "task":
					v, e := c.CreateRemediationTask(t.Context(), a, CreateRemediationTaskInput{IncidentID: "incident", ReleaseID: "release", Title: "Fix", Owner: "Team", EvidenceID: "evidence"})
					id, err = v.ID, e
				}
				if err == nil || id != "" || len(f.incidents)+len(f.timeline)+len(f.tasks)+len(f.audits) != 0 {
					t.Fatal("failed command leaked effects", id, err)
				}
				if failure == "scope" && f.transactions != 0 {
					t.Fatal("scope denial reached reader")
				}
			})
		}
	}
	c, f, a, _ := incidentFixture(t)
	f.subjects["release:other"] = IncidentSubject{ID: "other", TenantID: "tenant", Type: "release", Resources: application.ResourceReferences{ProductID: "other-product", ReleaseID: "other"}}
	if _, err := c.CreateRemediationTask(t.Context(), a, CreateRemediationTaskInput{IncidentID: "incident", ReleaseID: "other", Title: "Fix", Owner: "Team"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("incident grant covered unrelated release", err)
	}
	a.ResourceGrants = append(a.ResourceGrants, identitydomain.ResourceGrant{ResourceType: "release", ResourceID: "other", Scopes: []string{"incident:write"}})
	if _, err := c.CreateRemediationTask(t.Context(), a, CreateRemediationTaskInput{IncidentID: "incident", ReleaseID: "other", Title: "Fix", Owner: "Team"}); err != nil {
		t.Fatal("authorized separate references were coupled", err)
	}
}
func TestIncidentCommandsRejectInvalidInputAndForeignSubject(t *testing.T) {
	for _, in := range []CreateIncidentInput{{ProductID: "product", Title: "", Severity: "high"}, {ProductID: "product", Title: "Incident", Severity: "info"}, {ProductID: "bad\x00", Title: "Incident", Severity: "high"}, {ProductID: "product", Title: "\xff", Severity: "high"}, {ProductID: strings.Repeat("p", 1025), Title: "Incident", Severity: "high"}, {ProductID: "product", Title: "Incident", Severity: "high", OpenedAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}} {
		c, f, a, _ := incidentFixture(t)
		if _, err := c.CreateIncident(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal(in, err)
		}
	}
	for _, kind := range []string{"product", "release", "incident", "evidence"} {
		for _, change := range []func(*IncidentSubject){func(v *IncidentSubject) { v.TenantID = "other" }, func(v *IncidentSubject) { v.ID = "other" }, func(v *IncidentSubject) { v.Type = "other" }, func(v *IncidentSubject) { v.Resources.ProductID = "" }} {
			c, f, a, _ := incidentFixture(t)
			v := f.subjects[kind+":"+kind]
			change(&v)
			f.subjects[kind+":"+kind] = v
			var err error
			if kind == "product" || kind == "release" {
				_, err = c.CreateIncident(t.Context(), a, CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Incident", Severity: "high"})
			} else {
				_, err = c.RecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "evidence"})
			}
			// A tenant-scoped evidence record is valid without a product only
			// when all narrower coordinates are absent; this fixture has them.
			if !errors.Is(err, ErrNotFound) || len(f.incidents)+len(f.timeline)+len(f.audits) != 0 {
				t.Fatal(kind, v, err)
			}
		}
	}
	if _, err := NewIncidentCommands(IncidentCommandConfig{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	c, f, a, _ := incidentFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.CreateIncident(ctx, a, CreateIncidentInput{}); !errors.Is(err, context.Canceled) || f.transactions != 0 {
		t.Fatal(err)
	}
	var missingContext context.Context
	if _, err := c.CreateIncident(missingContext, a, CreateIncidentInput{}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := c.RecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: " ", EvidenceID: "evidence"}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := c.CreateRemediationTask(t.Context(), a, CreateRemediationTaskInput{Title: "Fix", Owner: "Team"}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if _, err := c.CreateRemediationTask(t.Context(), a, CreateRemediationTaskInput{IncidentID: "incident", Title: "Fix", Owner: "Team", DueAt: &time.Time{}}); !errors.Is(err, ErrValidation) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.audits, []application.AuditEvent(nil)) {
		t.Fatal("bad command audited")
	}
}

func TestIncidentCommandsPreserveReleaseOnlyGrantsAndTenantEvidence(t *testing.T) {
	c, f, a, _ := incidentFixture(t)
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "release", ResourceID: "release", Scopes: []string{"incident:write"}}}
	if _, err := c.CreateIncident(t.Context(), a, CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Incident", Severity: "high"}); err != nil {
		t.Fatal("release grant denied incident creation", err)
	}
	if _, err := c.RecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "evidence"}); err != nil {
		t.Fatal("release grant denied references", err)
	}
	f.subjects["evidence:detached"] = IncidentSubject{ID: "detached", TenantID: "tenant", Type: "evidence"}
	if err := c.AuthorizeRecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "detached"}); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("release grant covered tenant-only evidence", err)
	}
	a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "tenant", ResourceID: "tenant", Scopes: []string{"incident:write"}}}
	if err := c.AuthorizeRecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted", EvidenceID: "detached"}); err != nil {
		t.Fatal(err)
	}
	before := len(f.incidents)
	f.subjects["release:release"] = IncidentSubject{ID: "release", TenantID: "tenant", Type: "release", Resources: application.ResourceReferences{ProductID: "other-product", ReleaseID: "release"}}
	if _, err := c.CreateIncident(t.Context(), a, CreateIncidentInput{ProductID: "product", ReleaseID: "release", Title: "Incident", Severity: "high"}); !errors.Is(err, ErrNotFound) || len(f.incidents) != before {
		t.Fatal("mismatched creation parent", err)
	}
}

func TestIncidentCommandsRejectBadClockIDsAndDirectInputBoundaries(t *testing.T) {
	for _, kind := range []string{"incident", "timeline", "task"} {
		for _, failure := range []string{"clock", "id", "audit-id"} {
			t.Run(kind+"/"+failure, func(t *testing.T) {
				c, f, a, _ := incidentFixture(t)
				if failure == "clock" {
					c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
				} else {
					c.config.IDs = application.IDGeneratorFunc(func(prefix string) string {
						if failure == "id" || prefix == "ace" {
							return " "
						}
						return prefix + "_new"
					})
				}
				var err error
				switch kind {
				case "incident":
					_, err = c.CreateIncident(t.Context(), a, CreateIncidentInput{ProductID: "product", Title: "Incident", Severity: "high"})
				case "timeline":
					_, err = c.RecordIncidentTimelineEvent(t.Context(), a, "incident", RecordIncidentTimelineInput{EventType: "noted", Summary: "Noted"})
				case "task":
					_, err = c.CreateRemediationTask(t.Context(), a, CreateRemediationTaskInput{IncidentID: "incident", Title: "Fix", Owner: "Team"})
				}
				if !errors.Is(err, ErrValidation) || len(f.incidents)+len(f.timeline)+len(f.tasks)+len(f.audits) != 0 {
					t.Fatal("invalid generated metadata persisted", err)
				}
			})
		}
	}
	c, f, a, _ := incidentFixture(t)
	badTime := time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("offset", 3600))
	if _, err := c.CreateIncident(t.Context(), a, CreateIncidentInput{ProductID: "product", Title: "Incident", Severity: "high", OpenedAt: badTime}); !errors.Is(err, ErrValidation) {
		t.Fatal("UTC year overflow", err)
	}
	for _, in := range []RecordIncidentTimelineInput{{EventType: "noted", Summary: strings.Repeat("x", 65537)}, {EventType: "\xff", Summary: "Noted"}, {EventType: "noted", Summary: "Noted", EvidenceID: strings.Repeat("x", 1025)}, {EventType: "noted", Summary: "Noted", OccurredAt: badTime}} {
		if _, err := c.RecordIncidentTimelineEvent(t.Context(), a, "incident", in); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	for _, in := range []CreateRemediationTaskInput{{IncidentID: "incident", Title: "Fix", Owner: "bad\x00"}, {ReleaseID: strings.Repeat("r", 1025), Title: "Fix", Owner: "Team"}, {IncidentID: "incident", Title: "Fix", Owner: "Team", DueAt: &badTime}} {
		if _, err := c.CreateRemediationTask(t.Context(), a, in); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
	if f.transactions != 0 {
		t.Fatal("invalid direct input reached transaction")
	}
}
