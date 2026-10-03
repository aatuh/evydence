package app

import (
	"context"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

const ScopeIncidentWrite = "incident:write"

// IncidentSubject contains only current tenant/parent coordinates. Readers
// must validate and lock their coherent ownership through the caller's commit.
type IncidentSubject struct {
	ID, TenantID, Type string
	Resources          application.ResourceReferences
}
type IncidentReader interface {
	ReadIncidentSubject(context.Context, string, string, string) (IncidentSubject, error)
}
type IncidentTransaction interface {
	IncidentReader
	application.Authorizer
	application.AuditAppender
	InsertIncident(context.Context, operationsdomain.Incident) error
	InsertIncidentTimelineEvent(context.Context, operationsdomain.IncidentTimelineEvent) error
	InsertRemediationTask(context.Context, operationsdomain.RemediationTask) error
}
type IncidentTransactions interface {
	ExecuteIncident(context.Context, func(context.Context, IncidentTransaction) error) error
}
type IncidentCommandConfig struct {
	Transactions IncidentTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type IncidentCommands struct{ config IncidentCommandConfig }
type CreateIncidentInput struct {
	ProductID, ReleaseID, Title, Severity string
	OpenedAt                              time.Time
}
type RecordIncidentTimelineInput struct {
	EventType, Summary, EvidenceID string
	OccurredAt                     time.Time
}
type CreateRemediationTaskInput struct {
	IncidentID, ReleaseID, Title, Owner, EvidenceID string
	DueAt                                           *time.Time
}

func NewIncidentCommands(c IncidentCommandConfig) (*IncidentCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &IncidentCommands{c}, nil
}
func incidentContextError(ctx context.Context) error {
	if ctx == nil {
		return ErrValidation
	}
	return ctx.Err()
}
func incidentActor(a identitydomain.Actor) (string, string) {
	if a.CollectorID != "" {
		return "collector", a.CollectorID
	}
	if a.UserID != "" {
		return "human_user", a.UserID
	}
	return "api_key", a.KeyID
}
func (c *IncidentCommands) prepareActor(ctx context.Context, a identitydomain.Actor) error {
	if c == nil {
		return ErrValidation
	}
	if err := incidentContextError(ctx); err != nil {
		return err
	}
	if err := c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeIncidentWrite, ScopeOnly: true}); err != nil {
		return err
	}
	_, id := incidentActor(a)
	if !validEnvironmentText(a.TenantID, 1024) || strings.TrimSpace(a.TenantID) != a.TenantID || !validEnvironmentText(id, 1024) || strings.TrimSpace(id) != id {
		return ErrValidation
	}
	return nil
}
func incidentOptionalText(v string, limit int) bool { return v == "" || validEnvironmentText(v, limit) }
func validIncidentID(v string) bool {
	return validEnvironmentText(v, 1024) && strings.TrimSpace(v) == v
}
func incidentTime(v time.Time) bool {
	v = v.UTC()
	return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999
}
func (c *IncidentCommands) prepareIncident(ctx context.Context, a identitydomain.Actor, in CreateIncidentInput) (CreateIncidentInput, error) {
	if err := c.prepareActor(ctx, a); err != nil {
		return in, err
	}
	if !incidentOptionalText(in.ProductID, 1024) || !incidentOptionalText(in.ReleaseID, 1024) || !incidentOptionalText(in.Title, 65536) || !incidentOptionalText(in.Severity, 128) {
		return in, ErrValidation
	}
	in.ProductID, in.ReleaseID, in.Title, in.Severity = strings.TrimSpace(in.ProductID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.Title), strings.ToLower(strings.TrimSpace(in.Severity))
	if in.ProductID == "" || in.Title == "" || !in.OpenedAt.IsZero() && !incidentTime(in.OpenedAt) {
		return in, ErrValidation
	}
	switch in.Severity {
	case "low", "medium", "high", "critical":
	default:
		return in, ErrValidation
	}
	return in, nil
}
func (c *IncidentCommands) prepareTimeline(ctx context.Context, a identitydomain.Actor, id string, in RecordIncidentTimelineInput) (string, RecordIncidentTimelineInput, error) {
	if err := c.prepareActor(ctx, a); err != nil {
		return id, in, err
	}
	if !validEnvironmentText(id, 1024) || !incidentOptionalText(in.EvidenceID, 1024) || !incidentOptionalText(in.EventType, 65536) || !incidentOptionalText(in.Summary, 65536) {
		return id, in, ErrValidation
	}
	id, in.EventType, in.Summary, in.EvidenceID = strings.TrimSpace(id), strings.TrimSpace(in.EventType), strings.TrimSpace(in.Summary), strings.TrimSpace(in.EvidenceID)
	if id == "" || in.EventType == "" || in.Summary == "" || !in.OccurredAt.IsZero() && !incidentTime(in.OccurredAt) {
		return id, in, ErrValidation
	}
	return id, in, nil
}
func (c *IncidentCommands) prepareTask(ctx context.Context, a identitydomain.Actor, in CreateRemediationTaskInput) (CreateRemediationTaskInput, error) {
	if err := c.prepareActor(ctx, a); err != nil {
		return in, err
	}
	for _, id := range []string{in.IncidentID, in.ReleaseID, in.EvidenceID} {
		if !incidentOptionalText(id, 1024) {
			return in, ErrValidation
		}
	}
	if !incidentOptionalText(in.Title, 65536) || !incidentOptionalText(in.Owner, 65536) {
		return in, ErrValidation
	}
	in.IncidentID, in.ReleaseID, in.EvidenceID, in.Title, in.Owner = strings.TrimSpace(in.IncidentID), strings.TrimSpace(in.ReleaseID), strings.TrimSpace(in.EvidenceID), strings.TrimSpace(in.Title), strings.TrimSpace(in.Owner)
	if in.Title == "" || in.Owner == "" || in.IncidentID == "" && in.ReleaseID == "" || in.DueAt != nil && !incidentTime(*in.DueAt) {
		return in, ErrValidation
	}
	in.DueAt = incidentTimeCopy(in.DueAt)
	return in, nil
}
func incidentTimeCopy(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	copy := v.UTC().Truncate(time.Microsecond)
	return &copy
}
func validIncidentSubject(v IncidentSubject, tenant, kind, id string) bool {
	if v.ID != id || v.TenantID != tenant || v.Type != kind {
		return false
	}
	r := v.Resources
	if r != (application.ResourceReferences{ProductID: r.ProductID, ProjectID: r.ProjectID, ReleaseID: r.ReleaseID, BuildID: r.BuildID, DeploymentID: r.DeploymentID}) {
		return false
	}
	for _, value := range []string{r.ProductID, r.ProjectID, r.ReleaseID, r.BuildID, r.DeploymentID} {
		if !incidentOptionalText(value, 1024) || strings.TrimSpace(value) != value {
			return false
		}
	}
	if r.ProductID == "" && r != (application.ResourceReferences{}) {
		return false
	}
	switch kind {
	case "product":
		return r == (application.ResourceReferences{ProductID: id})
	case "release":
		return r.ProductID != "" && r.ReleaseID == id && r == (application.ResourceReferences{ProductID: r.ProductID, ReleaseID: id})
	case "incident":
		return r.ProductID != "" && r == (application.ResourceReferences{ProductID: r.ProductID, ReleaseID: r.ReleaseID})
	case "evidence":
		return true
	default:
		return false
	}
}
func authorizeIncidentSubject(ctx context.Context, tx IncidentTransaction, a identitydomain.Actor, kind, id string) (IncidentSubject, error) {
	v, err := tx.ReadIncidentSubject(ctx, a.TenantID, kind, id)
	if err != nil {
		return IncidentSubject{}, err
	}
	if !validIncidentSubject(v, a.TenantID, kind, id) {
		return IncidentSubject{}, ErrNotFound
	}
	err = tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeIncidentWrite, Resources: v.Resources, TenantWide: v.Resources == (application.ResourceReferences{})})
	return v, err
}
func authorizeIncidentCreation(ctx context.Context, tx IncidentTransaction, a identitydomain.Actor, in CreateIncidentInput) error {
	p, err := tx.ReadIncidentSubject(ctx, a.TenantID, "product", in.ProductID)
	if err != nil {
		return err
	}
	if !validIncidentSubject(p, a.TenantID, "product", in.ProductID) {
		return ErrNotFound
	}
	refs := p.Resources
	if in.ReleaseID != "" {
		v, err := tx.ReadIncidentSubject(ctx, a.TenantID, "release", in.ReleaseID)
		if err != nil {
			return err
		}
		if !validIncidentSubject(v, a.TenantID, "release", in.ReleaseID) {
			return ErrNotFound
		}
		if v.Resources.ProductID != in.ProductID {
			return ErrNotFound
		}
		refs = v.Resources
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeIncidentWrite, Resources: refs})
}
func authorizeIncidentTimeline(ctx context.Context, tx IncidentTransaction, a identitydomain.Actor, id string, in RecordIncidentTimelineInput) error {
	if _, err := authorizeIncidentSubject(ctx, tx, a, "incident", id); err != nil {
		return err
	}
	if in.EvidenceID != "" {
		_, err := authorizeIncidentSubject(ctx, tx, a, "evidence", in.EvidenceID)
		return err
	}
	return nil
}
func authorizeRemediationTask(ctx context.Context, tx IncidentTransaction, a identitydomain.Actor, in CreateRemediationTaskInput) error {
	// Each optional reference is independently authorized. Existing clients may
	// deliberately link an incident and remediation release in different scopes.
	for _, ref := range []struct{ kind, id string }{{"incident", in.IncidentID}, {"release", in.ReleaseID}, {"evidence", in.EvidenceID}} {
		if ref.id != "" {
			if _, err := authorizeIncidentSubject(ctx, tx, a, ref.kind, ref.id); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *IncidentCommands) execute(ctx context.Context, a identitydomain.Actor, fn func(context.Context, IncidentTransaction) error) error {
	return c.config.Transactions.ExecuteIncident(ctx, func(ctx context.Context, tx IncidentTransaction) error {
		if err := incidentContextError(ctx); err != nil {
			return err
		}
		if tx == nil {
			return ErrValidation
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeIncidentWrite, ScopeOnly: true}); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return incidentContextError(ctx)
	})
}

// Guards run in the same durable unit of work before reservation or replay and
// never write records, audits, or idempotency responses.
func (c *IncidentCommands) AuthorizeCreateIncident(ctx context.Context, a identitydomain.Actor, in CreateIncidentInput) error {
	in, err := c.prepareIncident(ctx, a, in)
	if err != nil {
		return err
	}
	return c.execute(ctx, a, func(ctx context.Context, tx IncidentTransaction) error {
		return authorizeIncidentCreation(ctx, tx, a, in)
	})
}
func (c *IncidentCommands) AuthorizeRecordIncidentTimelineEvent(ctx context.Context, a identitydomain.Actor, id string, in RecordIncidentTimelineInput) error {
	id, in, err := c.prepareTimeline(ctx, a, id, in)
	if err != nil {
		return err
	}
	return c.execute(ctx, a, func(ctx context.Context, tx IncidentTransaction) error {
		return authorizeIncidentTimeline(ctx, tx, a, id, in)
	})
}
func (c *IncidentCommands) AuthorizeCreateRemediationTask(ctx context.Context, a identitydomain.Actor, in CreateRemediationTaskInput) error {
	in, err := c.prepareTask(ctx, a, in)
	if err != nil {
		return err
	}
	return c.execute(ctx, a, func(ctx context.Context, tx IncidentTransaction) error {
		return authorizeRemediationTask(ctx, tx, a, in)
	})
}
func (c *IncidentCommands) appendAudit(ctx context.Context, tx IncidentTransaction, a identitydomain.Actor, at time.Time, action, kind, subject string) error {
	actorType, actorID := incidentActor(a)
	id := c.config.IDs.NewID("ace")
	if !validIncidentID(id) {
		return ErrValidation
	}
	if err := incidentContextError(ctx); err != nil {
		return err
	}
	_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: id, TenantID: a.TenantID, EntryType: action, SubjectType: kind, SubjectID: subject, ActorType: actorType, ActorID: actorID, OccurredAt: at})
	return err
}
func (c *IncidentCommands) CreateIncident(ctx context.Context, a identitydomain.Actor, in CreateIncidentInput) (operationsdomain.Incident, error) {
	in, err := c.prepareIncident(ctx, a, in)
	if err != nil {
		return operationsdomain.Incident{}, err
	}
	var out operationsdomain.Incident
	err = c.execute(ctx, a, func(ctx context.Context, tx IncidentTransaction) error {
		if err := authorizeIncidentCreation(ctx, tx, a, in); err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !incidentTime(now) {
			return ErrValidation
		}
		opened := in.OpenedAt.UTC().Truncate(time.Microsecond)
		if opened.IsZero() {
			opened = now
		}
		status, err := operationsdomain.ParseIncidentStatus("open")
		if err != nil {
			return ErrValidation
		}
		out = operationsdomain.Incident{ID: c.config.IDs.NewID("inc"), TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Title: in.Title, Severity: in.Severity, Status: status, OpenedAt: opened, SchemaVersion: operationsdomain.IncidentSchemaVersion, CreatedAt: now}
		if !validIncidentID(out.ID) {
			return ErrValidation
		}
		if err := incidentContextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertIncident(ctx, out); err != nil {
			return err
		}
		return c.appendAudit(ctx, tx, a, now, "incident.created", "incident", out.ID)
	})
	if err != nil {
		return operationsdomain.Incident{}, err
	}
	return out, nil
}
func (c *IncidentCommands) RecordIncidentTimelineEvent(ctx context.Context, a identitydomain.Actor, id string, in RecordIncidentTimelineInput) (operationsdomain.IncidentTimelineEvent, error) {
	id, in, err := c.prepareTimeline(ctx, a, id, in)
	if err != nil {
		return operationsdomain.IncidentTimelineEvent{}, err
	}
	var out operationsdomain.IncidentTimelineEvent
	err = c.execute(ctx, a, func(ctx context.Context, tx IncidentTransaction) error {
		if err := authorizeIncidentTimeline(ctx, tx, a, id, in); err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !incidentTime(now) {
			return ErrValidation
		}
		occurred := in.OccurredAt.UTC().Truncate(time.Microsecond)
		if occurred.IsZero() {
			occurred = now
		}
		out = operationsdomain.IncidentTimelineEvent{ID: c.config.IDs.NewID("it"), TenantID: a.TenantID, IncidentID: id, EventType: in.EventType, Summary: in.Summary, EvidenceID: in.EvidenceID, OccurredAt: occurred, SchemaVersion: operationsdomain.IncidentTimelineSchemaVersion, CreatedAt: now}
		if !validIncidentID(out.ID) {
			return ErrValidation
		}
		if err := incidentContextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertIncidentTimelineEvent(ctx, out); err != nil {
			return err
		}
		return c.appendAudit(ctx, tx, a, now, "incident.timeline_recorded", "incident", id)
	})
	if err != nil {
		return operationsdomain.IncidentTimelineEvent{}, err
	}
	return out, nil
}
func (c *IncidentCommands) CreateRemediationTask(ctx context.Context, a identitydomain.Actor, in CreateRemediationTaskInput) (operationsdomain.RemediationTask, error) {
	in, err := c.prepareTask(ctx, a, in)
	if err != nil {
		return operationsdomain.RemediationTask{}, err
	}
	var out operationsdomain.RemediationTask
	err = c.execute(ctx, a, func(ctx context.Context, tx IncidentTransaction) error {
		if err := authorizeRemediationTask(ctx, tx, a, in); err != nil {
			return err
		}
		now := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !incidentTime(now) {
			return ErrValidation
		}
		out = operationsdomain.RemediationTask{ID: c.config.IDs.NewID("rt"), TenantID: a.TenantID, IncidentID: in.IncidentID, ReleaseID: in.ReleaseID, EvidenceID: in.EvidenceID, Title: in.Title, Owner: in.Owner, Status: "open", DueAt: incidentTimeCopy(in.DueAt), SchemaVersion: operationsdomain.RemediationTaskSchemaVersion, CreatedAt: now}
		if !validIncidentID(out.ID) {
			return ErrValidation
		}
		if err := incidentContextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertRemediationTask(ctx, out); err != nil {
			return err
		}
		return c.appendAudit(ctx, tx, a, now, "remediation_task.created", "remediation_task", out.ID)
	})
	if err != nil {
		return operationsdomain.RemediationTask{}, err
	}
	out.DueAt = incidentTimeCopy(out.DueAt)
	return out, nil
}
