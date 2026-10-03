// Package application contains the small, transport-neutral command
// primitives shared by bounded-context application services.
package application

import (
	"context"
	"errors"
	"time"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Authorization sentinels are transport-neutral. Adapters map them to the
// public problem catalog without exposing actor or grant details.
var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
)

// Clock supplies command timestamps without hidden process-global state.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// IDGenerator supplies context-owned record identifiers.
type IDGenerator interface {
	NewID(prefix string) string
}

type IDGeneratorFunc func(string) string

func (f IDGeneratorFunc) NewID(prefix string) string { return f(prefix) }

// ResourceReferences are the explicit, tenant-scoped resource coordinates
// supplied to authorization policy. Blank fields are intentionally absent.
type ResourceReferences struct {
	ProductID         string
	ProjectID         string
	ReleaseID         string
	ArtifactID        string
	BuildID           string
	DeploymentID      string
	EnvironmentID     string
	CustomerPackageID string
}

// AuthorizationRequest keeps scope and resource decisions visible at each
// service entry point. ScopeOnly preserves operations that have no resource
// association at command time, such as registering a detached artifact.
type AuthorizationRequest struct {
	Scope      string
	Resources  ResourceReferences
	ScopeOnly  bool
	TenantWide bool
}

type Authorizer interface {
	Authorize(context.Context, identitydomain.Actor, AuthorizationRequest) error
}

// AuditEvent is the unsequenced audit intent appended inside the caller's
// transaction. Persistence assigns chain sequence and predecessor metadata.
type AuditEvent struct {
	ID           string
	TenantID     string
	EntryType    string
	SubjectType  string
	SubjectID    string
	ActorType    string
	ActorID      string
	OccurredAt   time.Time
	PayloadHash  string
	SignatureRef string
}

// AuditReceipt identifies the committed audit entry without exposing chain
// internals to the owning context.
type AuditReceipt struct {
	ID string
}

type AuditAppender interface {
	AppendAudit(context.Context, AuditEvent) (AuditReceipt, error)
}

// OutboxEvent is a post-commit effect requested by the owning context. The
// transaction adapter assigns storage-specific deduplication metadata.
type OutboxEvent struct {
	ID          string
	TenantID    string
	Kind        string
	SubjectType string
	SubjectID   string
	Payload     map[string]any
	CreatedAt   time.Time
}

type OutboxEnqueuer interface {
	EnqueueOutbox(context.Context, OutboxEvent) error
}
