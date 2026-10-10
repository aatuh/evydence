package httpapi

import (
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
)

// Historical fixture input translates to the actual focused evidence command.
type evidenceFixtureInput struct {
	ProductID        string
	ProjectID        string
	ReleaseID        string
	BuildID          string
	DeploymentID     string
	Type             string
	Subtype          string
	Title            string
	SourceSystem     string
	SourceIdentity   map[string]any
	CollectorID      string
	ObservedAt       time.Time
	PayloadRef       string
	PayloadHash      string
	PayloadMediaType string
	PayloadSize      int64
	StagedPayload    app.ObjectPayload
	SubjectRefs      []domain.SubjectRef
	Metadata         map[string]any
	Tags             []string
	Limitations      []string
}
