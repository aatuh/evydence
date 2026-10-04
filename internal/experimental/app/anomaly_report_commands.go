// Package app owns focused commands for quarantined experimental peripherals.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

var (
	ErrValidation = errors.New("invalid experimental command")
	ErrNotFound   = errors.New("experimental command resource not found")
	ErrConflict   = errors.New("experimental command conflict")
)

const MaxAnomalyIDBytes = 1024
const MaxAnomalySubjectTypeBytes = 128

type AnomalyReportInput struct{ SubjectType, SubjectID string }
type AnomalyScope struct {
	TenantID, SubjectType, SubjectID string
	Resources                        application.ResourceReferences
}

// Facts expose fixed-size existence projections, not scanner or provider data.
type AnomalyReleaseFacts struct {
	TenantID, ReleaseID                                            string
	HasPassedBuild, HasVerifiedBuildAttestation, UnhandledCritical bool
}
type AnomalyScopeReader interface {
	ReadAnomalyScope(context.Context, string, string, string) (AnomalyScope, error)
}
type AnomalyReleaseFactsReader interface {
	ReadAnomalyReleaseFacts(context.Context, string, string, time.Time) (AnomalyReleaseFacts, error)
}
type AnomalyTransaction interface {
	AnomalyScopeReader
	AnomalyReleaseFactsReader
	InsertAnomalyReport(context.Context, experimentaldomain.AnomalyReport) error
	application.Authorizer
	application.AuditAppender
}
type AnomalyTransactions interface {
	ExecuteAnomalyReport(context.Context, string, func(context.Context, AnomalyTransaction) error) error
}
type AnomalyCommandConfig struct {
	Transactions AnomalyTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type AnomalyCommands struct{ config AnomalyCommandConfig }

func NewAnomalyCommands(c AnomalyCommandConfig) (*AnomalyCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &AnomalyCommands{c}, nil
}
func anomalyText(v string, max int) bool {
	return len(v) <= max && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func anomalyID(v string) bool {
	return anomalyText(v, MaxAnomalyIDBytes) && v != "" && strings.TrimSpace(v) == v
}
func NormalizeAnomalyInput(in AnomalyReportInput) (AnomalyReportInput, error) {
	if !anomalyText(in.SubjectType, MaxAnomalySubjectTypeBytes) || !anomalyText(in.SubjectID, MaxAnomalyIDBytes) {
		return in, ErrValidation
	}
	in.SubjectType, in.SubjectID = strings.TrimSpace(in.SubjectType), strings.TrimSpace(in.SubjectID)
	switch in.SubjectType {
	case "tenant", "product", "release", "evidence", "build", "customer_package":
	default:
		return in, ErrValidation
	}
	if !anomalyID(in.SubjectID) {
		return in, ErrValidation
	}
	return in, nil
}
func anomalyActor(a identitydomain.Actor) (string, string) {
	if a.CollectorID != "" {
		return "collector", strings.TrimSpace(a.CollectorID)
	}
	if a.UserID != "" {
		return "human_user", strings.TrimSpace(a.UserID)
	}
	return "api_key", strings.TrimSpace(a.KeyID)
}
func (c *AnomalyCommands) prepare(ctx context.Context, a identitydomain.Actor, in AnomalyReportInput) (AnomalyReportInput, error) {
	if c == nil || ctx == nil {
		return in, ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return in, err
	}
	in, err := NormalizeAnomalyInput(in)
	if err != nil {
		return in, err
	}
	_, id := anomalyActor(a)
	if !anomalyID(a.TenantID) || !anomalyID(id) {
		return in, application.ErrUnauthorized
	}
	return in, c.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: "report:read", ScopeOnly: true})
}
func authorizedAnomalyScope(ctx context.Context, tx AnomalyTransaction, a identitydomain.Actor, in AnomalyReportInput) error {
	s, err := tx.ReadAnomalyScope(ctx, a.TenantID, in.SubjectType, in.SubjectID)
	if err != nil {
		return err
	}
	r := s.Resources
	if s.TenantID != a.TenantID || s.SubjectType != in.SubjectType || s.SubjectID != in.SubjectID || r.ArtifactID != "" || r.EnvironmentID != "" {
		return ErrNotFound
	}
	for _, id := range []string{r.ProductID, r.ProjectID, r.ReleaseID, r.BuildID, r.DeploymentID, r.CustomerPackageID} {
		if id != "" && !anomalyID(id) {
			return ErrNotFound
		}
	}
	if in.SubjectType == "tenant" && (in.SubjectID != a.TenantID || r != (application.ResourceReferences{})) || in.SubjectType == "product" && r.ProductID != in.SubjectID || in.SubjectType == "release" && (r.ReleaseID != in.SubjectID || r.ProductID == "") || in.SubjectType == "customer_package" && r.CustomerPackageID != in.SubjectID {
		return ErrNotFound
	}
	return tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: "report:read", Resources: r, TenantWide: r == (application.ResourceReferences{})})
}
func (c *AnomalyCommands) AuthorizeGenerateAnomalyReport(ctx context.Context, a identitydomain.Actor, in AnomalyReportInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteAnomalyReport(ctx, a.TenantID, func(ctx context.Context, tx AnomalyTransaction) error {
		if err := authorizedAnomalyScope(ctx, tx, a, in); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func (c *AnomalyCommands) GenerateAnomalyReport(ctx context.Context, a identitydomain.Actor, in AnomalyReportInput) (experimentaldomain.AnomalyReport, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return experimentaldomain.AnomalyReport{}, err
	}
	var out experimentaldomain.AnomalyReport
	err = c.config.Transactions.ExecuteAnomalyReport(ctx, a.TenantID, func(ctx context.Context, tx AnomalyTransaction) error {
		if err := authorizedAnomalyScope(ctx, tx, a, in); err != nil {
			return err
		}
		at := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		id := c.config.IDs.NewID("ano")
		if at.IsZero() || at.Year() < 1 || at.Year() > 9999 || !anomalyID(id) {
			return ErrValidation
		}
		var facts AnomalyReleaseFacts
		if in.SubjectType == "release" {
			var err error
			facts, err = tx.ReadAnomalyReleaseFacts(ctx, a.TenantID, in.SubjectID, at)
			if err != nil {
				return err
			}
			if facts.TenantID != a.TenantID || facts.ReleaseID != in.SubjectID {
				return ErrNotFound
			}
		}
		out = BuildAnomalyReport(id, a.TenantID, in, at, facts)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.InsertAnomalyReport(ctx, CloneAnomalyReport(out)); err != nil {
			return err
		}
		actorType, actorID := anomalyActor(a)
		e := application.AuditEvent{ID: c.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "anomaly_report.created", SubjectType: "anomaly_report", SubjectID: out.ID, ActorType: actorType, ActorID: actorID, OccurredAt: at}
		if !anomalyID(e.ID) {
			return ErrValidation
		}
		if _, err := tx.AppendAudit(ctx, e); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return experimentaldomain.AnomalyReport{}, err
	}
	return CloneAnomalyReport(out), nil
}

// BuildAnomalyReport retains the versioned legacy signals and their ordering.
// Non-release roots have no checks; "clear" is not a security conclusion.
func BuildAnomalyReport(id, tenant string, in AnomalyReportInput, at time.Time, f AnomalyReleaseFacts) experimentaldomain.AnomalyReport {
	signals := []experimentaldomain.AnomalySignal{}
	if in.SubjectType == "release" {
		if !f.HasPassedBuild {
			signals = append(signals, experimentaldomain.AnomalySignal{Name: "missing_passed_build", Severity: "medium", Detail: "No passed build run is linked to this release."})
		}
		if !f.HasVerifiedBuildAttestation {
			signals = append(signals, experimentaldomain.AnomalySignal{Name: "missing_matching_attestation", Severity: "medium", Detail: "No passed trusted-attestation receipt covers a registered release artifact digest."})
		}
		if f.UnhandledCritical {
			signals = append(signals, experimentaldomain.AnomalySignal{Name: "unhandled_critical_finding", Severity: "high", Detail: "An open critical finding lacks a valid decision or approved exception."})
		}
	}
	result := "clear"
	if len(signals) > 0 {
		result = "attention_required"
	}
	return experimentaldomain.AnomalyReport{ID: id, TenantID: tenant, SubjectType: in.SubjectType, SubjectID: in.SubjectID, Result: result, Signals: signals, Assumptions: []string{"Signals are deterministic checks over stored Evydence records."}, Limitations: []string{"This report identifies evidence anomalies only and does not infer malicious behavior or release security."}, SchemaVersion: experimentaldomain.AnomalyReportVersion, CreatedAt: at}
}
func CloneAnomalyReport(v experimentaldomain.AnomalyReport) experimentaldomain.AnomalyReport {
	v.Signals = append([]experimentaldomain.AnomalySignal{}, v.Signals...)
	v.Assumptions = append([]string(nil), v.Assumptions...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func EncodeAnomalyReport(v experimentaldomain.AnomalyReport) ([]byte, error) {
	m := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "subject_type": v.SubjectType, "subject_id": v.SubjectID, "result": v.Result, "assumptions": v.Assumptions, "limitations": v.Limitations, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	if len(v.Signals) > 0 {
		signals := make([]map[string]any, len(v.Signals))
		for i, s := range v.Signals {
			signals[i] = map[string]any{"name": s.Name, "severity": s.Severity, "detail": s.Detail}
		}
		m["signals"] = signals
	}
	return json.Marshal(m)
}
