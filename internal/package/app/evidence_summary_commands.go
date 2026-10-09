package app

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const (
	MaxEvidenceSummaryItems      = 512
	MaxEvidenceSummaryIDBytes    = 1024
	MaxEvidenceSummaryTypeBytes  = 128
	MaxEvidenceSummaryTitleBytes = 64 << 10
)

type CreateEvidenceSummaryInput struct {
	SubjectType string
	SubjectID   string
	EvidenceIDs []string
}

// Resources are resolved authorization coordinates. Filter retains the raw
// product/project/release selection semantics of the existing summary format;
// inferred parent coordinates must not silently narrow evidence selection.
type EvidenceSummaryScope struct {
	TenantID, SubjectType, SubjectID string
	Resources                        application.ResourceReferences
	Filter                           application.ResourceReferences
}

// EvidenceSummaryItem exposes citation metadata only, not payloads, findings,
// secrets, or arbitrary evidence metadata. Resources are the stored coordinates.
type EvidenceSummaryItem struct {
	ID, TenantID, Type, Title, CanonicalHash string
	Resources                                application.ResourceReferences
}

type EvidenceSummaryReader interface {
	ReadEvidenceSummaryScope(context.Context, string, string, string) (EvidenceSummaryScope, error)
	ReadEvidenceSummaryItems(context.Context, EvidenceSummaryScope, []string) ([]EvidenceSummaryItem, error)
}

type EvidenceSummaryTransaction interface {
	EvidenceSummaryReader
	InsertEvidenceSummary(context.Context, packagedomain.EvidenceSummary) error
	application.Authorizer
	application.AuditAppender
}

type EvidenceSummaryTransactions interface {
	ExecuteEvidenceSummary(context.Context, string, func(context.Context, EvidenceSummaryTransaction) error) error
}

type EvidenceSummaryCommandConfig struct {
	Transactions EvidenceSummaryTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}

type EvidenceSummaryCommands struct{ config EvidenceSummaryCommandConfig }

func NewEvidenceSummaryCommands(config EvidenceSummaryCommandConfig) (*EvidenceSummaryCommands, error) {
	if config.Transactions == nil || config.Authorizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &EvidenceSummaryCommands{config: config}, nil
}

func (s *EvidenceSummaryCommands) prepare(ctx context.Context, actor identitydomain.Actor, in CreateEvidenceSummaryInput) (CreateEvidenceSummaryInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	in, err := NormalizeEvidenceSummaryInput(in)
	if err != nil {
		return in, err
	}
	return in, s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, ScopeOnly: true})
}

// NormalizeEvidenceSummaryInput is shared by transport and command boundaries.
func NormalizeEvidenceSummaryInput(in CreateEvidenceSummaryInput) (CreateEvidenceSummaryInput, error) {
	in.SubjectType = strings.TrimSpace(in.SubjectType)
	in.SubjectID = strings.TrimSpace(in.SubjectID)
	switch in.SubjectType {
	case "tenant", "product", "release", "evidence", "build", "customer_package":
	default:
		return in, ErrValidation
	}
	if !summaryString(in.SubjectID, MaxEvidenceSummaryIDBytes) || len(in.EvidenceIDs) > MaxEvidenceSummaryItems {
		return in, ErrValidation
	}
	in.EvidenceIDs = append([]string(nil), in.EvidenceIDs...)
	for i, id := range in.EvidenceIDs {
		in.EvidenceIDs[i] = strings.TrimSpace(id)
		if !summaryString(in.EvidenceIDs[i], MaxEvidenceSummaryIDBytes) {
			return in, ErrValidation
		}
	}
	sort.Strings(in.EvidenceIDs)
	for i := 1; i < len(in.EvidenceIDs); i++ {
		if in.EvidenceIDs[i] == in.EvidenceIDs[i-1] {
			return in, ErrValidation
		}
	}
	return in, nil
}

func summaryString(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func summaryMatches(item EvidenceSummaryItem, scope EvidenceSummaryScope) bool {
	r, f := item.Resources, scope.Filter
	return (f.ProductID == "" || r.ProductID == f.ProductID) && (f.ProjectID == "" || r.ProjectID == f.ProjectID) && (f.ReleaseID == "" || r.ReleaseID == f.ReleaseID)
}

func readAuthorizedSummaryScope(ctx context.Context, tx EvidenceSummaryTransaction, actor identitydomain.Actor, in CreateEvidenceSummaryInput) (EvidenceSummaryScope, error) {
	scope, err := tx.ReadEvidenceSummaryScope(ctx, actor.TenantID, in.SubjectType, in.SubjectID)
	if err != nil {
		return scope, err
	}
	if scope.TenantID != actor.TenantID || scope.SubjectType != in.SubjectType || scope.SubjectID != in.SubjectID {
		return EvidenceSummaryScope{}, ErrNotFound
	}
	err = tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReportRead, Resources: scope.Resources, TenantWide: scope.Resources == (application.ResourceReferences{})})
	return scope, err
}

// Replays recheck current root authorization without reading citations or
// inserting a summary. HTTP transaction executors retain this guard on replay.
func (s *EvidenceSummaryCommands) AuthorizeCreateEvidenceSummary(ctx context.Context, actor identitydomain.Actor, in CreateEvidenceSummaryInput) error {
	in, err := s.prepare(ctx, actor, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteEvidenceSummary(ctx, actor.TenantID, func(ctx context.Context, tx EvidenceSummaryTransaction) error {
		_, err := readAuthorizedSummaryScope(ctx, tx, actor, in)
		return err
	})
}

func (s *EvidenceSummaryCommands) CreateEvidenceSummary(ctx context.Context, actor identitydomain.Actor, in CreateEvidenceSummaryInput) (packagedomain.EvidenceSummary, error) {
	in, err := s.prepare(ctx, actor, in)
	if err != nil {
		return packagedomain.EvidenceSummary{}, err
	}
	var result packagedomain.EvidenceSummary
	err = s.config.Transactions.ExecuteEvidenceSummary(ctx, actor.TenantID, func(ctx context.Context, tx EvidenceSummaryTransaction) error {
		scope, err := readAuthorizedSummaryScope(ctx, tx, actor, in)
		if err != nil {
			return err
		}
		items, err := tx.ReadEvidenceSummaryItems(ctx, scope, in.EvidenceIDs)
		if err != nil {
			return err
		}
		if len(items) == 0 && len(in.EvidenceIDs) != 0 {
			return ErrNotFound
		}
		if len(items) == 0 || len(items) > MaxEvidenceSummaryItems {
			return ErrValidation
		}
		items = append([]EvidenceSummaryItem(nil), items...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		if len(in.EvidenceIDs) != 0 {
			if len(items) != len(in.EvidenceIDs) {
				return ErrNotFound
			}
			for i := range items {
				if items[i].ID != in.EvidenceIDs[i] {
					return ErrNotFound
				}
			}
		}
		ids := make([]string, len(items))
		citations := make([]packagedomain.EvidenceCitation, len(items))
		titles := make([]string, len(items))
		for i, item := range items {
			if item.TenantID != actor.TenantID {
				return ErrNotFound
			}
			if i > 0 && items[i-1].ID == item.ID {
				return ErrConflict
			}
			if !summaryMatches(item, scope) {
				return ErrValidation
			}
			if !summaryString(item.ID, MaxEvidenceSummaryIDBytes) || !summaryString(item.Type, MaxEvidenceSummaryTypeBytes) || !summaryString(item.Title, MaxEvidenceSummaryTitleBytes) || !summaryString(item.CanonicalHash, MaxEvidenceSummaryIDBytes) {
				return ErrValidation
			}
			ids[i], titles[i] = item.ID, item.Title
			citations[i] = packagedomain.EvidenceCitation{EvidenceID: item.ID, Type: item.Type, Title: item.Title, CanonicalHash: item.CanonicalHash}
		}
		now := s.config.Clock.Now().UTC()
		result = packagedomain.EvidenceSummary{ID: s.config.IDs.NewID("sum"), TenantID: actor.TenantID, SubjectType: in.SubjectType, SubjectID: in.SubjectID,
			EvidenceIDs: ids, Citations: citations, Summary: "Technical evidence recorded for " + in.SubjectType + " " + in.SubjectID + ": " + strings.Join(titles, "; ") + ".",
			Assumptions:   []string{"Summary is generated only from explicitly linked Evydence records."},
			Limitations:   []string{"This summary supports evidence review and does not assert legal compliance, certification, or release security."},
			SchemaVersion: packagedomain.EvidenceSummaryVersion, CreatedAt: now}
		encoded, err := EncodeEvidenceSummary(result)
		if err != nil {
			return err
		}
		if len(encoded) > MaxGeneratedReportBytes {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertEvidenceSummary(ctx, cloneEvidenceSummary(result)); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "evidence_summary.created", SubjectType: "evidence_summary", SubjectID: result.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now})
		if err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return packagedomain.EvidenceSummary{}, err
	}
	return cloneEvidenceSummary(result), nil
}

func cloneEvidenceSummary(v packagedomain.EvidenceSummary) packagedomain.EvidenceSummary {
	v.EvidenceIDs = append([]string(nil), v.EvidenceIDs...)
	v.Citations = append([]packagedomain.EvidenceCitation(nil), v.Citations...)
	v.Assumptions = append([]string(nil), v.Assumptions...)
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}

// EncodeEvidenceSummary owns the versioned technical-summary document shape.
// Domain records remain transport-neutral. The command budgets these exact
// bytes and HTTP returns this same projection, avoiding divergent encoders.
func EncodeEvidenceSummary(v packagedomain.EvidenceSummary) ([]byte, error) {
	citations := make([]map[string]string, len(v.Citations))
	for i, c := range v.Citations {
		citations[i] = map[string]string{"evidence_id": c.EvidenceID, "type": c.Type, "title": c.Title, "canonical_hash": c.CanonicalHash}
	}
	return json.Marshal(map[string]any{
		"id": v.ID, "tenant_id": v.TenantID, "subject_type": v.SubjectType, "subject_id": v.SubjectID,
		"evidence_ids": v.EvidenceIDs, "summary": v.Summary, "citations": citations,
		"assumptions": v.Assumptions, "limitations": v.Limitations, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt,
	})
}
