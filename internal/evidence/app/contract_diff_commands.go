package app

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

// Matches the existing contract point-query budget. Operations and nested
// strings share one budget rather than each permitting an unbounded payload.
const ContractDiffProjectionByteLimit = 32 << 20
const ContractDiffOperationLimit = ContractDiffProjectionByteLimit / 64

type ContractDiffSubject struct{ ID, TenantID, ProductID, ReleaseID, EvidenceID string }
type ContractDiffRelease struct{ ID, TenantID, ProductID string }
type ContractDiffReader interface {
	ReadContractDiffSubject(context.Context, string, string) (ContractDiffSubject, error)
	ReadContractDiffRelease(context.Context, string, string) (ContractDiffRelease, error)
	ReadContractDiffProjection(context.Context, string, string) (evidencedomain.OpenAPIContract, error)
}
type ContractDiffTransaction interface {
	ContractDiffReader
	application.Authorizer
	application.AuditAppender
	InsertContractDiff(context.Context, evidencedomain.ContractDiff) error
}
type ContractDiffTransactionRunner interface {
	ExecuteContractDiff(context.Context, func(context.Context, ContractDiffTransaction) error) error
}
type ContractDiffCommandConfig struct {
	Authorizer   application.Authorizer
	Transactions ContractDiffTransactionRunner
	Clock        application.Clock
	IDs          application.IDGenerator
}
type ContractDiffCommands struct{ config ContractDiffCommandConfig }

func NewContractDiffCommands(c ContractDiffCommandConfig) (*ContractDiffCommands, error) {
	if c.Authorizer == nil || c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &ContractDiffCommands{c}, nil
}
func (s *ContractDiffCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateContractDiffInput) (CreateContractDiffInput, error) {
	if s == nil {
		return in, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return in, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, ScopeOnly: true}); err != nil {
		return in, err
	}
	if !validDiffText(a.TenantID, 1024, true) || !validDiffText(auditActorID(a), 1024, true) {
		return in, ErrValidation
	}
	for _, v := range []string{in.BaseContractID, in.TargetContractID, in.ReleaseID} {
		if !validDiffText(v, 1024, false) {
			return in, ErrValidation
		}
	}
	in.BaseContractID = strings.TrimSpace(in.BaseContractID)
	in.TargetContractID = strings.TrimSpace(in.TargetContractID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	if in.BaseContractID == "" || in.TargetContractID == "" || in.BaseContractID == in.TargetContractID {
		return in, ErrValidation
	}
	return in, nil
}
func authorizeContractDiff(ctx context.Context, tx ContractDiffTransaction, a identitydomain.Actor, in CreateContractDiffInput) ([2]ContractDiffSubject, error) {
	var subjects [2]ContractDiffSubject
	if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, ScopeOnly: true}); err != nil {
		return subjects, err
	}
	for i, id := range []string{in.BaseContractID, in.TargetContractID} {
		v, err := tx.ReadContractDiffSubject(ctx, a.TenantID, id)
		if err != nil {
			return subjects, err
		}
		if v.ID != id || v.TenantID != a.TenantID {
			return subjects, ErrNotFound
		}
		for _, value := range []string{v.ProductID, v.EvidenceID} {
			if !validDiffText(value, 1024, true) || strings.TrimSpace(value) != value {
				return subjects, ErrNotFound
			}
		}
		if !validDiffText(v.ReleaseID, 1024, false) || strings.TrimSpace(v.ReleaseID) != v.ReleaseID {
			return subjects, ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, Resources: application.ResourceReferences{ProductID: v.ProductID, ReleaseID: v.ReleaseID}}); err != nil {
			return subjects, err
		}
		subjects[i] = v
	}
	if subjects[0].ProductID != subjects[1].ProductID {
		return subjects, ErrNotFound
	}
	// The requested release need not be one of the two source releases. It
	// must be current, tenant-owned, authorized, and of their common product.
	if in.ReleaseID != "" {
		v, err := tx.ReadContractDiffRelease(ctx, a.TenantID, in.ReleaseID)
		if err != nil {
			return subjects, err
		}
		if v.ID != in.ReleaseID || v.TenantID != a.TenantID || v.ProductID != subjects[0].ProductID {
			return subjects, ErrNotFound
		}
		if err := tx.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopeEvidenceRead, Resources: application.ResourceReferences{ProductID: v.ProductID, ReleaseID: v.ID}}); err != nil {
			return subjects, err
		}
	}
	return subjects, nil
}

// Replay authorizes current metadata without reading operation documents.
func (s *ContractDiffCommands) AuthorizeCreateContractDiff(ctx context.Context, a identitydomain.Actor, in CreateContractDiffInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteContractDiff(ctx, func(ctx context.Context, tx ContractDiffTransaction) error {
		_, err := authorizeContractDiff(ctx, tx, a, in)
		return err
	})
}
func validContractDiffProjection(v evidencedomain.OpenAPIContract) bool {
	if len(v.Operations) > ContractDiffOperationLimit || v.PathCount < 0 || !strings.HasPrefix(v.Hash, "sha256:") || len(v.Hash) != 71 {
		return false
	}
	if _, err := hex.DecodeString(v.Hash[7:]); err != nil {
		return false
	}
	// Every normalized operation consumes fixed structural space as well as
	// its strings, so empty structures cannot evade the aggregate bound.
	remaining := ContractDiffProjectionByteLimit
	consume := func(text string) bool {
		if !validDiffText(text, remaining, false) {
			return false
		}
		remaining -= len(text)
		return true
	}
	for _, op := range v.Operations {
		if !validDiffText(op.Path, ContractDiffProjectionByteLimit, true) || !validDiffText(op.Method, ContractDiffProjectionByteLimit, true) {
			return false
		}
		if remaining < 64 {
			return false
		}
		remaining -= 64
		if !consume(op.Path) || !consume(op.Method) || !consume(op.OperationID) {
			return false
		}
		for _, values := range [][]string{op.RequiredRequestFields, op.ResponseStatuses} {
			for _, text := range values {
				if remaining < 8 {
					return false
				}
				remaining -= 8
				if !consume(text) {
					return false
				}
			}
		}
	}
	return true
}
func (s *ContractDiffCommands) CreateContractDiff(ctx context.Context, a identitydomain.Actor, in CreateContractDiffInput) (evidencedomain.ContractDiff, error) {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	var diff evidencedomain.ContractDiff
	err = s.config.Transactions.ExecuteContractDiff(ctx, func(ctx context.Context, tx ContractDiffTransaction) error {
		subjects, err := authorizeContractDiff(ctx, tx, a, in)
		if err != nil {
			return err
		}
		var contracts [2]evidencedomain.OpenAPIContract
		for i, subject := range subjects {
			v, err := tx.ReadContractDiffProjection(ctx, a.TenantID, subject.ID)
			if err != nil {
				return err
			}
			if (ContractDiffSubject{ID: v.ID, TenantID: v.TenantID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, EvidenceID: v.EvidenceID}) != subject {
				return ErrNotFound
			}
			if !validContractDiffProjection(v) {
				return ErrValidation
			}
			contracts[i] = v
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		result, breaking, nonBreaking := evaluateContractDifference(contracts[0], contracts[1])
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if now.IsZero() || now.Year() < 1 || now.Year() > 9999 {
			return ErrValidation
		}
		diff = evidencedomain.ContractDiff{ID: s.config.IDs.NewID("cdiff"), TenantID: a.TenantID, BaseContractID: in.BaseContractID, TargetContractID: in.TargetContractID, ProductID: subjects[0].ProductID, ReleaseID: in.ReleaseID, Result: result, BreakingChanges: breaking, NonBreakingChanges: nonBreaking, SchemaVersion: evidencedomain.ContractDiffSchemaVersion, CreatedAt: now}
		if !validDiffText(diff.ID, 1024, true) {
			return ErrValidation
		}
		if err := tx.InsertContractDiff(ctx, diff); err != nil {
			return err
		}
		audit := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "openapi_contract.diffed", SubjectType: "contract_diff", SubjectID: diff.ID, ActorID: auditActorID(a), ActorType: auditActorType(a), OccurredAt: now}
		if !validDiffText(audit.ID, 1024, true) {
			return ErrValidation
		}
		_, err = tx.AppendAudit(ctx, audit)
		return err
	})
	if err != nil {
		return evidencedomain.ContractDiff{}, err
	}
	return cloneContractDiff(diff), nil
}
func evaluateContractDifference(base, target evidencedomain.OpenAPIContract) (string, []string, []string) {
	result := "unchanged"
	breaking, nonBreaking := []string{}, []string{}
	if base.Hash != target.Hash {
		result = "changed"
		breaking, nonBreaking = diffOpenAPIOperations(base, target)
		if len(base.Operations) == 0 || len(target.Operations) == 0 {
			breaking, nonBreaking = []string{}, []string{}
			if target.PathCount < base.PathCount {
				breaking = append(breaking, "target contract has fewer paths than base contract")
			}
			if target.PathCount > base.PathCount {
				nonBreaking = append(nonBreaking, "target contract has additional paths")
			}
		}
		if len(breaking) > 0 {
			result = "breaking"
		}
	}
	return result, breaking, nonBreaking
}
