package app

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type CandidateReleaseCoordinates struct{ ID, TenantID, ProductID string }

type CandidateReleaseReader interface {
	ReadCandidateRelease(context.Context, string, string) (CandidateReleaseCoordinates, error)
}

// CandidateCreationTransaction owns current parent/reference checks, grants,
// one candidate insert and the audit append, never an unrelated catalog.
type CandidateCreationTransaction interface {
	CandidateReleaseReader
	ReleaseCandidateReferenceValidator
	application.Authorizer
	InsertCandidate(context.Context, releasedomain.ReleaseCandidate) error
	application.AuditAppender
}
type CandidateCreationTransactionRunner interface {
	ExecuteCandidateCreation(context.Context, func(context.Context, CandidateCreationTransaction) error) error
}
type CandidateCommandConfig struct {
	Authorizer    application.Authorizer
	Transactions  CandidateCreationTransactionRunner
	Canonicalizer ReleaseCandidateCanonicalizer
	Clock         application.Clock
	IDs           application.IDGenerator
}
type CandidateCommands struct{ config CandidateCommandConfig }

func NewCandidateCommands(config CandidateCommandConfig) (*CandidateCommands, error) {
	if config.Authorizer == nil || config.Transactions == nil || config.Canonicalizer == nil || config.Clock == nil || config.IDs == nil {
		return nil, ErrValidation
	}
	return &CandidateCommands{config: config}, nil
}

func (s *CandidateCommands) CreateReleaseCandidate(ctx context.Context, actor identitydomain.Actor, input CreateReleaseCandidateInput) (releasedomain.ReleaseCandidate, error) {
	if s == nil {
		return releasedomain.ReleaseCandidate{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: ScopeReleaseWrite, ScopeOnly: true}); err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	var err error
	input, err = NormalizeCandidateCreationInput(input)
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	refs := ReleaseCandidateReferences{BuildIDs: input.BuildIDs, ArtifactIDs: input.ArtifactIDs, SBOMIDs: input.SBOMIDs, ScanIDs: input.ScanIDs, VEXIDs: input.VEXIDs, ContractIDs: input.ContractIDs, BundleIDs: input.BundleIDs}
	var candidate releasedomain.ReleaseCandidate
	err = s.config.Transactions.ExecuteCandidateCreation(ctx, func(ctx context.Context, tx CandidateCreationTransaction) error {
		parent, err := authorizeCandidateCreationScope(ctx, tx, actor, input)
		if err != nil {
			return err
		}
		state, _ := releasedomain.ParseReleaseCandidateState("open")
		candidate = releasedomain.ReleaseCandidate{ID: s.config.IDs.NewID("rc"), TenantID: actor.TenantID, ReleaseID: parent.ID, Name: input.Name, Revision: 1, State: state, BuildIDs: refs.BuildIDs, ArtifactIDs: refs.ArtifactIDs, SBOMIDs: refs.SBOMIDs, ScanIDs: refs.ScanIDs, VEXIDs: refs.VEXIDs, ContractIDs: refs.ContractIDs, BundleIDs: refs.BundleIDs, SchemaVersion: releasedomain.ReleaseCandidateSchemaVersion, CreatedAt: s.config.Clock.Now().UTC()}
		if !validCandidateText(candidate.ID, 1024) || candidate.CreatedAt.IsZero() {
			return ErrValidation
		}
		hash, err := s.config.Canonicalizer.HashReleaseCandidate(ctx, cloneReleaseCandidate(candidate))
		if err != nil {
			return err
		}
		if !validDigest(hash) {
			return ErrValidation
		}
		candidate.SnapshotHash = hash
		if err := tx.InsertCandidate(ctx, cloneReleaseCandidate(candidate)); err != nil {
			return err
		}
		_, err = tx.AppendAudit(ctx, auditEventFor(s.config.IDs, actor, candidate.CreatedAt, "release_candidate.created", "release_candidate", candidate.ID, candidate.SnapshotHash))
		return err
	})
	if err != nil {
		return releasedomain.ReleaseCandidate{}, err
	}
	return candidate, nil
}

func validCandidateText(v string, limit int) bool {
	return v != "" && len(v) <= limit && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}

// ValidCandidateReferences bounds identifier-only lookup work and the eventual
// snapshot. SQL adapters reuse this rule for direct port callers.
func ValidCandidateReferences(refs ReleaseCandidateReferences) bool {
	count, bytes := 0, 0
	for _, ids := range [][]string{refs.BuildIDs, refs.ArtifactIDs, refs.SBOMIDs, refs.ScanIDs, refs.VEXIDs, refs.ContractIDs, refs.BundleIDs} {
		if len(ids) > 4096-count {
			return false
		}
		count += len(ids)
		for _, id := range ids {
			if !validCandidateText(id, 1024) {
				return false
			}
			bytes += len(id)
			if bytes > 65536 {
				return false
			}
		}
	}
	return true
}
