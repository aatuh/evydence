package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

// SourceCommitReader exposes only current ownership and one bounded commit,
// never repository contents or a tenant-wide source-state snapshot.
type SourceCommitReader interface {
	SourceRepositoryWriteReader
	SourceCommitBySHA(context.Context, string, string, string) (integrationdomain.SourceCommit, bool, error)
}
type SourceCommitTransaction interface {
	SourceCommitReader
	application.Authorizer
	application.AuditAppender
	InsertSourceCommit(context.Context, integrationdomain.SourceCommit) error
}
type SourceCommitTransactions interface {
	ExecuteSourceCommit(context.Context, func(context.Context, SourceCommitTransaction) error) error
}
type SourceCommitConfig struct {
	Transactions SourceCommitTransactions
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SourceCommitCommands struct{ config SourceCommitConfig }
type RecordSourceCommitInput struct {
	RepositoryID, SHA, Author, Message string
	CommittedAt                        time.Time
}

func NewSourceCommitCommands(c SourceCommitConfig) (*SourceCommitCommands, error) {
	if c.Transactions == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SourceCommitCommands{c}, nil
}
func validSourceCommitSHA(v string) bool {
	if len(v) != 40 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}
func validSourceCommitHash(v string) bool {
	if v == "" {
		return true
	}
	if !strings.HasPrefix(v, "sha256:") || len(v) != 71 {
		return false
	}
	_, err := hex.DecodeString(v[7:])
	return err == nil
}
func validSourceTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }
func sourceAuditIdentity(a identitydomain.Actor) (string, string) {
	if a.CollectorID != "" {
		return "collector", a.CollectorID
	}
	if a.UserID != "" {
		return "human_user", a.UserID
	}
	return "api_key", a.KeyID
}
func NormalizeSourceCommitInput(in RecordSourceCommitInput) (RecordSourceCommitInput, error) {
	// Message is opaque hash input: preserve its exact bytes, including NUL.
	if !validSourceText(in.RepositoryID, 1024, false) || !validSourceText(in.SHA, 1024, false) || !validSourceText(in.Author, MaxSourceTextBytes, true) || len(in.Message) > MaxSourceTextBytes || !in.CommittedAt.IsZero() && !validSourceTime(in.CommittedAt) {
		return in, ErrValidation
	}
	in.RepositoryID, in.SHA, in.Author = strings.TrimSpace(in.RepositoryID), strings.ToLower(strings.TrimSpace(in.SHA)), strings.TrimSpace(in.Author)
	if in.RepositoryID == "" || !validSourceCommitSHA(in.SHA) {
		return in, ErrValidation
	}
	return in, nil
}

func (s *SourceCommitCommands) RecordSourceCommit(ctx context.Context, a identitydomain.Actor, in RecordSourceCommitInput) (integrationdomain.SourceCommit, error) {
	if s == nil {
		return integrationdomain.SourceCommit{}, ErrValidation
	}
	if err := prepareSourceWrite(ctx, a, s.config.Authorizer); err != nil {
		return integrationdomain.SourceCommit{}, err
	}
	in, err := NormalizeSourceCommitInput(in)
	if err != nil {
		return integrationdomain.SourceCommit{}, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if in.CommittedAt.IsZero() {
		in.CommittedAt = now
	}
	in.CommittedAt = in.CommittedAt.UTC().Truncate(time.Microsecond)
	if !validSourceTime(now) || !validSourceTime(in.CommittedAt) {
		return integrationdomain.SourceCommit{}, ErrValidation
	}
	var result integrationdomain.SourceCommit
	err = s.config.Transactions.ExecuteSourceCommit(ctx, func(ctx context.Context, tx SourceCommitTransaction) error {
		r, err := authorizeSourceWriteRepository(ctx, tx, a, in.RepositoryID)
		if err != nil {
			return err
		}
		v, found, err := tx.SourceCommitBySHA(ctx, a.TenantID, r.ID, in.SHA)
		if err != nil {
			return err
		}
		if found {
			if !validSourceText(v.ID, 1024, false) || v.TenantID != a.TenantID || v.RepositoryID != r.ID || v.SHA != in.SHA || !validSourceText(v.Author, MaxSourceTextBytes, true) || !validSourceCommitHash(v.MessageHash) || v.SchemaVersion != integrationdomain.SourceCommitSchemaVersion || !validSourceTime(v.CommittedAt) || !validSourceTime(v.CreatedAt) {
				return ErrConflict
			}
			result = v
			return nil
		}
		hash := ""
		if strings.TrimSpace(in.Message) != "" {
			hash = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(in.Message)))
		}
		v = integrationdomain.SourceCommit{ID: s.config.IDs.NewID("commit"), TenantID: a.TenantID, RepositoryID: r.ID, SHA: in.SHA, Author: in.Author, MessageHash: hash, CommittedAt: in.CommittedAt, CreatedAt: now, SchemaVersion: integrationdomain.SourceCommitSchemaVersion}
		if err := tx.InsertSourceCommit(ctx, v); err != nil {
			return err
		}
		actorType, actorID := sourceAuditIdentity(a)
		if _, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "source_commit.recorded", SubjectType: "source_commit", SubjectID: v.ID, ActorType: actorType, ActorID: actorID, OccurredAt: now}); err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		return integrationdomain.SourceCommit{}, err
	}
	return result, nil
}
