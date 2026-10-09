package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxPublicTransparencyNameBytes = 256
const MaxPublicTransparencyEndpointBytes = 4096
const MaxPublicTransparencyKeyBytes = 16 << 10
const MaxPublicTransparencyIDBytes = 1024

type PublicTransparencyLogInput struct{ Name, Endpoint, PublicKey string }
type PublicTransparencyPublicationInput struct{ LogID, CheckpointID, ExternalID string }

// The source contains only current tenant-owned coordinates and the root used
// by the existing entry commitment. No provider, key, or leaf payload crosses it.
type PublicTransparencyPublicationSource struct{ TenantID, LogID, CheckpointID, BatchID, RootHash string }
type PublicTransparencyMetadataReader interface {
	ReadPublicTransparencyTenant(context.Context, string) error
	ReadPublicTransparencyPublication(context.Context, string, string, string) (PublicTransparencyPublicationSource, error)
}
type PublicTransparencyMetadataTransaction interface {
	PublicTransparencyMetadataReader
	application.AuditAppender
	InsertPublicTransparencyLog(context.Context, d.PublicTransparencyLog) error
	InsertPublicTransparencyEntry(context.Context, d.PublicTransparencyLogEntry) error
}
type PublicTransparencyMetadataTransactions interface {
	ExecutePublicTransparencyMetadata(context.Context, string, func(context.Context, PublicTransparencyMetadataTransaction) error) error
}
type PublicTransparencyMetadataConfig struct {
	Transactions PublicTransparencyMetadataTransactions
	Clock        application.Clock
	IDs          application.IDGenerator
}
type PublicTransparencyMetadataCommands struct {
	config PublicTransparencyMetadataConfig
}

func NewPublicTransparencyMetadataCommands(c PublicTransparencyMetadataConfig) (*PublicTransparencyMetadataCommands, error) {
	if c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &PublicTransparencyMetadataCommands{c}, nil
}
func AuthorizePublicTransparencyMetadataActor(ctx context.Context, a identitydomain.Actor) error {
	if err := application.AuthorizeTenantWideScope(ctx, a, "keys:admin"); err != nil {
		return err
	}
	_, id := anomalyActor(a)
	if !anomalyID(a.TenantID) || !anomalyID(id) {
		return application.ErrUnauthorized
	}
	return nil
}
func NormalizePublicTransparencyLogInput(in PublicTransparencyLogInput) (PublicTransparencyLogInput, error) {
	if !anomalyText(in.Name, MaxPublicTransparencyNameBytes) || !anomalyText(in.Endpoint, MaxPublicTransparencyEndpointBytes) || !anomalyText(in.PublicKey, MaxPublicTransparencyKeyBytes) {
		return in, ErrValidation
	}
	in.Name, in.PublicKey = strings.TrimSpace(in.Name), strings.TrimSpace(in.PublicKey)
	var err error
	in.Endpoint, err = normalizePublicTransparencyEndpoint(in.Endpoint)
	if err != nil || in.Name == "" || in.PublicKey == "" {
		return in, ErrValidation
	}
	return in, nil
}
func normalizePublicTransparencyEndpoint(raw string) (string, error) {
	if !anomalyText(raw, MaxPublicTransparencyEndpointBytes) {
		return "", ErrValidation
	}
	endpoint := strings.TrimSpace(raw)
	u, err := url.Parse(endpoint)
	if err != nil || !strings.HasPrefix(endpoint, "https://") || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return "", ErrValidation
	}
	return endpoint, nil
}
func NormalizePublicTransparencyPublicationInput(in PublicTransparencyPublicationInput) (PublicTransparencyPublicationInput, error) {
	for _, id := range []string{in.LogID, in.CheckpointID, in.ExternalID} {
		if !anomalyText(id, MaxPublicTransparencyIDBytes) || strings.TrimSpace(id) == "" {
			return in, ErrValidation
		}
	}
	in.LogID, in.CheckpointID, in.ExternalID = strings.TrimSpace(in.LogID), strings.TrimSpace(in.CheckpointID), strings.TrimSpace(in.ExternalID)
	return in, nil
}
func validPublicTransparencyRecord(id, tenant string, at time.Time) bool {
	return anomalyID(id) && anomalyID(tenant) && !at.IsZero() && at.Year() >= 1 && at.Year() <= 9999
}
func BuildPublicTransparencyLog(id, tenant string, in PublicTransparencyLogInput, at time.Time) (d.PublicTransparencyLog, error) {
	in, err := NormalizePublicTransparencyLogInput(in)
	if err != nil || !validPublicTransparencyRecord(id, tenant, at) {
		return d.PublicTransparencyLog{}, ErrValidation
	}
	return d.PublicTransparencyLog{ID: id, TenantID: tenant, Name: in.Name, Endpoint: in.Endpoint, PublicKey: in.PublicKey, State: "configured", SchemaVersion: d.PublicTransparencyLogVersion, CreatedAt: at}, nil
}
func ValidatePublicTransparencyPublicationSource(tenant string, in PublicTransparencyPublicationInput, s PublicTransparencyPublicationSource) error {
	if s.TenantID != tenant || s.LogID != in.LogID || s.CheckpointID != in.CheckpointID {
		return ErrNotFound
	}
	if !anomalyID(s.BatchID) || !strings.HasPrefix(s.RootHash, "sha256:") || len(s.RootHash) != 71 {
		return ErrValidation
	}
	if _, err := hex.DecodeString(s.RootHash[7:]); err != nil {
		return ErrValidation
	}
	return nil
}
func BuildPublicTransparencyPublication(id, tenant string, in PublicTransparencyPublicationInput, s PublicTransparencyPublicationSource, at time.Time) (d.PublicTransparencyLogEntry, error) {
	in, err := NormalizePublicTransparencyPublicationInput(in)
	if err != nil || !validPublicTransparencyRecord(id, tenant, at) {
		return d.PublicTransparencyLogEntry{}, ErrValidation
	}
	if err := ValidatePublicTransparencyPublicationSource(tenant, in, s); err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	hash, err := application.NormalizedJSONHash(struct {
		LogID        string `json:"log_id"`
		CheckpointID string `json:"checkpoint_id"`
		MerkleRoot   string `json:"merkle_root"`
		ExternalID   string `json:"external_id"`
	}{s.LogID, s.CheckpointID, s.RootHash, in.ExternalID})
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return d.PublicTransparencyLogEntry{ID: id, TenantID: tenant, LogID: s.LogID, CheckpointID: s.CheckpointID, MerkleBatchID: s.BatchID, ExternalID: in.ExternalID, EntryHash: hash, State: "published", SchemaVersion: d.PublicTransparencyEntryVersion, CreatedAt: at}, nil
}
func (c *PublicTransparencyMetadataCommands) authorize(ctx context.Context, a identitydomain.Actor) error {
	if c == nil {
		return ErrValidation
	}
	return AuthorizePublicTransparencyMetadataActor(ctx, a)
}
func (c *PublicTransparencyMetadataCommands) AuthorizeCreatePublicTransparencyLog(ctx context.Context, a identitydomain.Actor, in PublicTransparencyLogInput) error {
	if err := c.authorize(ctx, a); err != nil {
		return err
	}
	if _, err := NormalizePublicTransparencyLogInput(in); err != nil {
		return err
	}
	return c.config.Transactions.ExecutePublicTransparencyMetadata(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyMetadataTransaction) error {
		return tx.ReadPublicTransparencyTenant(ctx, a.TenantID)
	})
}
func (c *PublicTransparencyMetadataCommands) CreatePublicTransparencyLog(ctx context.Context, a identitydomain.Actor, in PublicTransparencyLogInput) (d.PublicTransparencyLog, error) {
	if err := c.authorize(ctx, a); err != nil {
		return d.PublicTransparencyLog{}, err
	}
	in, err := NormalizePublicTransparencyLogInput(in)
	if err != nil {
		return d.PublicTransparencyLog{}, err
	}
	var out d.PublicTransparencyLog
	err = c.config.Transactions.ExecutePublicTransparencyMetadata(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyMetadataTransaction) error {
		if err := tx.ReadPublicTransparencyTenant(ctx, a.TenantID); err != nil {
			return err
		}
		out, err = BuildPublicTransparencyLog(c.config.IDs.NewID("ptl"), a.TenantID, in, c.config.Clock.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			return err
		}
		if err := tx.InsertPublicTransparencyLog(ctx, out); err != nil {
			return err
		}
		return c.appendMetadataAudit(ctx, tx, a, out.ID, "public_transparency_log", "created", "", out.CreatedAt)
	})
	if err != nil {
		return d.PublicTransparencyLog{}, err
	}
	return out, nil
}
func (c *PublicTransparencyMetadataCommands) AuthorizePublishPublicTransparencyLogEntry(ctx context.Context, a identitydomain.Actor, in PublicTransparencyPublicationInput) error {
	if err := c.authorize(ctx, a); err != nil {
		return err
	}
	in, err := NormalizePublicTransparencyPublicationInput(in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecutePublicTransparencyMetadata(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyMetadataTransaction) error {
		s, err := tx.ReadPublicTransparencyPublication(ctx, a.TenantID, in.LogID, in.CheckpointID)
		if err != nil {
			return err
		}
		return ValidatePublicTransparencyPublicationSource(a.TenantID, in, s)
	})
}
func (c *PublicTransparencyMetadataCommands) PublishPublicTransparencyLogEntry(ctx context.Context, a identitydomain.Actor, in PublicTransparencyPublicationInput) (d.PublicTransparencyLogEntry, error) {
	if err := c.authorize(ctx, a); err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	in, err := NormalizePublicTransparencyPublicationInput(in)
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	var out d.PublicTransparencyLogEntry
	err = c.config.Transactions.ExecutePublicTransparencyMetadata(ctx, a.TenantID, func(ctx context.Context, tx PublicTransparencyMetadataTransaction) error {
		s, err := tx.ReadPublicTransparencyPublication(ctx, a.TenantID, in.LogID, in.CheckpointID)
		if err != nil {
			return err
		}
		out, err = BuildPublicTransparencyPublication(c.config.IDs.NewID("pte"), a.TenantID, in, s, c.config.Clock.Now().UTC().Truncate(time.Microsecond))
		if err != nil {
			return err
		}
		if err := tx.InsertPublicTransparencyEntry(ctx, out); err != nil {
			return err
		}
		return c.appendMetadataAudit(ctx, tx, a, out.ID, "public_transparency_log_entry", "published", out.EntryHash, out.CreatedAt)
	})
	if err != nil {
		return d.PublicTransparencyLogEntry{}, err
	}
	return out, nil
}
func (c *PublicTransparencyMetadataCommands) appendMetadataAudit(ctx context.Context, tx PublicTransparencyMetadataTransaction, a identitydomain.Actor, id, kind, event, hash string, at time.Time) error {
	if err := AuthorizePublicTransparencyMetadataActor(ctx, a); err != nil {
		return err
	}
	auditID := c.config.IDs.NewID("ace")
	if !anomalyID(auditID) {
		return ErrValidation
	}
	actorType, actorID := anomalyActor(a)
	_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: auditID, TenantID: a.TenantID, EntryType: kind + "." + event, SubjectType: kind, SubjectID: id, ActorType: actorType, ActorID: actorID, PayloadHash: hash, OccurredAt: at})
	if err != nil {
		return err
	}
	return ctx.Err()
}
func EncodePublicTransparencyLog(v d.PublicTransparencyLog) ([]byte, error) {
	return json.Marshal(map[string]any{"id": v.ID, "tenant_id": v.TenantID, "name": v.Name, "endpoint": v.Endpoint, "public_key": v.PublicKey, "state": v.State, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt})
}
func EncodePublicTransparencyPublication(v d.PublicTransparencyLogEntry) ([]byte, error) {
	return json.Marshal(map[string]any{"id": v.ID, "tenant_id": v.TenantID, "log_id": v.LogID, "checkpoint_id": v.CheckpointID, "merkle_batch_id": v.MerkleBatchID, "external_id": v.ExternalID, "entry_hash": v.EntryHash, "state": v.State, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt})
}
