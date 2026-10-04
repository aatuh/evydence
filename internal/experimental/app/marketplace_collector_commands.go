package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

const MaxMarketplaceLabelBytes = 256
const MaxMarketplaceVersionBytes = 128
const MaxMarketplaceIDBytes = 1024
const MaxMarketplaceDigestBytes = 128

type MarketplaceCollectorInput struct{ Name, Provider, Version, Publisher, ManifestHash, SignatureID, SBOMID, ScanID string }
type MarketplaceReferenceIDs struct{ SignatureID, SBOMID, ScanID string }
type MarketplaceReferences struct{ TenantID, SignatureID, SBOMID, ScanID string }
type MarketplaceReferenceReader interface {
	ReadMarketplaceReferences(context.Context, string, MarketplaceReferenceIDs) (MarketplaceReferences, error)
}
type MarketplaceCollectorTransaction interface {
	MarketplaceReferenceReader
	application.AuditAppender
	InsertMarketplaceCollector(context.Context, experimentaldomain.MarketplaceCollector) error
}
type MarketplaceCollectorTransactions interface {
	ExecuteMarketplaceCollector(context.Context, string, func(context.Context, MarketplaceCollectorTransaction) error) error
}
type MarketplaceCollectorConfig struct {
	Transactions MarketplaceCollectorTransactions
	Clock        application.Clock
	IDs          application.IDGenerator
}
type MarketplaceCollectorCommands struct{ config MarketplaceCollectorConfig }

func NewMarketplaceCollectorCommands(c MarketplaceCollectorConfig) (*MarketplaceCollectorCommands, error) {
	if c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &MarketplaceCollectorCommands{c}, nil
}
func NormalizeMarketplaceCollectorInput(in MarketplaceCollectorInput) (MarketplaceCollectorInput, error) {
	for _, v := range []struct {
		text string
		max  int
	}{{in.Name, MaxMarketplaceLabelBytes}, {in.Provider, MaxMarketplaceLabelBytes}, {in.Version, MaxMarketplaceVersionBytes}, {in.Publisher, MaxMarketplaceLabelBytes}, {in.ManifestHash, MaxMarketplaceDigestBytes}, {in.SignatureID, MaxMarketplaceIDBytes}, {in.SBOMID, MaxMarketplaceIDBytes}, {in.ScanID, MaxMarketplaceIDBytes}} {
		if !anomalyText(v.text, v.max) {
			return in, ErrValidation
		}
	}
	for _, id := range []string{in.SignatureID, in.SBOMID, in.ScanID} {
		if id != "" && strings.TrimSpace(id) == "" {
			return in, ErrValidation
		}
	}
	in.Name, in.Provider, in.Version, in.Publisher, in.ManifestHash = strings.TrimSpace(in.Name), strings.TrimSpace(in.Provider), strings.TrimSpace(in.Version), strings.TrimSpace(in.Publisher), strings.TrimSpace(in.ManifestHash)
	in.SignatureID, in.SBOMID, in.ScanID = strings.TrimSpace(in.SignatureID), strings.TrimSpace(in.SBOMID), strings.TrimSpace(in.ScanID)
	if in.Name == "" || in.Provider == "" || in.Version == "" || in.Publisher == "" || !strings.HasPrefix(in.ManifestHash, "sha256:") || len(in.ManifestHash) != 71 {
		return in, ErrValidation
	}
	if _, err := hex.DecodeString(in.ManifestHash[7:]); err != nil {
		return in, ErrValidation
	}
	return in, nil
}
func AuthorizeMarketplaceCollectorActor(ctx context.Context, a identitydomain.Actor) error {
	if err := application.AuthorizeTenantWideScope(ctx, a, "collector:admin"); err != nil {
		return err
	}
	_, id := anomalyActor(a)
	if !anomalyID(a.TenantID) || !anomalyID(id) {
		return application.ErrUnauthorized
	}
	return nil
}
func BuildMarketplaceCollector(id, tenant string, in MarketplaceCollectorInput, at time.Time) (experimentaldomain.MarketplaceCollector, error) {
	in, err := NormalizeMarketplaceCollectorInput(in)
	if err != nil {
		return experimentaldomain.MarketplaceCollector{}, err
	}
	if !anomalyID(id) || !anomalyID(tenant) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return experimentaldomain.MarketplaceCollector{}, ErrValidation
	}
	return experimentaldomain.MarketplaceCollector{ID: id, TenantID: tenant, Name: in.Name, Provider: in.Provider, Version: in.Version, Publisher: in.Publisher, ManifestHash: in.ManifestHash, SignatureID: in.SignatureID, SBOMID: in.SBOMID, ScanID: in.ScanID, State: "registered", Limitations: []string{"Registration records package metadata and does not imply marketplace trust or endorsement."}, SchemaVersion: experimentaldomain.MarketplaceCollectorVersion, CreatedAt: at}, nil
}
func (c *MarketplaceCollectorCommands) prepare(ctx context.Context, a identitydomain.Actor, in MarketplaceCollectorInput) (MarketplaceCollectorInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := AuthorizeMarketplaceCollectorActor(ctx, a); err != nil {
		return in, err
	}
	return NormalizeMarketplaceCollectorInput(in)
}
func marketplaceReferences(in MarketplaceCollectorInput) MarketplaceReferenceIDs {
	return MarketplaceReferenceIDs{SignatureID: in.SignatureID, SBOMID: in.SBOMID, ScanID: in.ScanID}
}
func authorizedMarketplaceReferences(ctx context.Context, tx MarketplaceCollectorTransaction, a identitydomain.Actor, in MarketplaceCollectorInput) error {
	if err := AuthorizeMarketplaceCollectorActor(ctx, a); err != nil {
		return err
	}
	r, err := tx.ReadMarketplaceReferences(ctx, a.TenantID, marketplaceReferences(in))
	if err != nil {
		return err
	}
	if r.TenantID != a.TenantID || r.SignatureID != in.SignatureID || r.SBOMID != in.SBOMID || r.ScanID != in.ScanID {
		return ErrNotFound
	}
	return ctx.Err()
}
func (c *MarketplaceCollectorCommands) AuthorizeCreateMarketplaceCollector(ctx context.Context, a identitydomain.Actor, in MarketplaceCollectorInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteMarketplaceCollector(ctx, a.TenantID, func(ctx context.Context, tx MarketplaceCollectorTransaction) error {
		return authorizedMarketplaceReferences(ctx, tx, a, in)
	})
}
func (c *MarketplaceCollectorCommands) CreateMarketplaceCollector(ctx context.Context, a identitydomain.Actor, in MarketplaceCollectorInput) (experimentaldomain.MarketplaceCollector, error) {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return experimentaldomain.MarketplaceCollector{}, err
	}
	var out experimentaldomain.MarketplaceCollector
	err = c.config.Transactions.ExecuteMarketplaceCollector(ctx, a.TenantID, func(ctx context.Context, tx MarketplaceCollectorTransaction) error {
		if err := authorizedMarketplaceReferences(ctx, tx, a, in); err != nil {
			return err
		}
		at := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		out, err = BuildMarketplaceCollector(c.config.IDs.NewID("mpc"), a.TenantID, in, at)
		if err != nil {
			return err
		}
		auditID := c.config.IDs.NewID("ace")
		if !anomalyID(auditID) {
			return ErrValidation
		}
		if err := tx.InsertMarketplaceCollector(ctx, CloneMarketplaceCollector(out)); err != nil {
			return err
		}
		kind, id := anomalyActor(a)
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: auditID, TenantID: a.TenantID, EntryType: "marketplace_collector.created", SubjectType: "marketplace_collector", SubjectID: out.ID, ActorType: kind, ActorID: id, PayloadHash: in.ManifestHash, OccurredAt: at})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return experimentaldomain.MarketplaceCollector{}, err
	}
	return CloneMarketplaceCollector(out), nil
}
func CloneMarketplaceCollector(v experimentaldomain.MarketplaceCollector) experimentaldomain.MarketplaceCollector {
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func EncodeMarketplaceCollector(v experimentaldomain.MarketplaceCollector) ([]byte, error) {
	m := map[string]any{"id": v.ID, "tenant_id": v.TenantID, "name": v.Name, "provider": v.Provider, "version": v.Version, "publisher": v.Publisher, "manifest_hash": v.ManifestHash, "state": v.State, "limitations": v.Limitations, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt}
	for k, id := range map[string]string{"signature_id": v.SignatureID, "sbom_id": v.SBOMID, "scan_id": v.ScanID} {
		if id != "" {
			m[k] = id
		}
	}
	return json.Marshal(m)
}
