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

const MaxSaaSProfileNameBytes = 256
const MaxSaaSProfileRegionBytes = 128
const MaxSaaSProfileIsolationBytes = 256
const MaxSaaSProfileIDBytes = 1024

// Untagged fields preserve the legacy raw-input configuration hash profile.
type SaaSProfileInput struct{ Name, Region, AdminTenantID, IsolationModel string }
type SaaSProfileTenants struct{ TenantID, AdminTenantID string }
type SaaSProfileTenantReader interface {
	ReadSaaSProfileTenants(context.Context, string, string) (SaaSProfileTenants, error)
}
type SaaSProfileTransaction interface {
	SaaSProfileTenantReader
	application.AuditAppender
	InsertSaaSProfile(context.Context, experimentaldomain.SaaSEditionProfile) error
}
type SaaSProfileTransactions interface {
	ExecuteSaaSProfile(context.Context, string, func(context.Context, SaaSProfileTransaction) error) error
}
type SaaSProfileConfig struct {
	Transactions SaaSProfileTransactions
	Clock        application.Clock
	IDs          application.IDGenerator
}
type SaaSProfileCommands struct{ config SaaSProfileConfig }

func NewSaaSProfileCommands(c SaaSProfileConfig) (*SaaSProfileCommands, error) {
	if c.Transactions == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &SaaSProfileCommands{c}, nil
}
func NormalizeSaaSProfileInput(in SaaSProfileInput) (SaaSProfileInput, error) {
	for _, v := range []struct {
		value string
		max   int
	}{{in.Name, MaxSaaSProfileNameBytes}, {in.Region, MaxSaaSProfileRegionBytes}, {in.AdminTenantID, MaxSaaSProfileIDBytes}, {in.IsolationModel, MaxSaaSProfileIsolationBytes}} {
		if !anomalyText(v.value, v.max) || strings.TrimSpace(v.value) == "" {
			return in, ErrValidation
		}
	}
	in.Name, in.Region, in.AdminTenantID, in.IsolationModel = strings.TrimSpace(in.Name), strings.TrimSpace(in.Region), strings.TrimSpace(in.AdminTenantID), strings.TrimSpace(in.IsolationModel)
	return in, nil
}
func AuthorizeSaaSProfileActor(ctx context.Context, a identitydomain.Actor) error {
	if err := application.AuthorizeInstanceScope(ctx, a, "instance:admin"); err != nil {
		return err
	}
	_, id := anomalyActor(a)
	if !anomalyID(a.TenantID) || !anomalyID(id) {
		return application.ErrUnauthorized
	}
	return nil
}
func SaaSProfileConfigHash(in SaaSProfileInput) (string, error) {
	if _, err := NormalizeSaaSProfileInput(in); err != nil {
		return "", err
	}
	return application.NormalizedJSONHash(in)
}
func BuildSaaSProfile(id, tenant string, in SaaSProfileInput, hash string, at time.Time) (experimentaldomain.SaaSEditionProfile, error) {
	in, err := NormalizeSaaSProfileInput(in)
	if err != nil {
		return experimentaldomain.SaaSEditionProfile{}, err
	}
	if !anomalyID(id) || !anomalyID(tenant) || at.IsZero() || at.Year() < 1 || at.Year() > 9999 || len(hash) != 71 || !strings.HasPrefix(hash, "sha256:") {
		return experimentaldomain.SaaSEditionProfile{}, ErrValidation
	}
	if _, err := hex.DecodeString(hash[7:]); err != nil {
		return experimentaldomain.SaaSEditionProfile{}, ErrValidation
	}
	return experimentaldomain.SaaSEditionProfile{ID: id, TenantID: tenant, Name: in.Name, Region: in.Region, AdminTenantID: in.AdminTenantID, IsolationModel: in.IsolationModel, Status: "proposed", ConfigHash: hash, Limitations: []string{"This profile records SaaS edition configuration intent; it is not a deployment readiness certification."}, SchemaVersion: experimentaldomain.SaaSEditionProfileVersion, CreatedAt: at}, nil
}
func (c *SaaSProfileCommands) prepare(ctx context.Context, a identitydomain.Actor, in SaaSProfileInput) (SaaSProfileInput, error) {
	if c == nil {
		return in, ErrValidation
	}
	if err := AuthorizeSaaSProfileActor(ctx, a); err != nil {
		return in, err
	}
	return NormalizeSaaSProfileInput(in)
}
func authorizedSaaSProfileTenants(ctx context.Context, tx SaaSProfileTransaction, a identitydomain.Actor, in SaaSProfileInput) error {
	if err := AuthorizeSaaSProfileActor(ctx, a); err != nil {
		return err
	}
	r, err := tx.ReadSaaSProfileTenants(ctx, a.TenantID, in.AdminTenantID)
	if err != nil {
		return err
	}
	if r.TenantID != a.TenantID || r.AdminTenantID != in.AdminTenantID {
		return ErrNotFound
	}
	return ctx.Err()
}
func (c *SaaSProfileCommands) AuthorizeCreateSaaSProfile(ctx context.Context, a identitydomain.Actor, in SaaSProfileInput) error {
	in, err := c.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return c.config.Transactions.ExecuteSaaSProfile(ctx, a.TenantID, func(ctx context.Context, tx SaaSProfileTransaction) error {
		return authorizedSaaSProfileTenants(ctx, tx, a, in)
	})
}
func (c *SaaSProfileCommands) CreateSaaSProfile(ctx context.Context, a identitydomain.Actor, raw SaaSProfileInput) (experimentaldomain.SaaSEditionProfile, error) {
	in, err := c.prepare(ctx, a, raw)
	if err != nil {
		return experimentaldomain.SaaSEditionProfile{}, err
	}
	var out experimentaldomain.SaaSEditionProfile
	err = c.config.Transactions.ExecuteSaaSProfile(ctx, a.TenantID, func(ctx context.Context, tx SaaSProfileTransaction) error {
		if err := authorizedSaaSProfileTenants(ctx, tx, a, in); err != nil {
			return err
		}
		hash, err := SaaSProfileConfigHash(raw)
		if err != nil {
			return err
		}
		at := c.config.Clock.Now().UTC().Truncate(time.Microsecond)
		out, err = BuildSaaSProfile(c.config.IDs.NewID("saas"), a.TenantID, in, hash, at)
		if err != nil {
			return err
		}
		auditID := c.config.IDs.NewID("ace")
		if !anomalyID(auditID) {
			return ErrValidation
		}
		if err := tx.InsertSaaSProfile(ctx, CloneSaaSProfile(out)); err != nil {
			return err
		}
		kind, id := anomalyActor(a)
		_, err = tx.AppendAudit(ctx, application.AuditEvent{ID: auditID, TenantID: a.TenantID, EntryType: "saas_profile.created", SubjectType: "saas_profile", SubjectID: out.ID, ActorType: kind, ActorID: id, PayloadHash: hash, OccurredAt: at})
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return experimentaldomain.SaaSEditionProfile{}, err
	}
	return CloneSaaSProfile(out), nil
}
func CloneSaaSProfile(v experimentaldomain.SaaSEditionProfile) experimentaldomain.SaaSEditionProfile {
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}
func EncodeSaaSProfile(v experimentaldomain.SaaSEditionProfile) ([]byte, error) {
	return json.Marshal(map[string]any{"id": v.ID, "tenant_id": v.TenantID, "name": v.Name, "region": v.Region, "admin_tenant_id": v.AdminTenantID, "isolation_model": v.IsolationModel, "status": v.Status, "config_hash": v.ConfigHash, "limitations": v.Limitations, "schema_version": v.SchemaVersion, "created_at": v.CreatedAt})
}
