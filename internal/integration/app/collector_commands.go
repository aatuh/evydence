package app

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
)

const ScopeCollectorAdmin = "collector:admin"
const MaxCollectorKeyBytes = 2304

type CollectorReference struct{ ID, TenantID, Type, Digest string }
type CollectorWriteReader interface {
	LockCollectorWrites(context.Context, string) error
	CollectorNameExists(context.Context, string, string) (bool, error)
	CommercialCollectorIdentityExists(context.Context, string, string, string, string) (bool, error)
	ReadCollectorReleaseReference(context.Context, string, string, string) (CollectorReference, error)
}

// These flat ports cannot load inventories or reach unrelated context services.
type CollectorTransaction interface {
	CollectorWriteReader
	application.Authorizer
	application.AuditAppender
	InsertCollectorAPIKey(context.Context, identitydomain.APIKey) error
	InsertCollector(context.Context, integrationdomain.Collector) error
	InsertCollectorRelease(context.Context, integrationdomain.CollectorRelease) error
	InsertCommercialCollectorDefinition(context.Context, integrationdomain.CommercialCollectorDefinition) error
}
type CollectorTransactions interface {
	ExecuteCollector(context.Context, func(context.Context, CollectorTransaction) error) error
}
type CollectorCredential struct{ Secret, Prefix, Hash string }
type CollectorCredentials interface {
	GenerateCollectorCredential(context.Context) (CollectorCredential, error)
}
type CollectorCommandConfig struct {
	Transactions CollectorTransactions
	Credentials  CollectorCredentials
	Authorizer   application.Authorizer
	Clock        application.Clock
	IDs          application.IDGenerator
}
type CollectorCommands struct{ config CollectorCommandConfig }
type CreateCollectorInput struct {
	Name, Type, Version string
	Scopes              []string
}
type RecordCollectorReleaseInput struct {
	CollectorID, Version, ArtifactDigest, SignatureID, SBOMID, ScanID string
	Pinned                                                            bool
}
type CreateCommercialCollectorInput struct {
	Name, Provider, Version, ManifestHash string
	AllowedScopes                         []string
}

func NewCollectorCommands(c CollectorCommandConfig) (*CollectorCommands, error) {
	if c.Transactions == nil || c.Credentials == nil || c.Authorizer == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &CollectorCommands{c}, nil
}

type collectorWriteAuthorizer struct{}

func NewCollectorWriteAuthorizer() application.Authorizer { return collectorWriteAuthorizer{} }
func (collectorWriteAuthorizer) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.Scope != ScopeCollectorAdmin || r.ScopeOnly || !r.TenantWide || r.Resources != (application.ResourceReferences{}) {
		return application.ErrForbidden
	}
	return application.AuthorizeTenantWideScope(ctx, a, r.Scope)
}
func collectorAuthorization() application.AuthorizationRequest {
	return application.AuthorizationRequest{Scope: ScopeCollectorAdmin, TenantWide: true}
}
func collectorActor(a identitydomain.Actor) (string, string) {
	if a.CollectorID != "" {
		return "collector", a.CollectorID
	}
	if a.UserID != "" {
		return "human_user", a.UserID
	}
	return "api_key", a.KeyID
}
func (s *CollectorCommands) prepareActor(ctx context.Context, a identitydomain.Actor) error {
	if s == nil || ctx == nil {
		return ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, collectorAuthorization()); err != nil {
		return err
	}
	_, id := collectorActor(a)
	if !validSourceText(a.TenantID, 1024, false) || strings.TrimSpace(a.TenantID) != a.TenantID || !validSourceText(id, 1024, false) || strings.TrimSpace(id) != id {
		return ErrValidation
	}
	return nil
}
func ValidCollectorType(typ string) bool {
	switch strings.TrimSpace(typ) {
	case "github_actions", "gitlab_ci", "generic_ci", "import_bundle":
		return true
	}
	return false
}
func NormalizeCollectorScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > 1024 {
		return nil, ErrValidation
	}
	out := make([]string, len(scopes))
	for i, scope := range scopes {
		if !validSourceText(scope, 128, false) {
			return nil, ErrValidation
		}
		scope = strings.TrimSpace(scope)
		switch scope {
		case "build:write", "build:read", "evidence:write", "evidence:read", "source:write", "source:read", "bundle:write", "bundle:read":
		default:
			return nil, ErrValidation
		}
		out[i] = scope
	}
	sort.Strings(out)
	return out, nil
}
func collectorDigest(v string) bool {
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return false
	}
	raw, err := hex.DecodeString(v[7:])
	return err == nil && len(raw) == 32
}
func (s *CollectorCommands) prepareCreate(ctx context.Context, a identitydomain.Actor, in CreateCollectorInput) (CreateCollectorInput, error) {
	if err := s.prepareActor(ctx, a); err != nil {
		return in, err
	}
	for _, v := range []string{in.Name, in.Type, in.Version} {
		if !validSourceText(v, MaxSourceTextBytes, false) {
			return in, ErrValidation
		}
	}
	in.Name, in.Type, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Type), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Version == "" || !ValidCollectorType(in.Type) || len(a.TenantID)+len(in.Name) > MaxCollectorKeyBytes {
		return in, ErrValidation
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"build:write", "evidence:write"}
	}
	var err error
	in.Scopes, err = NormalizeCollectorScopes(in.Scopes)
	return in, err
}
func (s *CollectorCommands) prepareRelease(ctx context.Context, a identitydomain.Actor, in RecordCollectorReleaseInput) (RecordCollectorReleaseInput, error) {
	if err := s.prepareActor(ctx, a); err != nil {
		return in, err
	}
	for _, v := range []string{in.CollectorID, in.SignatureID, in.SBOMID, in.ScanID} {
		if !validSourceText(v, 1024, true) {
			return in, ErrValidation
		}
	}
	if !validSourceText(in.Version, MaxSourceTextBytes, false) || !validSourceText(in.ArtifactDigest, 128, false) {
		return in, ErrValidation
	}
	in.CollectorID, in.Version, in.ArtifactDigest, in.SignatureID, in.SBOMID, in.ScanID = strings.TrimSpace(in.CollectorID), strings.TrimSpace(in.Version), strings.TrimSpace(in.ArtifactDigest), strings.TrimSpace(in.SignatureID), strings.TrimSpace(in.SBOMID), strings.TrimSpace(in.ScanID)
	if in.CollectorID == "" || in.Version == "" || !collectorDigest(in.ArtifactDigest) {
		return in, ErrValidation
	}
	return in, nil
}
func (s *CollectorCommands) prepareCommercial(ctx context.Context, a identitydomain.Actor, in CreateCommercialCollectorInput) (CreateCommercialCollectorInput, error) {
	if err := s.prepareActor(ctx, a); err != nil {
		return in, err
	}
	for _, v := range []string{in.Name, in.Provider, in.Version} {
		if !validSourceText(v, MaxSourceTextBytes, false) {
			return in, ErrValidation
		}
	}
	in.Name, in.Provider, in.Version = strings.TrimSpace(in.Name), strings.TrimSpace(in.Provider), strings.TrimSpace(in.Version)
	if in.Name == "" || in.Provider == "" || in.Version == "" || !collectorDigest(in.ManifestHash) || len(a.TenantID)+len(in.Name)+len(in.Provider)+len(in.Version) > MaxCollectorKeyBytes {
		return in, ErrValidation
	}
	var err error
	in.AllowedScopes, err = NormalizeCollectorScopes(in.AllowedScopes)
	return in, err
}
func (s *CollectorCommands) execute(ctx context.Context, a identitydomain.Actor, fn func(context.Context, CollectorTransaction) error) error {
	return s.config.Transactions.ExecuteCollector(ctx, func(ctx context.Context, tx CollectorTransaction) error {
		if ctx == nil || tx == nil {
			return ErrValidation
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tx.Authorize(ctx, a, collectorAuthorization()); err != nil {
			return err
		}
		if err := tx.LockCollectorWrites(ctx, a.TenantID); err != nil {
			return err
		}
		if err := fn(ctx, tx); err != nil {
			return err
		}
		return ctx.Err()
	})
}
func authorizeCollectorReferences(ctx context.Context, tx CollectorTransaction, tenant string, in RecordCollectorReleaseInput) error {
	for _, ref := range []struct{ kind, id string }{{"collector", in.CollectorID}, {"signature", in.SignatureID}, {"sbom", in.SBOMID}, {"scan", in.ScanID}} {
		if ref.id == "" {
			continue
		}
		v, err := tx.ReadCollectorReleaseReference(ctx, tenant, ref.kind, ref.id)
		if err != nil {
			return err
		}
		if v.ID != ref.id || v.TenantID != tenant || v.Type != ref.kind || ref.kind == "signature" && v.Digest != in.ArtifactDigest {
			return ErrNotFound
		}
	}
	return nil
}

// Guards validate current authority before durable reservation/replay and do
// not generate credentials, reject their own existing names, or append effects.
func (s *CollectorCommands) AuthorizeCreateCollector(ctx context.Context, a identitydomain.Actor, in CreateCollectorInput) error {
	if _, err := s.prepareCreate(ctx, a, in); err != nil {
		return err
	}
	return s.execute(ctx, a, func(context.Context, CollectorTransaction) error { return nil })
}
func (s *CollectorCommands) AuthorizeRecordCollectorRelease(ctx context.Context, a identitydomain.Actor, in RecordCollectorReleaseInput) error {
	in, err := s.prepareRelease(ctx, a, in)
	if err != nil {
		return err
	}
	return s.execute(ctx, a, func(ctx context.Context, tx CollectorTransaction) error {
		return authorizeCollectorReferences(ctx, tx, a.TenantID, in)
	})
}
func (s *CollectorCommands) AuthorizeCreateCommercialCollectorDefinition(ctx context.Context, a identitydomain.Actor, in CreateCommercialCollectorInput) error {
	if _, err := s.prepareCommercial(ctx, a, in); err != nil {
		return err
	}
	return s.execute(ctx, a, func(context.Context, CollectorTransaction) error { return nil })
}
func validCollectorTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }
func validCollectorID(v string) bool {
	return validSourceText(v, 1024, false) && strings.TrimSpace(v) == v
}
func (s *CollectorCommands) appendAudit(ctx context.Context, tx CollectorTransaction, a identitydomain.Actor, now time.Time, action, kind, id, digest string) error {
	typ, actorID := collectorActor(a)
	e := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: action, SubjectType: kind, SubjectID: id, ActorType: typ, ActorID: actorID, PayloadHash: digest, OccurredAt: now}
	if !validCollectorID(e.ID) {
		return ErrValidation
	}
	_, err := tx.AppendAudit(ctx, e)
	return err
}
func (s *CollectorCommands) CreateCollector(ctx context.Context, a identitydomain.Actor, in CreateCollectorInput) (integrationdomain.Collector, identitydomain.APIKey, string, error) {
	in, err := s.prepareCreate(ctx, a, in)
	if err != nil {
		return integrationdomain.Collector{}, identitydomain.APIKey{}, "", err
	}
	var collector integrationdomain.Collector
	var key identitydomain.APIKey
	var secret string
	err = s.execute(ctx, a, func(ctx context.Context, tx CollectorTransaction) error {
		exists, err := tx.CollectorNameExists(ctx, a.TenantID, in.Name)
		if err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validCollectorTime(now) {
			return ErrValidation
		}
		credential, err := s.config.Credentials.GenerateCollectorCredential(ctx)
		if err != nil {
			return err
		}
		hash, err := hex.DecodeString(credential.Hash)
		if err != nil || len(hash) != 32 || !validSourceText(credential.Secret, 4096, false) || !validSourceText(credential.Prefix, 128, false) || !strings.HasPrefix(credential.Secret, credential.Prefix) || credential.Secret == credential.Prefix || credential.Hash == credential.Secret {
			return ErrValidation
		}
		secret = credential.Secret
		key = identitydomain.APIKey{ID: s.config.IDs.NewID("key"), TenantID: a.TenantID, Name: "collector:" + in.Name, Prefix: credential.Prefix, Hash: credential.Hash, Scopes: append([]string(nil), in.Scopes...), CreatedAt: now}
		status, _ := integrationdomain.ParseCollectorStatus("active")
		collector = integrationdomain.Collector{ID: s.config.IDs.NewID("col"), TenantID: a.TenantID, Name: in.Name, Type: in.Type, Version: in.Version, APIKeyID: key.ID, Status: status, AllowedScopes: append([]string(nil), in.Scopes...), SchemaVersion: integrationdomain.CollectorSchemaVersion, CreatedAt: now}
		if !validCollectorID(key.ID) || !validCollectorID(collector.ID) {
			return ErrValidation
		}
		storedKey := key
		storedKey.Scopes = append([]string(nil), key.Scopes...)
		if err := tx.InsertCollectorAPIKey(ctx, storedKey); err != nil {
			return err
		}
		stored := collector
		stored.AllowedScopes = append([]string(nil), collector.AllowedScopes...)
		if err := tx.InsertCollector(ctx, stored); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, a, now, "collector.created", "collector", collector.ID, "")
	})
	if err != nil {
		return integrationdomain.Collector{}, identitydomain.APIKey{}, "", err
	}
	key.Hash = ""
	return collector, key, secret, nil
}
func (s *CollectorCommands) RecordCollectorRelease(ctx context.Context, a identitydomain.Actor, in RecordCollectorReleaseInput) (integrationdomain.CollectorRelease, error) {
	in, err := s.prepareRelease(ctx, a, in)
	if err != nil {
		return integrationdomain.CollectorRelease{}, err
	}
	var out integrationdomain.CollectorRelease
	err = s.execute(ctx, a, func(ctx context.Context, tx CollectorTransaction) error {
		if err := authorizeCollectorReferences(ctx, tx, a.TenantID, in); err != nil {
			return err
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validCollectorTime(now) {
			return ErrValidation
		}
		status, health := "recorded", "needs_evidence"
		if in.SignatureID != "" && in.SBOMID != "" && in.ScanID != "" {
			status, health = "evidence_complete", "healthy"
		}
		out = integrationdomain.CollectorRelease{ID: s.config.IDs.NewID("colrel"), TenantID: a.TenantID, CollectorID: in.CollectorID, Version: in.Version, ArtifactDigest: in.ArtifactDigest, SignatureID: in.SignatureID, SBOMID: in.SBOMID, ScanID: in.ScanID, Pinned: in.Pinned, VerificationStatus: status, HealthStatus: health, Limitations: []string{"Collector supply-chain status reflects evidence recorded in Evydence and does not prove collector runtime safety."}, SchemaVersion: integrationdomain.CollectorReleaseSchemaVersion, CreatedAt: now}
		if !validCollectorID(out.ID) {
			return ErrValidation
		}
		stored := out
		stored.Limitations = append([]string(nil), out.Limitations...)
		if err := tx.InsertCollectorRelease(ctx, stored); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, a, now, "collector_release.recorded", "collector", in.CollectorID, in.ArtifactDigest)
	})
	if err != nil {
		return integrationdomain.CollectorRelease{}, err
	}
	return out, nil
}
func (s *CollectorCommands) CreateCommercialCollectorDefinition(ctx context.Context, a identitydomain.Actor, in CreateCommercialCollectorInput) (integrationdomain.CommercialCollectorDefinition, error) {
	in, err := s.prepareCommercial(ctx, a, in)
	if err != nil {
		return integrationdomain.CommercialCollectorDefinition{}, err
	}
	var out integrationdomain.CommercialCollectorDefinition
	err = s.execute(ctx, a, func(ctx context.Context, tx CollectorTransaction) error {
		exists, err := tx.CommercialCollectorIdentityExists(ctx, a.TenantID, in.Provider, in.Name, in.Version)
		if err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
		if !validCollectorTime(now) {
			return ErrValidation
		}
		out = integrationdomain.CommercialCollectorDefinition{ID: s.config.IDs.NewID("ccol"), TenantID: a.TenantID, Name: in.Name, Provider: in.Provider, Version: in.Version, ManifestHash: in.ManifestHash, AllowedScopes: append([]string(nil), in.AllowedScopes...), Status: "available", SchemaVersion: integrationdomain.CommercialCollectorVersion, CreatedAt: now}
		if !validCollectorID(out.ID) {
			return ErrValidation
		}
		stored := out
		stored.AllowedScopes = append([]string(nil), out.AllowedScopes...)
		if err := tx.InsertCommercialCollectorDefinition(ctx, stored); err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, a, now, "commercial_collector.created", "commercial_collector", out.ID, in.ManifestHash)
	})
	if err != nil {
		return integrationdomain.CommercialCollectorDefinition{}, err
	}
	return out, nil
}
