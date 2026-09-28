package app

import (
	"context"
	"strings"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const ReleaseBundleSnapshotVersion = "release-bundle-snapshot.v1.0.0"

// ReleaseBundleSnapshot is the complete committed input to bundle generation.
// It deliberately contains values rather than repositories or context maps.
type ReleaseBundleSnapshot struct {
	SnapshotVersion  string
	TenantID         string
	ProductID        string
	ReleaseID        string
	ReleaseVersion   string
	ReleaseState     string
	EvidenceIDs      []string
	ChainSequence    int
	ChainHeadHash    string
	ObjectLockProofs []map[string]any
}

type PackageSigningRequest struct {
	TenantID    string
	SubjectType string
	SubjectID   string
	PayloadHash string
	CreatedAt   time.Time
}

// PackageSignature is the persistence-safe output of the cryptographic
// adapter. Private key material never crosses this port.
type PackageSignature struct {
	ID          string
	TenantID    string
	SubjectType string
	SubjectID   string
	KeyID       string
	Algorithm   string
	Value       string
	CreatedAt   time.Time
}

type PackageSigner interface {
	SignPackage(context.Context, PackageSigningRequest) (PackageSignature, error)
}

type PackageSignatureRepository interface {
	InsertPackageSignature(context.Context, PackageSignature) error
}

func (s *Service) CreateReleaseBundle(ctx context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseBundle, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	if err := s.authorize(ctx, actor, "bundle:write", application.ResourceReferences{}, true); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	if releaseID == "" {
		return packagedomain.ReleaseBundle{}, ErrValidation
	}
	if s.projectionRefresher != nil {
		if err := s.projectionRefresher.RefreshPackageProjection(ctx, actor.TenantID); err != nil {
			return packagedomain.ReleaseBundle{}, err
		}
	}
	snapshot, err := s.reader.ReadCommittedReleaseBundleSnapshot(ctx, actor.TenantID, releaseID)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	snapshot = cloneReleaseBundleSnapshot(snapshot)
	if snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != releaseID {
		return packagedomain.ReleaseBundle{}, ErrNotFound
	}
	if !validReleaseBundleSnapshot(snapshot) {
		return packagedomain.ReleaseBundle{}, ErrConflict
	}
	resources := application.ResourceReferences{ProductID: snapshot.ProductID, ReleaseID: snapshot.ReleaseID}
	if err := s.authorize(ctx, actor, "bundle:write", resources, false); err != nil {
		return packagedomain.ReleaseBundle{}, err
	}

	now := s.clock.Now().UTC()
	bundleID := s.ids.NewID("rb")
	evidenceIDs, _ := normalizedNonEmptyStrings(snapshot.EvidenceIDs, false)
	manifest := map[string]any{
		"manifest_version": packagedomain.ReleaseBundleSchemaVersion,
		"bundle_id":        bundleID, "tenant_id": actor.TenantID,
		"release":            map[string]any{"id": snapshot.ReleaseID, "version": snapshot.ReleaseVersion, "state": snapshot.ReleaseState},
		"evidence_ids":       evidenceIDs,
		"chain_checkpoint":   map[string]any{"sequence": snapshot.ChainSequence, "head_hash": snapshot.ChainHeadHash},
		"generated_at":       now.Format(time.RFC3339Nano),
		"generator":          map[string]any{"name": "evydence", "version": "dev"},
		"object_lock_proofs": cloneBundleMapSlice(snapshot.ObjectLockProofs),
	}
	manifestHash, err := s.canonicalizer.HashPackageManifest(ctx, manifest)
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	if strings.TrimSpace(manifestHash) == "" {
		return packagedomain.ReleaseBundle{}, ErrValidation
	}
	signature, err := s.signer.SignPackage(ctx, PackageSigningRequest{
		TenantID: actor.TenantID, SubjectType: "release_bundle", SubjectID: bundleID, PayloadHash: manifestHash, CreatedAt: now,
	})
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	if !validReleaseBundleSignature(signature, actor.TenantID, bundleID, now) {
		return packagedomain.ReleaseBundle{}, ErrConflict
	}
	state, err := packagedomain.ParseBundleState(packagedomain.BundleStateGeneratedValue)
	if err != nil {
		return packagedomain.ReleaseBundle{}, ErrValidation
	}
	bundle := packagedomain.ReleaseBundle{
		ID: bundleID, TenantID: actor.TenantID, ReleaseID: snapshot.ReleaseID, State: state,
		Manifest: manifest, ManifestHash: manifestHash, SignatureRefs: []string{signature.ID}, CreatedAt: now,
	}
	err = s.transactions.Execute(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Authorization().Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:write", Resources: resources}); err != nil {
			return err
		}
		if err := tx.Signatures().InsertPackageSignature(ctx, signature); err != nil {
			return err
		}
		if err := tx.Packages().InsertReleaseBundle(ctx, bundle); err != nil {
			return err
		}
		audit := s.auditEvent(actor, now, "bundle.generated", "release_bundle", bundle.ID, manifestHash)
		audit.SignatureRef = signature.ID
		if _, err := tx.Audit().AppendAudit(ctx, audit); err != nil {
			return err
		}
		return tx.Outbox().EnqueueOutbox(ctx, application.OutboxEvent{
			ID: s.ids.NewID("job"), TenantID: actor.TenantID, Kind: "sign_bundle", SubjectType: "release_bundle",
			SubjectID: bundle.ID, Payload: map[string]any{"manifest_hash": manifestHash}, CreatedAt: now,
		})
	})
	if err != nil {
		return packagedomain.ReleaseBundle{}, err
	}
	return cloneReleaseBundle(bundle), nil
}

func validReleaseBundleSnapshot(snapshot ReleaseBundleSnapshot) bool {
	return snapshot.SnapshotVersion == ReleaseBundleSnapshotVersion && strings.TrimSpace(snapshot.ProductID) != "" &&
		strings.TrimSpace(snapshot.ReleaseVersion) != "" && strings.TrimSpace(snapshot.ReleaseState) != "" && snapshot.ChainSequence >= 0
}

func validReleaseBundleSignature(signature PackageSignature, tenantID, bundleID string, createdAt time.Time) bool {
	return validPackageSignature(signature, tenantID, "release_bundle", bundleID, createdAt)
}

func validPackageSignature(signature PackageSignature, tenantID, subjectType, subjectID string, createdAt time.Time) bool {
	return strings.TrimSpace(signature.ID) != "" && signature.TenantID == tenantID && signature.SubjectType == subjectType &&
		signature.SubjectID == subjectID && strings.TrimSpace(signature.KeyID) != "" && strings.TrimSpace(signature.Algorithm) != "" &&
		strings.TrimSpace(signature.Value) != "" && signature.CreatedAt.Equal(createdAt)
}

func cloneReleaseBundleSnapshot(value ReleaseBundleSnapshot) ReleaseBundleSnapshot {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.ObjectLockProofs = cloneBundleMapSlice(value.ObjectLockProofs)
	return value
}

func cloneReleaseBundle(value packagedomain.ReleaseBundle) packagedomain.ReleaseBundle {
	value.Manifest = cloneBundleMap(value.Manifest)
	value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
	if value.PublishedAt != nil {
		publishedAt := *value.PublishedAt
		value.PublishedAt = &publishedAt
	}
	if value.RevokedAt != nil {
		revokedAt := *value.RevokedAt
		value.RevokedAt = &revokedAt
	}
	return value
}

func cloneBundleMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	result := make(map[string]any, len(value))
	for key, child := range value {
		result[key] = cloneBundleValue(child)
	}
	return result
}

func cloneBundleMapSlice(values []map[string]any) []map[string]any {
	if values == nil {
		return nil
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		result = append(result, cloneBundleMap(value))
	}
	return result
}

func cloneBundleValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneBundleMap(typed)
	case []map[string]any:
		return cloneBundleMapSlice(typed)
	case []any:
		if typed == nil {
			return []any(nil)
		}
		result := make([]any, 0, len(typed))
		for _, child := range typed {
			result = append(result, cloneBundleValue(child))
		}
		return result
	case []string:
		if typed == nil {
			return []string(nil)
		}
		result := make([]string, len(typed))
		copy(result, typed)
		return result
	case map[string]int:
		result := make(map[string]int, len(typed))
		for key, child := range typed {
			result[key] = child
		}
		return result
	default:
		return typed
	}
}
