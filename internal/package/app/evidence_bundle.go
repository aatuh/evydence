package app

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

const EvidenceBundleSnapshotVersion = "evidence-bundle-snapshot.v1.0.0"

// EvidenceBundleEvidence is the tenant-scoped authorization coordinate stored
// in a committed export snapshot. It never includes raw evidence payloads.
type EvidenceBundleEvidence struct {
	ID        string
	Resources application.ResourceReferences
}

// EvidenceBundleSnapshot is the complete immutable input to one export. The
// adapter must obtain every field from one committed read view.
type EvidenceBundleSnapshot struct {
	SnapshotVersion  string
	TenantID         string
	ProductID        string
	ReleaseID        string
	Evidence         []EvidenceBundleEvidence
	AuditChainHead   string
	ObjectLockProofs []map[string]any
}

func (s *ExportCommands) ExportEvidenceBundle(ctx context.Context, actor identitydomain.Actor, releaseID string, evidenceIDs []string) (packagedomain.EvidenceBundle, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", ScopeOnly: true}); err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	releaseID = strings.TrimSpace(releaseID)
	requestedIDs, err := normalizedNonEmptyStrings(evidenceIDs, true)
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	now := s.config.Clock.Now().UTC()
	snapshot, err := s.config.Reader.ReadEvidenceBundleSnapshot(ctx, actor.TenantID, releaseID, now)
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	snapshot = cloneEvidenceBundleSnapshot(snapshot)
	if snapshot.TenantID != actor.TenantID || snapshot.ReleaseID != releaseID {
		return packagedomain.EvidenceBundle{}, ErrNotFound
	}
	if !validEvidenceBundleSnapshot(snapshot) {
		return packagedomain.EvidenceBundle{}, ErrConflict
	}
	rootResources := application.ResourceReferences{ProductID: snapshot.ProductID, ReleaseID: releaseID}
	if releaseID != "" {
		if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: rootResources}); err != nil {
			return packagedomain.EvidenceBundle{}, err
		}
	}

	byID := make(map[string]EvidenceBundleEvidence, len(snapshot.Evidence))
	for _, item := range snapshot.Evidence {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			return packagedomain.EvidenceBundle{}, ErrConflict
		}
		if _, duplicate := byID[id]; duplicate {
			return packagedomain.EvidenceBundle{}, ErrConflict
		}
		if releaseID != "" && item.Resources.ReleaseID != releaseID {
			return packagedomain.EvidenceBundle{}, ErrConflict
		}
		item.ID = id
		byID[id] = item
	}
	selected := make([]string, 0)
	if len(requestedIDs) > 0 {
		for _, id := range requestedIDs {
			item, ok := byID[id]
			if !ok {
				return packagedomain.EvidenceBundle{}, ErrNotFound
			}
			if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: item.Resources}); err != nil {
				return packagedomain.EvidenceBundle{}, err
			}
			selected = append(selected, id)
		}
	} else {
		for id, item := range byID {
			if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:read", Resources: item.Resources}); err != nil {
				if errors.Is(err, ErrForbidden) {
					continue
				}
				return packagedomain.EvidenceBundle{}, err
			}
			selected = append(selected, id)
		}
	}
	sort.Strings(selected)
	selectedItems := make([]EvidenceBundleEvidence, 0, len(selected))
	for _, id := range selected {
		selectedItems = append(selectedItems, byID[id])
	}
	bundleID := s.config.IDs.NewID("eb")
	manifest := map[string]any{
		"bundle_version": packagedomain.EvidenceBundleSchemaVersion, "tenant_id": actor.TenantID,
		"release_id": releaseID, "evidence_ids": append([]string(nil), selected...),
		"audit_chain_head": snapshot.AuditChainHead, "object_lock_proofs": cloneBundleMapSlice(snapshot.ObjectLockProofs),
		"verification":        "Run evydence verify-evidence-bundle <bundle.json> offline.",
		"verification_limits": []string{"Object-lock proof records reflect Evydence verification metadata and do not prove legal compliance, provider IAM correctness, or complete WORM enforcement."},
	}
	manifestHash, err := s.config.Hasher.HashPackageManifest(ctx, manifest)
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	if strings.TrimSpace(manifestHash) == "" {
		return packagedomain.EvidenceBundle{}, ErrValidation
	}
	signature, err := s.config.Signer.SignPackage(ctx, PackageSigningRequest{
		TenantID: actor.TenantID, SubjectType: "evidence_bundle", SubjectID: bundleID, PayloadHash: manifestHash, CreatedAt: now,
	})
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	if !validPackageSignature(signature, actor.TenantID, "evidence_bundle", bundleID, now) {
		return packagedomain.EvidenceBundle{}, ErrConflict
	}
	bundle := packagedomain.EvidenceBundle{
		ID: bundleID, TenantID: actor.TenantID, ReleaseID: releaseID, EvidenceIDs: selected,
		Manifest: manifest, ManifestHash: manifestHash, SignatureRefs: []string{signature.ID},
		VerificationText: "Verify manifest_hash over manifest canonical JSON and signature references with tenant public keys.",
		SchemaVersion:    packagedomain.EvidenceBundleSchemaVersion, CreatedAt: now,
	}
	err = s.config.Transactions.ExecuteEvidenceBundleExport(ctx, func(ctx context.Context, tx ExportTransaction) error {
		if err := tx.AuthorizeEvidenceBundleSelection(ctx, actor, rootResources, selectedItems); err != nil {
			return err
		}
		if err := tx.InsertEvidenceBundleSignature(ctx, signature, manifestHash); err != nil {
			return err
		}
		if err := tx.InsertEvidenceBundle(ctx, bundle); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "evidence_bundle.exported", SubjectType: "evidence_bundle", SubjectID: bundle.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now, PayloadHash: manifestHash, SignatureRef: signature.ID})
		return err
	})
	if err != nil {
		return packagedomain.EvidenceBundle{}, err
	}
	return cloneEvidenceBundle(bundle), nil
}

func (s *ImportCommands) ImportEvidenceBundle(ctx context.Context, actor identitydomain.Actor, bundle packagedomain.EvidenceBundle) (packagedomain.EvidenceBundleImport, error) {
	if err := contextError(ctx); err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	if err := validateActor(actor); err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:write", ScopeOnly: true}); err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	if err := validateReportTemplateTenant(actor); err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	if err := ValidatePortableBundleInput(bundle); err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	bundle = cloneEvidenceBundle(bundle)
	if len(bundle.Manifest) == 0 || strings.TrimSpace(bundle.ManifestHash) == "" {
		return packagedomain.EvidenceBundleImport{}, ErrValidation
	}
	hash, err := s.config.Hasher.HashPackageManifest(ctx, bundle.Manifest)
	if err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	if hash != bundle.ManifestHash {
		return packagedomain.EvidenceBundleImport{}, ErrValidation
	}
	version, ok := bundle.Manifest["bundle_version"].(string)
	if !ok || version != packagedomain.EvidenceBundleSchemaVersion {
		return packagedomain.EvidenceBundleImport{}, ErrValidation
	}
	manifestIDs, ok := evidenceIDsFromManifest(bundle.Manifest["evidence_ids"])
	if !ok {
		return packagedomain.EvidenceBundleImport{}, ErrValidation
	}
	outerIDs, err := normalizedNonEmptyStrings(bundle.EvidenceIDs, true)
	if err != nil || !reflect.DeepEqual(manifestIDs, outerIDs) {
		return packagedomain.EvidenceBundleImport{}, ErrValidation
	}
	var record packagedomain.EvidenceBundleImport
	err = s.config.Transactions.ExecuteBundleImport(ctx, func(ctx context.Context, tx ImportTransaction) error {
		if err := tx.Authorize(ctx, actor, application.AuthorizationRequest{Scope: "bundle:write", TenantWide: true}); err != nil {
			return err
		}
		if guard, ok := tx.(BundleImportScopeLocker); ok {
			if err := guard.LockBundleImportTenant(ctx, actor.TenantID); err != nil {
				return err
			}
		}
		now := s.config.Clock.Now().UTC()
		record = packagedomain.EvidenceBundleImport{ID: s.config.IDs.NewID("ebi"), TenantID: actor.TenantID, BundleHash: bundle.ManifestHash, Result: "accepted", ImportedCount: len(manifestIDs), SchemaVersion: packagedomain.EvidenceBundleImportVersion, CreatedAt: now}
		if err := tx.InsertEvidenceBundleImport(ctx, record); err != nil {
			return err
		}
		_, err := tx.AppendAudit(ctx, application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: actor.TenantID, EntryType: "evidence_bundle.imported", SubjectType: "evidence_bundle_import", SubjectID: record.ID, ActorType: auditActorType(actor), ActorID: auditActorID(actor), OccurredAt: now, PayloadHash: bundle.ManifestHash})
		return err
	})
	if err != nil {
		return packagedomain.EvidenceBundleImport{}, err
	}
	return record, nil
}

func validEvidenceBundleSnapshot(snapshot EvidenceBundleSnapshot) bool {
	if snapshot.SnapshotVersion != EvidenceBundleSnapshotVersion {
		return false
	}
	return snapshot.ReleaseID == "" || strings.TrimSpace(snapshot.ProductID) != ""
}

func evidenceIDsFromManifest(value any) ([]string, bool) {
	var values []string
	switch typed := value.(type) {
	case []string:
		values = append([]string(nil), typed...)
	case []any:
		values = make([]string, 0, len(typed))
		for _, value := range typed {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			values = append(values, text)
		}
	default:
		return nil, false
	}
	normalized, err := normalizedNonEmptyStrings(values, true)
	return normalized, err == nil && len(normalized) == len(values)
}

func cloneEvidenceBundleSnapshot(value EvidenceBundleSnapshot) EvidenceBundleSnapshot {
	value.Evidence = append([]EvidenceBundleEvidence(nil), value.Evidence...)
	value.ObjectLockProofs = cloneBundleMapSlice(value.ObjectLockProofs)
	return value
}

func cloneEvidenceBundle(value packagedomain.EvidenceBundle) packagedomain.EvidenceBundle {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.Manifest = cloneBundleMap(value.Manifest)
	value.SignatureRefs = append([]string(nil), value.SignatureRefs...)
	return value
}
