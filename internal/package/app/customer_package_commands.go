package app

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

const (
	CustomerPackageSnapshotVersion = "package-snapshot.v1.0.0"
	MaxCustomerPackageTitleBytes   = 4096
)

// The database adapter returns public manifest inputs and the selected policy
// from one committed, bounded snapshot. It never returns payload bytes, storage
// locations, credentials, or another context's repositories/services.
type CustomerPackageCreationSnapshot struct {
	Profile  packagedomain.RedactionProfile
	Snapshot PackageSnapshot
}
type CustomerPackageSnapshotReader interface {
	ReadCustomerPackageCreationSnapshot(context.Context, string, string, string, string, time.Time) (CustomerPackageCreationSnapshot, error)
}
type CustomerPackageCreationTransaction interface {
	GetRedactionProfile(context.Context, string, string) (packagedomain.RedactionProfile, error)
	InsertCustomerSecurityPackage(context.Context, packagedomain.CustomerSecurityPackage) error
	application.Authorizer
	application.AuditAppender
}
type CustomerPackageCreationTransactions interface {
	ExecuteCustomerPackageCreation(context.Context, func(context.Context, CustomerPackageCreationTransaction) error) error
}
type CustomerPackageCommandConfig struct {
	Reader       CustomerPackageSnapshotReader
	Transactions CustomerPackageCreationTransactions
	Authorizer   application.Authorizer
	Hasher       ManifestHasher
	Clock        application.Clock
	IDs          application.IDGenerator
}

// CustomerPackageCommands freezes one snapshot into the existing manifest
// format. Its write boundary can only validate scope/policy and append the
// package and audit record; it cannot navigate unrelated context internals.
type CustomerPackageCommands struct{ config CustomerPackageCommandConfig }

func NewCustomerPackageCommands(c CustomerPackageCommandConfig) (*CustomerPackageCommands, error) {
	if c.Reader == nil || c.Transactions == nil || c.Authorizer == nil || c.Hasher == nil || c.Clock == nil || c.IDs == nil {
		return nil, ErrValidation
	}
	return &CustomerPackageCommands{config: c}, nil
}

// Check raw byte bounds before trimming. Future expiry is deliberately checked
// only for fresh creation, not by the idempotency replay guard.
func NormalizeCustomerPackageInput(in CreateCustomerPackageInput) (CreateCustomerPackageInput, error) {
	for _, id := range []string{in.ProductID, in.ReleaseID, in.RedactionProfileID} {
		if !redactionText(id, MaxCustomerPackageIDBytes) {
			return CreateCustomerPackageInput{}, ErrValidation
		}
	}
	if !redactionText(in.Title, MaxCustomerPackageTitleBytes) || in.ExpiresAt.IsZero() || in.ExpiresAt.Year() < 1 || in.ExpiresAt.Year() > 9999 {
		return CreateCustomerPackageInput{}, ErrValidation
	}
	in.ProductID = strings.TrimSpace(in.ProductID)
	in.ReleaseID = strings.TrimSpace(in.ReleaseID)
	in.RedactionProfileID = strings.TrimSpace(in.RedactionProfileID)
	in.Title = strings.TrimSpace(in.Title)
	in.ExpiresAt = in.ExpiresAt.UTC()
	if in.ProductID == "" || in.RedactionProfileID == "" || in.Title == "" || !customerCreationTime(in.ExpiresAt) {
		return CreateCustomerPackageInput{}, ErrValidation
	}
	return in, nil
}

func (s *CustomerPackageCommands) prepare(ctx context.Context, a identitydomain.Actor, in CreateCustomerPackageInput) (CreateCustomerPackageInput, error) {
	if s == nil {
		return CreateCustomerPackageInput{}, ErrValidation
	}
	if err := contextError(ctx); err != nil {
		return CreateCustomerPackageInput{}, err
	}
	if err := validateActor(a); err != nil {
		return CreateCustomerPackageInput{}, err
	}
	if !redactionID(a.TenantID) || !redactionID(auditActorID(a)) {
		return CreateCustomerPackageInput{}, ErrForbidden
	}
	if err := s.config.Authorizer.Authorize(ctx, a, application.AuthorizationRequest{Scope: ScopePackageWrite, ScopeOnly: true}); err != nil {
		return CreateCustomerPackageInput{}, err
	}
	in, err := NormalizeCustomerPackageInput(in)
	if err != nil {
		return CreateCustomerPackageInput{}, err
	}
	if err := s.config.Authorizer.Authorize(ctx, a, customerCreationAuthorization(in)); err != nil {
		return CreateCustomerPackageInput{}, err
	}
	return in, nil
}
func customerCreationAuthorization(in CreateCustomerPackageInput) application.AuthorizationRequest {
	return application.AuthorizationRequest{Scope: ScopePackageWrite, Resources: application.ResourceReferences{ProductID: in.ProductID, ReleaseID: in.ReleaseID}}
}

// Run before both fresh creation and replay. The adapter re-resolves and locks
// the current tenant-owned parents before authorizing. No frozen evidence is
// read, and no package IDs, manifests, or audit records are generated here.
func (s *CustomerPackageCommands) AuthorizeCreateCustomerSecurityPackage(ctx context.Context, a identitydomain.Actor, in CreateCustomerPackageInput) error {
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return err
	}
	return s.config.Transactions.ExecuteCustomerPackageCreation(ctx, func(ctx context.Context, tx CustomerPackageCreationTransaction) error {
		if err := tx.Authorize(ctx, a, customerCreationAuthorization(in)); err != nil {
			return err
		}
		profile, err := tx.GetRedactionProfile(ctx, a.TenantID, in.RedactionProfileID)
		if err != nil {
			return err
		}
		if !validCustomerCreationProfile(profile, a.TenantID, in.RedactionProfileID) {
			return ErrNotFound
		}
		return contextError(ctx)
	})
}

func (s *CustomerPackageCommands) CreateCustomerSecurityPackage(ctx context.Context, a identitydomain.Actor, in CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	var empty packagedomain.CustomerSecurityPackage
	in, err := s.prepare(ctx, a, in)
	if err != nil {
		return empty, err
	}
	now := s.config.Clock.Now().UTC().Truncate(time.Microsecond)
	if !customerCreationTime(now) || !in.ExpiresAt.After(now) {
		return empty, ErrValidation
	}
	view, err := s.config.Reader.ReadCustomerPackageCreationSnapshot(ctx, a.TenantID, in.ProductID, in.ReleaseID, in.RedactionProfileID, now)
	if err != nil {
		return empty, err
	}
	if !validCustomerCreationProfile(view.Profile, a.TenantID, in.RedactionProfileID) {
		return empty, ErrNotFound
	}
	if !validPackageSnapshot(view.Snapshot, a.TenantID, in.ProductID, in.ReleaseID) || len(view.Snapshot.Evidence) > MaxSecurityReviewEvidenceIDs {
		return empty, ErrConflict
	}
	// Database readers preflight rows/bytes before transfer. This independent
	// check rejects invalid/oversized adapter results before recursive copying,
	// ID generation, hashing, or writes (including cyclic/non-JSON values).
	encoded, err := json.Marshal(view.Snapshot)
	if err != nil || !customerCreationJSON(encoded) {
		return empty, ErrConflict
	}
	// Normalize arbitrary JSON-compatible adapter values before redaction:
	// typed maps, structs, and RawMessage must not bypass recursive key checks.
	// UseNumber keeps large artifact sizes/counts exact while making an owned
	// tree independent of the reader's maps and slices.
	var snapshot PackageSnapshot
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&snapshot); err != nil {
		return empty, ErrConflict
	}
	snapshot = restoreCustomerSnapshotMetadata(view.Snapshot, snapshot, view.Profile.ExcludedFields)
	profile := cloneRedactionProfile(view.Profile)
	profile.CreatedAt = profile.CreatedAt.UTC()
	id := s.config.IDs.NewID("csp")
	if !redactionID(id) {
		return empty, ErrValidation
	}
	manifest := sanitizeManifestMap(buildCustomerPackageManifest(id, now, in.Title, profile, snapshot), profile.ExcludedFields)
	encoded, err = json.Marshal(manifest)
	if err != nil || !customerCreationJSON(encoded) {
		return empty, ErrConflict
	}
	hash, err := s.config.Hasher.HashPackageManifest(ctx, manifest)
	if err != nil {
		return empty, err
	}
	if !redactionID(hash) {
		return empty, ErrValidation
	}
	pkg := packagedomain.CustomerSecurityPackage{ID: id, TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: profile.ID, Title: in.Title, State: "generated", Manifest: manifest, ManifestHash: hash, ExpiresAt: in.ExpiresAt, SchemaVersion: packagedomain.CustomerPackageSchemaVersion, CreatedAt: now}
	err = s.config.Transactions.ExecuteCustomerPackageCreation(ctx, func(ctx context.Context, tx CustomerPackageCreationTransaction) error {
		if err := tx.Authorize(ctx, a, customerCreationAuthorization(in)); err != nil {
			return err
		}
		current, err := tx.GetRedactionProfile(ctx, a.TenantID, profile.ID)
		if err != nil {
			return err
		}
		current = cloneRedactionProfile(current)
		current.CreatedAt = current.CreatedAt.UTC()
		if !reflect.DeepEqual(current, profile) {
			return ErrConflict
		}
		// Recheck after parent/policy locks; a long wait must not create an
		// already-expired package. Replay intentionally does not use this check.
		lockedNow := s.config.Clock.Now().UTC()
		if !customerCreationTime(lockedNow) || !in.ExpiresAt.After(lockedNow) {
			return ErrValidation
		}
		event := application.AuditEvent{ID: s.config.IDs.NewID("ace"), TenantID: a.TenantID, EntryType: "customer_package.generated", SubjectType: "customer_security_package", SubjectID: id, ActorType: auditActorType(a), ActorID: auditActorID(a), OccurredAt: now, PayloadHash: hash}
		if !redactionID(event.ID) {
			return ErrValidation
		}
		if err := contextError(ctx); err != nil {
			return err
		}
		if err := tx.InsertCustomerSecurityPackage(ctx, cloneCustomerSecurityPackage(pkg)); err != nil {
			return err
		}
		if _, err := tx.AppendAudit(ctx, event); err != nil {
			return err
		}
		return contextError(ctx)
	})
	if err != nil {
		return empty, err
	}
	return cloneCustomerSecurityPackage(pkg), nil
}

func customerCreationJSON(raw []byte) bool {
	return len(raw) <= MaxCustomerPackageManifestBytes && jsonbounds.Validate(raw, jsonbounds.Limits{MaxDepth: 32, MaxObjectKeys: 4096, MaxArrayItems: MaxSecurityReviewEvidenceIDs, MaxStringBytes: MaxCustomerPackageManifestBytes}) == nil
}
func customerCreationTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }
func validCustomerCreationProfile(v packagedomain.RedactionProfile, tenant, id string) bool {
	if !validRedactionProfile(v, tenant, id) || !redactionText(v.Name, MaxRedactionProfileTextBytes) || !redactionText(v.Description, MaxRedactionProfileTextBytes) || len(v.AllowedTypes) > MaxRedactionProfileEntries || len(v.ExcludedFields) > MaxRedactionProfileEntries {
		return false
	}
	for _, values := range [][]string{v.AllowedTypes, v.ExcludedFields} {
		for _, value := range values {
			if !redactionText(value, MaxRedactionProfileEntryBytes) {
				return false
			}
		}
	}
	return true
}
