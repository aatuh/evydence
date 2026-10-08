package app

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskquery "github.com/aatuh/evydence/internal/risk/query"
)

var _ riskquery.ReleaseReadinessReader = memoryDecisionRepository{}

func (r memoryDecisionRepository) ReadReleaseReadinessSnapshot(ctx context.Context, tenant, release string) (riskapp.ReadinessSnapshot, error) {
	return r.ReadReleaseReadinessSnapshotAt(ctx, tenant, release, time.Now().UTC())
}

// The explicit time mirrors the native SQL reader's transaction-local
// evaluation time. These test-backend facts never build a Ledger snapshot.
func (r memoryDecisionRepository) ReadReleaseReadinessSnapshotAt(ctx context.Context, tenant, release string, at time.Time) (riskapp.ReadinessSnapshot, error) {
	if at.IsZero() || at.Year() < 1 || at.Year() > 9999 {
		return riskapp.ReadinessSnapshot{}, riskapp.ErrValidation
	}
	var out riskapp.ReadinessSnapshot
	err := memoryGovernanceRead(ctx, r.uow, tenant, release, func(s *MemoryUnitOfWorkSnapshot) error {
		root, err := memoryOperationsCoordinates(s, tenant, application.ResourceReferences{ReleaseID: release})
		if err != nil {
			return err
		}
		product := root.ProductID
		facts, err := readMemoryReadinessFacts(ctx, s, tenant, product, release, at)
		if err != nil {
			return err
		}
		out = riskapp.ReadinessSnapshot{SnapshotVersion: riskapp.ReadinessSnapshotVersion, TenantID: tenant, ProductID: product, ReleaseID: release, HasArtifact: facts.HasArtifact, HasSBOM: facts.HasSBOM, HasVulnerabilityScan: facts.HasVulnerabilityScan, HasArtifactDigest: facts.HasArtifactDigest, HasPassedBuild: facts.HasPassedBuild, HasVerifiedBuildAttestation: facts.HasVerifiedBuildAttestation, UnhandledCritical: facts.UnhandledCritical, UnhandledHigh: facts.UnhandledHigh}
		remainingIDs, remainingBytes := 4096, packageapp.MaxCustomerPackageManifestBytes
		appendID := func(list *[]string, id string) error {
			if !memoryMembershipQueryText(id, 1024) || remainingIDs == 0 {
				return ErrValidation
			}
			encoded, err := json.Marshal(id)
			if err != nil || len(encoded) > remainingBytes {
				return ErrValidation
			}
			remainingIDs--
			remainingBytes -= len(encoded)
			*list = append(*list, id)
			return nil
		}
		for id, d := range s.Decisions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if d.ID != id || d.TenantID != tenant || d.ReleaseID != release || d.SupersededBy != "" || !memoryReadinessDecisionOwned(d, facts.scans) {
				continue
			}
			if d.CustomerVisible && strings.TrimSpace(d.ImpactStatement) == "" {
				if err := appendID(&out.MissingCustomerStatementIDs, id); err != nil {
					return err
				}
			}
			if d.Status == "not_affected" && strings.TrimSpace(d.Justification) == "" {
				if err := appendID(&out.MissingNotAffectedReasonIDs, id); err != nil {
					return err
				}
			}
		}
		for id, x := range s.Exceptions {
			if err := ctx.Err(); err != nil {
				return err
			}
			if x.ID != id || x.TenantID != tenant || x.ReleaseID != release || !memoryReadinessExceptionOwned(s, tenant, x, facts.scans) {
				continue
			}
			if strings.TrimSpace(x.Owner) == "" || strings.TrimSpace(x.Reason) == "" || x.Approved && (strings.TrimSpace(x.ApprovedBy) == "" || x.ApprovedAt == nil) {
				if err := appendID(&out.IncompleteExceptionIDs, id); err != nil {
					return err
				}
			}
		}
		packageLimit := remainingIDs
		for id, p := range s.CustomerPackages {
			if err := ctx.Err(); err != nil {
				return err
			}
			if p.ID != id || p.TenantID != tenant || p.ReleaseID != release || p.ProductID != product {
				continue
			}
			out.PackageCount++
			if out.PackageCount > packageLimit {
				return ErrValidation
			}
			profile, ok := s.RedactionProfiles[p.RedactionProfileID]
			if !ok || profile.ID != p.RedactionProfileID || profile.TenantID != tenant || !memoryReadinessRedaction(profile) || !p.ExpiresAt.After(at) {
				if err := appendID(&out.InvalidPackageOrProfileIDs, id); err != nil {
					return err
				}
			}
		}
		for _, list := range [][]string{out.MissingCustomerStatementIDs, out.MissingNotAffectedReasonIDs, out.IncompleteExceptionIDs, out.InvalidPackageOrProfileIDs} {
			sort.Strings(list)
		}
		out.HasVerifiedSignedBundle, err = memoryReadinessSignedBundle(ctx, s, tenant, release, at)
		return err
	})
	if errors.Is(err, ErrNotFound) {
		err = riskapp.ErrNotFound
	}
	if errors.Is(err, ErrValidation) {
		err = riskapp.ErrValidation
	}
	if err != nil {
		return riskapp.ReadinessSnapshot{}, err
	}
	return out, nil
}

func memoryReadinessDecisionOwned(d domain.VulnerabilityDecision, scans map[string][]domain.VulnerabilityFinding) bool {
	count, match := 0, false
	for _, f := range scans[d.ScanID] {
		if f.ID == d.FindingID {
			count++
			match = match || f.Vulnerability == d.Vulnerability && f.Component == d.Component
		}
	}
	return count == 1 && match
}

func memoryReadinessExceptionOwned(s *MemoryUnitOfWorkSnapshot, tenant string, x domain.Exception, scans map[string][]domain.VulnerabilityFinding) bool {
	if x.ControlID != "" {
		c, ok := s.SecurityControls[x.ControlID]
		if !ok || c.ID != x.ControlID || c.TenantID != tenant {
			return false
		}
		f, ok := s.ControlFrameworks[c.FrameworkID]
		if !ok || f.ID != c.FrameworkID || f.TenantID != tenant {
			return false
		}
	}
	if x.FindingID == "" {
		return true
	}
	for _, findings := range scans {
		for _, f := range findings {
			if f.ID == x.FindingID {
				return true
			}
		}
	}
	return false
}

func memoryReadinessRedaction(p domain.RedactionProfile) bool {
	if len(p.AllowedTypes) == 0 {
		return false
	}
	excluded := map[string]bool{}
	for _, field := range p.ExcludedFields {
		excluded[strings.ToLower(strings.TrimSpace(field))] = true
	}
	for _, field := range []string{"payload_ref", "object_key", "private_key", "token", "secret", "internal_notes"} {
		if !excluded[field] {
			return false
		}
	}
	return true
}
