package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Historical declarations retained unchanged for package-local regressions.
// HTTP fixtures use focused services and bounded repository projections.
// These methods are not a runtime backend or native SQL/provider evidence.

func evidenceMatchesRefs(item domain.EvidenceItem, refs resourceRefs) bool {
	if refs.ProductID != "" && item.ProductID != refs.ProductID {
		return false
	}
	if refs.ProjectID != "" && item.ProjectID != refs.ProjectID {
		return false
	}
	if refs.ReleaseID != "" && item.ReleaseID != refs.ReleaseID {
		return false
	}
	return true
}

type CreateGraphSnapshotInput struct {
	ProductID string
	ReleaseID string
}

type CreateSaaSEditionProfileInput struct {
	Name           string
	Region         string
	AdminTenantID  string
	IsolationModel string
}

type CreateMarketplaceCollectorInput struct {
	Name         string
	Provider     string
	Version      string
	Publisher    string
	ManifestHash string
	SignatureID  string
	SBOMID       string
	ScanID       string
}

func (l *Ledger) CreateGraphSnapshot(ctx context.Context, actor domain.Actor, in CreateGraphSnapshotInput) (domain.EvidenceGraphSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	if err := require(actor, ScopeEvidenceRead); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	normalized, err := packageapp.NormalizeGraphSnapshotInput(packageapp.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, ErrValidation
	}
	productID, releaseID := normalized.ProductID, normalized.ReleaseID
	l.mu.Lock()
	defer l.mu.Unlock()
	scope, err := l.authorizeGraphSnapshotLocked(actor, normalized)
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	refs := resourceRefs{ProductID: productID, ReleaseID: releaseID}
	roots := []packagedomain.GraphNode{}
	if productID != "" {
		product := l.products[productID]
		roots = append(roots, packagedomain.GraphNode{ID: product.ID, Type: "product", Label: product.Name})
	}
	if releaseID != "" {
		release := l.releases[releaseID]
		roots = append(roots, packagedomain.GraphNode{ID: release.ID, Type: "release", Label: release.Version})
	}
	remainingNodes := MaxEvidenceGraphNodes - len(roots)
	evidenceIDs, exceeded := l.evidenceIDsForRefsBoundedLocked(actor.TenantID, refs, "", remainingNodes)
	if exceeded {
		return domain.EvidenceGraphSnapshot{}, ErrValidation
	}
	items := make([]packageapp.GraphSnapshotEvidence, 0, len(evidenceIDs))
	for _, id := range evidenceIDs {
		item := l.evidence[id]
		if item.ReleaseID != "" {
			parent, ok := l.releases[item.ReleaseID]
			if !ok || parent.TenantID != actor.TenantID || parent.ProductID != scope.Resources.ProductID {
				return domain.EvidenceGraphSnapshot{}, ErrNotFound
			}
		}
		if len(item.SubjectRefs) > MaxEvidenceGraphEdges {
			return domain.EvidenceGraphSnapshot{}, ErrValidation
		}
		v := packageapp.GraphSnapshotEvidence{ID: item.ID, TenantID: item.TenantID, ProductID: item.ProductID, ReleaseID: item.ReleaseID, Title: item.Title}
		for _, ref := range item.SubjectRefs {
			v.References = append(v.References, packageapp.GraphSnapshotReference{Type: ref.Type, ID: ref.ID})
		}
		items = append(items, v)
	}
	projection, err := packageapp.BuildGraphSnapshotProjection(scope, roots, items)
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, fromPackageContextError(err)
	}
	hash, err := canonicalAnyHash(packageapp.GraphSnapshotHashMaterial(projection))
	if err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	projection.ID, projection.GraphHash, projection.CreatedAt = newID("grf"), hash, l.now()
	graph := graphSnapshotLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertEvidenceGraphSnapshot(ctx, graph); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(graph.CreatedAt, actor.TenantID, "evidence_graph_snapshot.created", "evidence_graph_snapshot", graph.ID, actorType(actor), actorID(actor), hash, ""))
			return err
		}); err != nil {
			return domain.EvidenceGraphSnapshot{}, err
		}
		l.graphSnapshots[graph.ID] = graphSnapshotLegacyRecord(projection)
		l.publishCommittedAuditEntryLocked(entry)
		return graph, nil
	}
	l.graphSnapshots[graph.ID] = graphSnapshotLegacyRecord(projection)
	_, _ = l.appendChainLocked(actor.TenantID, "evidence_graph_snapshot.created", "evidence_graph_snapshot", graph.ID, actorType(actor), actorID(actor), hash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.EvidenceGraphSnapshot{}, err
	}
	return graph, nil
}

func (l *Ledger) CreateSaaSEditionProfile(ctx context.Context, actor domain.Actor, in CreateSaaSEditionProfileInput) (domain.SaaSEditionProfile, error) {
	if err := ctx.Err(); err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	if err := l.AuthorizeCreateSaaSEditionProfile(ctx, actor, in); err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	normalized, err := experimentalapp.NormalizeSaaSProfileInput(saasProfileInput(in))
	if err != nil {
		return domain.SaaSEditionProfile{}, fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[normalized.AdminTenantID]; !ok {
		return domain.SaaSEditionProfile{}, ErrNotFound
	}
	if _, ok := l.tenants[actor.TenantID]; !ok {
		return domain.SaaSEditionProfile{}, ErrNotFound
	}
	cfgHash, err := experimentalapp.SaaSProfileConfigHash(saasProfileInput(in))
	if err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	projection, err := experimentalapp.BuildSaaSProfile(newID("saas"), actor.TenantID, normalized, cfgHash, l.now())
	if err != nil {
		return domain.SaaSEditionProfile{}, fromExperimentalCommandError(err)
	}
	profile := SaaSProfileLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertSaaSEditionProfile(ctx, profile); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(profile.CreatedAt, actor.TenantID, "saas_profile.created", "saas_profile", profile.ID, actorType(actor), actorID(actor), cfgHash, ""))
			return err
		}); err != nil {
			return domain.SaaSEditionProfile{}, err
		}
		l.saasProfiles[profile.ID] = SaaSProfileLegacyRecord(projection)
		l.publishCommittedAuditEntryLocked(entry)
		return profile, nil
	}
	l.saasProfiles[profile.ID] = SaaSProfileLegacyRecord(projection)
	_, _ = l.appendChainLocked(actor.TenantID, "saas_profile.created", "saas_profile", profile.ID, actorType(actor), actorID(actor), cfgHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SaaSEditionProfile{}, err
	}
	return profile, nil
}

func (l *Ledger) CreateMarketplaceCollector(ctx context.Context, actor domain.Actor, in CreateMarketplaceCollectorInput) (domain.MarketplaceCollector, error) {
	if err := ctx.Err(); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	if err := l.AuthorizeCreateMarketplaceCollector(ctx, actor, in); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	normalized, err := experimentalapp.NormalizeMarketplaceCollectorInput(marketplaceCollectorInput(in))
	if err != nil {
		return domain.MarketplaceCollector{}, fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.authorizeMarketplaceReferencesLocked(ctx, actor.TenantID, normalized); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	projection, err := experimentalapp.BuildMarketplaceCollector(newID("mpc"), actor.TenantID, normalized, l.now())
	if err != nil {
		return domain.MarketplaceCollector{}, fromExperimentalCommandError(err)
	}
	collector := MarketplaceCollectorLegacyRecord(projection)
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Future.InsertMarketplaceCollector(ctx, collector); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(collector.CreatedAt, actor.TenantID, "marketplace_collector.created", "marketplace_collector", collector.ID, actorType(actor), actorID(actor), collector.ManifestHash, ""))
			return err
		}); err != nil {
			return domain.MarketplaceCollector{}, err
		}
		l.marketplaceCollectors[collector.ID] = MarketplaceCollectorLegacyRecord(projection)
		l.publishCommittedAuditEntryLocked(entry)
		return collector, nil
	}
	l.marketplaceCollectors[collector.ID] = MarketplaceCollectorLegacyRecord(projection)
	_, _ = l.appendChainLocked(actor.TenantID, "marketplace_collector.created", "marketplace_collector", collector.ID, actorType(actor), actorID(actor), collector.ManifestHash, "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.MarketplaceCollector{}, err
	}
	return collector, nil
}

func (l *Ledger) ListMarketplaceCollectors(ctx context.Context, actor domain.Actor) ([]domain.MarketplaceCollector, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.resourceAllowedLocked(actor, ScopeCollectorRead, resourceRefs{}) {
		return nil, ErrForbidden
	}
	out := []domain.MarketplaceCollector{}
	for _, collector := range l.marketplaceCollectors {
		if collector.TenantID == actor.TenantID {
			out = append(out, cloneLocalMarketplaceCollector(collector))
		}
	}
	sortMarketplaceCollectors(out)
	return out, nil
}

func (l *Ledger) MarketplaceCollectorHealth(ctx context.Context, actor domain.Actor, id string) (domain.MarketplaceCollectorHealthReport, error) {
	if err := ctx.Err(); err != nil {
		return domain.MarketplaceCollectorHealthReport{}, err
	}
	if err := require(actor, ScopeCollectorRead); err != nil {
		return domain.MarketplaceCollectorHealthReport{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.resourceAllowedLocked(actor, ScopeCollectorRead, resourceRefs{}) {
		return domain.MarketplaceCollectorHealthReport{}, ErrForbidden
	}
	collector, ok := l.marketplaceCollectors[strings.TrimSpace(id)]
	if !ok || collector.TenantID != actor.TenantID {
		return domain.MarketplaceCollectorHealthReport{}, ErrNotFound
	}
	collector = cloneLocalMarketplaceCollector(collector)
	checks := []domain.VerifyCheck{{Name: "manifest_digest", Result: "passed", Detail: "collector package manifest digest is recorded"}}
	result := "verified"
	if collector.SignatureID == "" {
		result = "incomplete"
		checks = append(checks, domain.VerifyCheck{Name: "signature_evidence", Result: "failed", Detail: "collector package signature evidence is missing"})
	} else if sig, ok := l.signatures[collector.SignatureID]; !ok || sig.TenantID != actor.TenantID {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "signature_evidence", Result: "failed", Detail: "collector package signature evidence reference is invalid"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "signature_evidence", Result: "passed"})
	}
	if collector.SBOMID == "" {
		result = worseHealth(result, "incomplete")
		checks = append(checks, domain.VerifyCheck{Name: "sbom_evidence", Result: "failed", Detail: "collector package SBOM evidence is missing"})
	} else if sbom, ok := l.sboms[collector.SBOMID]; !ok || sbom.TenantID != actor.TenantID {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "sbom_evidence", Result: "failed", Detail: "collector package SBOM evidence reference is invalid"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "sbom_evidence", Result: "passed"})
	}
	if collector.ScanID == "" {
		result = worseHealth(result, "incomplete")
		checks = append(checks, domain.VerifyCheck{Name: "vulnerability_scan_evidence", Result: "failed", Detail: "collector package vulnerability scan evidence is missing"})
	} else if scan, ok := l.scans[collector.ScanID]; !ok || scan.TenantID != actor.TenantID {
		result = "failed"
		checks = append(checks, domain.VerifyCheck{Name: "vulnerability_scan_evidence", Result: "failed", Detail: "collector package vulnerability scan evidence reference is invalid"})
	} else {
		checks = append(checks, domain.VerifyCheck{Name: "vulnerability_scan_evidence", Result: "passed"})
	}
	return domain.MarketplaceCollectorHealthReport{
		ReportType:        "marketplace_collector_health",
		CollectorID:       collector.ID,
		Name:              collector.Name,
		Provider:          collector.Provider,
		Version:           collector.Version,
		SupplyChainStatus: result,
		Checks:            checks,
		Collector:         collector,
		Assumptions:       []string{"Health is based on evidence recorded in Evydence for this tenant."},
		Limitations:       []string{"This report does not prove marketplace trust, package safety, or provider endorsement."},
		GeneratedAt:       l.now(),
	}, nil
}

func worseHealth(current, candidate string) string {
	if current == "failed" || candidate == "failed" {
		return "failed"
	}
	if current == "incomplete" || candidate == "incomplete" {
		return "incomplete"
	}
	return "verified"
}

// evidenceIDsForRefsBoundedLocked returns no partial list when a traversal
// exceeds its caller-provided budget. Callers therefore fail closed rather
// than silently presenting a truncated graph or report as complete.
func (l *Ledger) evidenceIDsForRefsBoundedLocked(tenantID string, refs resourceRefs, evidenceType string, limit int) ([]string, bool) {
	if limit <= 0 {
		return nil, true
	}
	ids := []string{}
	for _, item := range l.evidence {
		if item.TenantID != tenantID {
			continue
		}
		if evidenceType != "" && item.Type != evidenceType {
			continue
		}
		if evidenceMatchesRefs(item, refs) {
			if len(ids) == limit {
				return nil, true
			}
			ids = append(ids, item.ID)
		}
	}
	return sortedStrings(ids), false
}

func sortMarketplaceCollectors(items []domain.MarketplaceCollector) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j-1].ID > items[j].ID; j-- {
			items[j-1], items[j] = items[j], items[j-1]
		}
	}
}

func (l *Ledger) authorizeGraphSnapshotLocked(a domain.Actor, in packageapp.CreateGraphSnapshotInput) (packageapp.GraphSnapshotScope, error) {
	r, err := l.authorizeProductReleaseLocked(a, ScopeEvidenceRead, in.ProductID, in.ReleaseID)
	return packageapp.GraphSnapshotScope{TenantID: a.TenantID, ProductID: in.ProductID, ReleaseID: in.ReleaseID, Resources: r}, err
}

func (l *Ledger) AuthorizeCreateGraphSnapshot(ctx context.Context, a domain.Actor, in CreateGraphSnapshotInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := require(a, ScopeEvidenceRead); err != nil {
		return err
	}
	v, err := packageapp.NormalizeGraphSnapshotInput(packageapp.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.authorizeGraphSnapshotLocked(a, v)
	return err
}

func saasProfileInput(in CreateSaaSEditionProfileInput) experimentalapp.SaaSProfileInput {
	return experimentalapp.SaaSProfileInput{Name: in.Name, Region: in.Region, AdminTenantID: in.AdminTenantID, IsolationModel: in.IsolationModel}
}

func (l *Ledger) AuthorizeCreateSaaSEditionProfile(ctx context.Context, a domain.Actor, in CreateSaaSEditionProfileInput) error {
	if err := experimentalapp.AuthorizeSaaSProfileActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	v, err := experimentalapp.NormalizeSaaSProfileInput(saasProfileInput(in))
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.tenants[a.TenantID]; !ok {
		return ErrNotFound
	}
	if _, ok := l.tenants[v.AdminTenantID]; !ok {
		return ErrNotFound
	}
	return ctx.Err()
}

func marketplaceCollectorInput(in CreateMarketplaceCollectorInput) experimentalapp.MarketplaceCollectorInput {
	return experimentalapp.MarketplaceCollectorInput{Name: in.Name, Provider: in.Provider, Version: in.Version, Publisher: in.Publisher, ManifestHash: in.ManifestHash, SignatureID: in.SignatureID, SBOMID: in.SBOMID, ScanID: in.ScanID}
}

func cloneLocalMarketplaceCollector(v domain.MarketplaceCollector) domain.MarketplaceCollector {
	v.Limitations = append([]string(nil), v.Limitations...)
	return v
}

func (l *Ledger) AuthorizeCreateMarketplaceCollector(ctx context.Context, a domain.Actor, in CreateMarketplaceCollectorInput) error {
	if err := experimentalapp.AuthorizeMarketplaceCollectorActor(ctx, a); err != nil {
		return fromExperimentalCommandError(err)
	}
	v, err := experimentalapp.NormalizeMarketplaceCollectorInput(marketplaceCollectorInput(in))
	if err != nil {
		return fromExperimentalCommandError(err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authorizeMarketplaceReferencesLocked(ctx, a.TenantID, v)
}

func (l *Ledger) authorizeMarketplaceReferencesLocked(ctx context.Context, tenant string, in experimentalapp.MarketplaceCollectorInput) error {
	if _, ok := l.tenants[tenant]; !ok {
		return ErrNotFound
	}
	if in.SignatureID != "" {
		v, ok := l.signatures[in.SignatureID]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
	}
	if in.SBOMID != "" {
		v, ok := l.sboms[in.SBOMID]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
	}
	if in.ScanID != "" {
		v, ok := l.scans[in.ScanID]
		if !ok || v.TenantID != tenant {
			return ErrNotFound
		}
	}
	return ctx.Err()
}
