package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	experimentalquery "github.com/aatuh/evydence/internal/experimental/query"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type memoryPeripheralPorts interface {
	packageapp.GraphSnapshotReader
	InsertFocusedGraphSnapshot(context.Context, packagedomain.EvidenceGraphSnapshot) error
	experimentalapp.SaaSProfileTenantReader
	InsertFocusedSaaSProfile(context.Context, experimentaldomain.SaaSEditionProfile) error
	experimentalapp.MarketplaceReferenceReader
	InsertFocusedMarketplaceCollector(context.Context, experimentaldomain.MarketplaceCollector) error
	experimentalquery.MarketplaceCollectorReader
}

func memoryPeripheralFixture(t *testing.T) (*memoryUnitOfWork, memoryPeripheralPorts) {
	t.Helper()
	_, tx := memoryQuestionnaireFixture(t)
	r, ok := tx.Repositories().Future.(memoryPeripheralPorts)
	if !ok {
		t.Fatal("memory future repository lacks focused peripheral ports")
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Title, e.SubjectRefs = "Recorded build", []domain.SubjectRef{{Type: "artifact", ID: "external-artifact"}}
	tx.state.Evidence[e.ID] = e
	for _, tenant := range []string{"tenant", "foreign"} {
		tx.state.Signatures[tenant+"-signature"] = domain.Signature{ID: tenant + "-signature", TenantID: tenant, Value: strings.Repeat("private-signature", 100000)}
		tx.state.SBOMs[tenant+"-sbom"] = domain.SBOM{ID: tenant + "-sbom", TenantID: tenant}
		tx.state.VulnerabilityScans[tenant+"-scan"] = domain.VulnerabilityScan{ID: tenant + "-scan", TenantID: tenant}
	}
	return tx, r
}

func TestMemoryPeripheralOwnershipAndGraphReadsAreBoundedDetachedAndPure(t *testing.T) {
	tx, r := memoryPeripheralFixture(t)
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []struct{ product, release string }{{"tenant-product", ""}, {"", "tenant-release"}, {"tenant-product", "tenant-release"}} {
		s, err := r.ReadGraphSnapshotScope(t.Context(), "tenant", raw.product, raw.release)
		if err != nil || s.ProductID != raw.product || s.ReleaseID != raw.release || s.Resources.ProductID != "tenant-product" {
			t.Fatal("graph scope changed raw or inferred coordinates", s, err)
		}
		roots, err := r.ReadGraphSnapshotRoots(t.Context(), s)
		if err != nil || len(roots) != 1+boolInt(raw.product != "" && raw.release != "") || raw.product == "" && roots[0].Type != "release" {
			t.Fatal("graph projected an implicit root", roots, err)
		}
		items, err := r.ReadGraphSnapshotEvidence(t.Context(), s, 1)
		if err != nil || len(items) != 1 || items[0].ID != "tenant-evidence" || items[0].Title != "Recorded build" || !reflect.DeepEqual(items[0].References, []packageapp.GraphSnapshotReference{{Type: "artifact", ID: "external-artifact"}}) {
			t.Fatal("graph changed bounded metadata", items, err)
		}
		items[0].References[0].ID = "mutated"
	}
	if _, err := r.ReadGraphSnapshotScope(t.Context(), "tenant", "foreign-product", ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("graph root crossed tenant", err)
	}
	if _, err := r.ReadSaaSProfileTenants(t.Context(), "tenant", "foreign"); err != nil {
		t.Fatal("explicit admin-tenant association was rejected", err)
	}
	if _, err := r.ReadSaaSProfileTenants(t.Context(), "tenant", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing admin tenant accepted", err)
	}
	ids := experimentalapp.MarketplaceReferenceIDs{SignatureID: "tenant-signature", SBOMID: "tenant-sbom", ScanID: "tenant-scan"}
	refs, err := r.ReadMarketplaceReferences(t.Context(), "tenant", ids)
	if err != nil || refs != (experimentalapp.MarketplaceReferences{TenantID: "tenant", SignatureID: ids.SignatureID, SBOMID: ids.SBOMID, ScanID: ids.ScanID}) {
		t.Fatal("reference read projected private evidence", refs, err)
	}
	for _, wrong := range []experimentalapp.MarketplaceReferenceIDs{{SignatureID: "foreign-signature"}, {SBOMID: "foreign-sbom"}, {ScanID: "foreign-scan"}} {
		if _, err := r.ReadMarketplaceReferences(t.Context(), "tenant", wrong); !errors.Is(err, ErrNotFound) {
			t.Fatal("marketplace reference crossed tenant", err)
		}
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("reads or result mutation changed storage")
	}
	s, err := r.ReadGraphSnapshotScope(t.Context(), "tenant", "tenant-product", "")
	if err != nil {
		t.Fatal(err)
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Title = strings.Repeat("x", packageapp.MaxGraphSnapshotLabelBytes+1)
	tx.state.Evidence[e.ID] = e
	if items, err := r.ReadGraphSnapshotEvidence(t.Context(), s, 1); !errors.Is(err, ErrValidation) || items != nil {
		t.Fatal("oversized graph metadata returned partial rows", items, err)
	}
	e.Title, e.ID = "Recorded build", "extra-evidence"
	first := tx.state.Evidence["tenant-evidence"]
	first.Title = "Recorded build"
	tx.state.Evidence[first.ID] = first
	tx.state.Evidence[e.ID] = e
	if items, err := r.ReadGraphSnapshotEvidence(t.Context(), s, 1); !errors.Is(err, ErrValidation) || items != nil {
		t.Fatal("graph silently truncated selected evidence", items, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := r.ReadGraphSnapshotEvidence(ctx, s, 1); !errors.Is(err, context.Canceled) {
		t.Fatal("graph ignored cancellation", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadMarketplaceReferences(t.Context(), "tenant", ids); !errors.Is(err, ErrConflict) {
		t.Fatal("closed transaction remained usable", err)
	}
}

func TestMemoryMarketplacePagesAndHealthUseCurrentOwnedReferences(t *testing.T) {
	tx, r := memoryPeripheralFixture(t)
	for _, tenant := range []string{"tenant", "foreign"} {
		v, err := experimentalapp.BuildMarketplaceCollector(tenant+"-collector", tenant, experimentalapp.MarketplaceCollectorInput{Name: "Scanner", Provider: "Example", Version: "1", Publisher: "Team", ManifestHash: "sha256:" + strings.Repeat("a", 64), SignatureID: tenant + "-signature", SBOMID: tenant + "-sbom", ScanID: tenant + "-scan"}, fixedNow())
		if err != nil {
			t.Fatal(err)
		}
		if err := r.InsertFocusedMarketplaceCollector(t.Context(), v); err != nil {
			t.Fatal(err)
		}
	}
	page, err := r.PageMarketplaceCollectors(t.Context(), experimentalquery.MarketplaceCollectorPageRequest{TenantID: "tenant", Page: appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}})
	if err != nil || len(page.Items) != 1 || page.Next != nil || page.Items[0].ID != "tenant-collector" {
		t.Fatal("marketplace page crossed tenant or lost fields", page, err)
	}
	page.Items[0].Limitations[0] = "mutated"
	point, err := r.GetMarketplaceCollectorPoint(t.Context(), "tenant", "tenant-collector")
	if err != nil || !point.SignatureFound || !point.SBOMFound || !point.ScanFound || point.Collector.Limitations[0] == "mutated" {
		t.Fatal("health ownership or result detachment changed", point, err)
	}
	if _, err := r.GetMarketplaceCollectorPoint(t.Context(), "tenant", "foreign-collector"); !errors.Is(err, experimentalquery.ErrNotFound) {
		t.Fatal("health crossed tenant", err)
	}
	delete(tx.state.Signatures, "tenant-signature")
	point, err = r.GetMarketplaceCollectorPoint(t.Context(), "tenant", "tenant-collector")
	if err != nil || point.SignatureFound || !point.SBOMFound || !point.ScanFound {
		t.Fatal("health did not reflect current signature absence", point, err)
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestMemoryFocusedPeripheralInsertsPreserveCompleteDetachedRecords(t *testing.T) {
	tx, r := memoryPeripheralFixture(t)
	scope, err := r.ReadGraphSnapshotScope(t.Context(), "tenant", "tenant-product", "tenant-release")
	if err != nil {
		t.Fatal(err)
	}
	roots, err := r.ReadGraphSnapshotRoots(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	items, err := r.ReadGraphSnapshotEvidence(t.Context(), scope, 1)
	if err != nil {
		t.Fatal(err)
	}
	graph, err := packageapp.BuildGraphSnapshotProjection(scope, roots, items)
	if err != nil {
		t.Fatal(err)
	}
	graph.ID, graph.CreatedAt = "new-graph", fixedNow()
	graph.GraphHash, err = application.NormalizedJSONHash(packageapp.GraphSnapshotHashMaterial(graph))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedGraphSnapshot(t.Context(), graph); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.state.EvidenceGraphSnapshots[graph.ID], graphSnapshotLegacyRecord(graph)) {
		t.Fatal("graph lost complete fields")
	}
	graph.Nodes[0].Label, graph.Edges[0].Relationship, graph.Limitations[0] = "mutated", "mutated", "mutated"
	if saved := tx.state.EvidenceGraphSnapshots[graph.ID]; saved.Nodes[0].Label == "mutated" || saved.Edges[0].Relationship == "mutated" || saved.Limitations[0] == "mutated" {
		t.Fatal("graph retained caller arrays")
	}
	raw := experimentalapp.SaaSProfileInput{Name: " Hosted ", Region: " EU ", AdminTenantID: "foreign", IsolationModel: " shared "}
	hash, err := experimentalapp.SaaSProfileConfigHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := experimentalapp.BuildSaaSProfile("new-profile", "tenant", raw, hash, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedSaaSProfile(t.Context(), profile); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.state.SaaSEditionProfiles[profile.ID], SaaSProfileLegacyRecord(profile)) {
		t.Fatal("profile dropped fields or changed raw-input hash")
	}
	profile.Limitations[0] = "mutated"
	if tx.state.SaaSEditionProfiles[profile.ID].Limitations[0] == "mutated" {
		t.Fatal("profile retained caller metadata")
	}
	collector, err := experimentalapp.BuildMarketplaceCollector("new-marketplace", "tenant", experimentalapp.MarketplaceCollectorInput{Name: "Scanner", Provider: "Example", Version: "1", Publisher: "Team", ManifestHash: "sha256:" + strings.Repeat("A", 64), SignatureID: "tenant-signature", SBOMID: "tenant-sbom", ScanID: "tenant-scan"}, fixedNow())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.InsertFocusedMarketplaceCollector(t.Context(), collector); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tx.state.MarketplaceCollectors[collector.ID], MarketplaceCollectorLegacyRecord(collector)) {
		t.Fatal("collector dropped fields or changed digest casing")
	}
	collector.Limitations[0] = "mutated"
	if tx.state.MarketplaceCollectors[collector.ID].Limitations[0] == "mutated" {
		t.Fatal("collector retained caller metadata")
	}
	before, err := cloneMemoryUnitOfWorkSnapshot(tx.state)
	if err != nil {
		t.Fatal(err)
	}
	graph.ID, graph.GraphHash = "bad-hash", "sha256:"+strings.Repeat("0", 64)
	if err := r.InsertFocusedGraphSnapshot(t.Context(), graph); !errors.Is(err, ErrValidation) {
		t.Fatal("graph accepted a mismatched hash", err)
	}
	profile.ID, profile.AdminTenantID = "missing-admin", "missing"
	if err := r.InsertFocusedSaaSProfile(t.Context(), profile); !errors.Is(err, ErrNotFound) {
		t.Fatal("profile accepted missing admin", err)
	}
	collector.ID, collector.SignatureID = "foreign-signature", "foreign-signature"
	if err := r.InsertFocusedMarketplaceCollector(t.Context(), collector); !errors.Is(err, ErrNotFound) {
		t.Fatal("collector accepted a foreign signature", err)
	}
	if !reflect.DeepEqual(before, tx.state) {
		t.Fatal("rejected focused insert changed storage")
	}
}
