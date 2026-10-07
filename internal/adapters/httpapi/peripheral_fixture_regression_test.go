package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type peripheralFixtureScope struct {
	operationsFixtureScope
	signatureID string
	sbom        domain.SBOM
	scan        domain.VulnerabilityScan
}

func seedPeripheralFixtureScope(t *testing.T, ledger *app.Ledger, name string) peripheralFixtureScope {
	t.Helper()
	f := peripheralFixtureScope{operationsFixtureScope: seedOperationsFixtureScope(t, ledger, name)}
	var err error
	f.sbom, err = ledger.UploadSBOM(t.Context(), f.actor, f.release.ID, "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"collector","purl":"pkg:generic/collector@1"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f.scan, err = ledger.UploadVulnerabilityScan(t.Context(), f.actor, []byte(fmt.Sprintf(`{"scanner":"generic","target_ref":"pkg:generic/collector@1","release_id":%q,"findings":[{"vulnerability":"CVE-2026-1","component":"collector","severity":"high","state":"open"}]}`, f.release.ID)))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := ledger.CreateReleaseBundle(t.Context(), f.actor, f.release.ID)
	if err != nil || len(bundle.SignatureRefs) != 1 {
		t.Fatal("seed signed bundle", err)
	}
	f.signatureID = bundle.SignatureRefs[0]
	return f
}

type peripheralFixtureRequest struct{ name, path, body, auditType string }

func peripheralFixtureRequests(f peripheralFixtureScope, adminTenant string) []peripheralFixtureRequest {
	return []peripheralFixtureRequest{
		{"graph", "/v1/evidence-graph-snapshots", fmt.Sprintf(`{"product_id":%q,"release_id":%q}`, f.product.ID, f.release.ID), "evidence_graph_snapshot.created"},
		{"saas", "/v1/saas/profiles", fmt.Sprintf(`{"name":" Hosted ","region":" eu ","admin_tenant_id":%q,"isolation_model":" shared-control-plane "}`, adminTenant), "saas_profile.created"},
		{"marketplace", "/v1/marketplace-collectors", fmt.Sprintf(`{"name":" Scanner ","provider":" Example ","version":" 1 ","publisher":" Team ","manifest_hash":"sha256:%s","signature_id":%q,"sbom_id":%q,"scan_id":%q}`, strings.Repeat("A", 64), f.signatureID, f.sbom.ID, f.scan.ID), "marketplace_collector.created"},
	}
}

type failingPeripheralFixture struct {
	peripheralFixtureCommands
	changedID string
	isolated  bool
}

func (f *failingPeripheralFixture) fail(ctx context.Context, id string, err error) error {
	if err != nil {
		return err
	}
	f.changedID, f.isolated = id, f.commandLedger(ctx) != f.ledger
	return errors.New("private peripheral failure after write")
}
func (f *failingPeripheralFixture) CreateGraphSnapshot(ctx context.Context, a domain.Actor, in packageapp.CreateGraphSnapshotInput) (packagedomain.EvidenceGraphSnapshot, error) {
	v, err := f.peripheralFixtureCommands.CreateGraphSnapshot(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingPeripheralFixture) CreateSaaSProfile(ctx context.Context, a domain.Actor, in experimentalapp.SaaSProfileInput) (experimentaldomain.SaaSEditionProfile, error) {
	v, err := f.peripheralFixtureCommands.CreateSaaSProfile(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func (f *failingPeripheralFixture) CreateMarketplaceCollector(ctx context.Context, a domain.Actor, in experimentalapp.MarketplaceCollectorInput) (experimentaldomain.MarketplaceCollector, error) {
	v, err := f.peripheralFixtureCommands.CreateMarketplaceCollector(ctx, a, in)
	return v, f.fail(ctx, v.ID, err)
}
func peripheralFixtureHuman(f peripheralFixtureScope) domain.Actor {
	return domain.Actor{TenantID: f.actor.TenantID, UserID: "fixture-human", Scopes: []string{"evidence:read", "collector:admin", "collector:read", "instance:admin"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "product", ResourceID: f.product.ID, Scopes: []string{"evidence:read"}}, {ResourceType: "tenant", ResourceID: f.actor.TenantID, Scopes: []string{"collector:admin", "collector:read"}}}}
}

func TestPeripheralFixturesRollBackGraphProfileCollectorAuditAndReplayAfterWrite(t *testing.T) {
	for index := 0; index < 3; index++ {
		ledger, factory := integrationRegressionLedger()
		owner := seedPeripheralFixtureScope(t, ledger, "Owner")
		request := peripheralFixtureRequests(owner, owner.actor.TenantID)[index]
		t.Run(request.name, func(t *testing.T) {
			server, err := newLegacyServerFixture(ledger)
			if err != nil {
				t.Fatal(err)
			}
			server.authn = &configuredAuthenticator{actor: peripheralFixtureHuman(owner)}
			commands := &failingPeripheralFixture{peripheralFixtureCommands: peripheralFixtureCommands{catalogFixtureCommands{ledger: ledger}}}
			server.graphSnapshotCommands, server.saasProfileCommands, server.marketplaceCollectorCommands = commands, commands, commands
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			out := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 500)
			if commands.changedID == "" || !commands.isolated || strings.Contains(out, commands.changedID) || strings.Contains(out, `"data"`) || strings.Contains(out, "private peripheral") {
				t.Fatal("failed peripheral write bypassed isolation or leaked partial data")
			}
			after, err := factory.Snapshot()
			if err != nil || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("missing failed receipt", err)
			}
			for key, receipt := range after.Idempotency {
				if _, exists := before.Idempotency[key]; !exists && (receipt.State != app.IdempotencyFailed || receipt.Status != 0 || receipt.Response != nil) {
					t.Fatal("failed peripheral write cached partial success")
				}
			}
			after.Idempotency = before.Idempotency
			if !reflect.DeepEqual(before, after) {
				t.Fatal("failed write committed graph, profile, collector, adjacency, audit or outbox effects")
			}
		})
	}
}

func TestPeripheralFixturesPreserveCompleteDTOHashAuditAndCurrentReplayAuthority(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPeripheralFixtureScope(t, ledger, "Owner")
	foreign := seedPeripheralFixtureScope(t, ledger, "Foreign")
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := peripheralFixtureHuman(owner)
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	for _, request := range peripheralFixtureRequests(owner, foreign.actor.TenantID) {
		t.Run(request.name, func(t *testing.T) {
			before, err := factory.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			original := postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201)
			id := dataField(t, original, "id")
			after, err := factory.Snapshot()
			if err != nil || len(after.AuditEntries[human.TenantID]) != len(before.AuditEntries[human.TenantID])+1 || len(after.Idempotency) != len(before.Idempotency)+1 {
				t.Fatal("fresh peripheral command lacks single audit/receipt", err)
			}
			var value any
			var payloadHash string
			switch request.name {
			case "graph":
				v := after.EvidenceGraphSnapshots[id]
				if len(after.EvidenceGraphSnapshots) != len(before.EvidenceGraphSnapshots)+1 || len(v.Nodes) < 3 || len(v.Edges) == 0 || v.ProductID != owner.product.ID || v.ReleaseID != owner.release.ID {
					t.Fatal("graph test omitted owned adjacency")
				}
				value, payloadHash = v, v.GraphHash
				wantHash, err := application.NormalizedJSONHash(packageapp.GraphSnapshotHashMaterial(graphFixtureModel(v)))
				if err != nil || wantHash != payloadHash {
					t.Fatal("graph canonical hash changed", err)
				}
			case "saas":
				v := after.SaaSEditionProfiles[id]
				if len(after.SaaSEditionProfiles) != len(before.SaaSEditionProfiles)+1 || v.AdminTenantID != foreign.actor.TenantID || v.TenantID != human.TenantID || v.Name != "Hosted" || v.Region != "eu" || v.Status != "proposed" {
					t.Fatal("instance-admin global reference or normalized intent changed")
				}
				value, payloadHash = v, v.ConfigHash
				in, err := decodeSaaSProfileRequest([]byte(request.body))
				if err != nil {
					t.Fatal(err)
				}
				wantHash, err := experimentalapp.SaaSProfileConfigHash(in)
				normalized, normalizeErr := experimentalapp.NormalizeSaaSProfileInput(in)
				normalizedHash, hashErr := experimentalapp.SaaSProfileConfigHash(normalized)
				if err != nil || normalizeErr != nil || hashErr != nil || payloadHash != wantHash || payloadHash == normalizedHash {
					t.Fatal("raw SaaS configuration hash profile changed")
				}
			case "marketplace":
				v := after.MarketplaceCollectors[id]
				if len(after.MarketplaceCollectors) != len(before.MarketplaceCollectors)+1 || v.Name != "Scanner" || v.State != "registered" || v.ManifestHash != "sha256:"+strings.Repeat("A", 64) || v.SignatureID != owner.signatureID || v.SBOMID != owner.sbom.ID || v.ScanID != owner.scan.ID {
					t.Fatal("marketplace normalization, digest spelling or owned references changed")
				}
				value, payloadHash = v, v.ManifestHash
			}
			want, err := json.Marshal(map[string]any{"data": value, "meta": map[string]string{"api_version": "v1"}})
			if err != nil {
				t.Fatal(err)
			}
			assertTrustHTTPReplay(t, string(want), original)
			audit := after.AuditEntries[human.TenantID][len(after.AuditEntries[human.TenantID])-1]
			if audit.TenantID != human.TenantID || audit.ActorType != "human_user" || audit.ActorID != human.UserID || audit.SubjectID != id || audit.EntryType != request.auditType || audit.PayloadHash != payloadHash {
				t.Fatal("peripheral audit lost owned caller/hash attribution")
			}
			assertTrustHTTPReplay(t, original, postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 201))
			if request.name == "saas" {
				auth.actor.Scopes = []string{"*"}
				postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
			} else {
				for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: foreign.product.ID, Scopes: []string{"*"}}}} {
					auth.actor.ResourceGrants = grants
					postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 403)
				}
			}
			auth.actor = human
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body+" "), 409)
			auth.err = app.ErrUnauthorized
			postRaw(t, server, "fixture-auth", request.path, request.name, []byte(request.body), 401)
			auth.err = nil
			latest, err := factory.Snapshot()
			if err != nil || !reflect.DeepEqual(after, latest) {
				t.Fatal("saved/rejected peripheral replay repeated effects", err)
			}
		})
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// Foreign graph parents and each evidence reference fail independently.
	postRaw(t, server, "fixture-auth", "/v1/evidence-graph-snapshots", "foreign-product", []byte(fmt.Sprintf(`{"product_id":%q}`, foreign.product.ID)), 404)
	postRaw(t, server, "fixture-auth", "/v1/evidence-graph-snapshots", "mismatched-parent", []byte(fmt.Sprintf(`{"product_id":%q,"release_id":%q}`, owner.product.ID, foreign.release.ID)), 404)
	marketplace := peripheralFixtureRequests(owner, owner.actor.TenantID)[2]
	for _, pair := range [][2]string{{owner.signatureID, foreign.signatureID}, {owner.sbom.ID, foreign.sbom.ID}, {owner.scan.ID, foreign.scan.ID}} {
		postRaw(t, server, "fixture-auth", marketplace.path, "foreign-reference", []byte(strings.Replace(marketplace.body, pair[0], pair[1], 1)), 404)
	}
	saas := peripheralFixtureRequests(owner, "missing-tenant")[1]
	postRaw(t, server, "fixture-auth", saas.path, "missing-admin", []byte(saas.body), 404)
	auth.actor.TenantID = "missing-tenant"
	postRaw(t, server, "fixture-auth", saas.path, "missing-owner", []byte(peripheralFixtureRequests(owner, owner.actor.TenantID)[1].body), 404)
	auth.actor = human
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("authorization preflight persisted foreign/missing records or replay reservations", err)
	}
}

func TestMarketplaceFixtureReadsKeepCompleteOwnedPagesHealthAndDetachedMetadata(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPeripheralFixtureScope(t, ledger, "Owner")
	foreign := seedPeripheralFixtureScope(t, ledger, "Foreign")
	want := map[string]string{}
	var first domain.MarketplaceCollector
	for _, scope := range []peripheralFixtureScope{owner, foreign} {
		for index := 0; index < 3; index++ {
			in, err := decodeMarketplaceCollectorRequest([]byte(peripheralFixtureRequests(scope, scope.actor.TenantID)[2].body))
			if err != nil {
				t.Fatal(err)
			}
			in.Version = fmt.Sprint(index + 1)
			if index == 1 {
				in.SignatureID, in.SBOMID, in.ScanID = "", "", ""
			}
			v, err := ledger.CreateMarketplaceCollector(t.Context(), scope.actor, marketplaceCollectorLegacyInput(in))
			if err != nil {
				t.Fatal(err)
			}
			if scope.actor.TenantID == owner.actor.TenantID {
				raw, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				want[v.ID] = string(raw)
				if index == 0 {
					first = v
				}
			}
		}
	}
	server, err := newLegacyServerFixture(ledger)
	if err != nil {
		t.Fatal(err)
	}
	human := peripheralFixtureHuman(owner)
	auth := &configuredAuthenticator{actor: human}
	server.authn = auth
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	cursor, firstCursor := "", ""
	for page := 0; page < 4; page++ {
		path := "/v1/marketplace-collectors?page_size=1&sort=id"
		if cursor != "" {
			path += "&cursor=" + url.QueryEscape(cursor)
		}
		out := getRaw(t, server, "fixture-auth", path, 200)
		var response struct {
			Data []json.RawMessage `json:"data"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(out.Body.Bytes(), &response); err != nil || len(response.Data) != 1 {
			t.Fatal("marketplace page lost a complete owned record", err)
		}
		var v domain.MarketplaceCollector
		if err := json.Unmarshal(response.Data[0], &v); err != nil || want[v.ID] == "" || found[v.ID] {
			t.Fatal("marketplace page returned foreign or repeated record", err)
		}
		assertTrustHTTPReplay(t, want[v.ID], string(response.Data[0]))
		found[v.ID] = true
		report, err := ledger.MarketplaceCollectorHealth(t.Context(), human, v.ID)
		if err != nil || len(report.Checks) != 4 || v.SignatureID == "" && report.SupplyChainStatus != "incomplete" || v.SignatureID != "" && report.SupplyChainStatus != "verified" {
			t.Fatal("health test lacks complete reference status", err)
		}
		wantHealth, err := json.Marshal(map[string]any{"data": report, "meta": map[string]string{"api_version": "v1"}})
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(wantHealth), getRaw(t, server, "fixture-auth", "/v1/marketplace-collectors/"+v.ID+"/health", 200).Body.String())
		if response.Meta.NextCursor == "" {
			break
		}
		if cursor == response.Meta.NextCursor {
			t.Fatal("marketplace cursor failed to advance")
		}
		cursor = response.Meta.NextCursor
		if firstCursor == "" {
			firstCursor = cursor
		}
	}
	if len(found) != len(want) || firstCursor == "" {
		t.Fatal("marketplace pagination lost records or never continued")
	}
	for id, v := range before.MarketplaceCollectors {
		if v.TenantID == foreign.actor.TenantID {
			getRaw(t, server, "fixture-auth", "/v1/marketplace-collectors/"+id+"/health", 404)
		}
	}
	for _, grants := range [][]domain.ResourceGrant{nil, {{ResourceType: "product", ResourceID: owner.product.ID, Scopes: []string{"collector:read"}}}, {{ResourceType: "tenant", ResourceID: foreign.actor.TenantID, Scopes: []string{"collector:read"}}}} {
		auth.actor.ResourceGrants = grants
		getRaw(t, server, "fixture-auth", "/v1/marketplace-collectors", 403)
		getRaw(t, server, "fixture-auth", "/v1/marketplace-collectors/"+first.ID+"/health", 403)
	}
	auth.actor = foreign.actor
	getRaw(t, server, "fixture-auth", "/v1/marketplace-collectors?page_size=1&sort=id&cursor="+url.QueryEscape(firstCursor), 400)
	auth.actor = human
	query := marketplaceQueryFixture{catalogFixtureCommands{ledger: ledger}}
	page, err := query.ListPage(t.Context(), human, appquery.PageRequest{PageSize: 100, Sort: appquery.SortID, Direction: appquery.Ascending}, nil)
	if err != nil || len(page.Items) != 3 {
		t.Fatal(err)
	}
	page.Items[0].Limitations[0] = "modified"
	health, err := query.Health(t.Context(), human, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantHealth, err := json.Marshal(marketplaceCollectorHealthFromQuery(health))
	if err != nil {
		t.Fatal(err)
	}
	health.Collector.Limitations[0], health.Checks[0].Detail, health.Assumptions[0], health.Limitations[0] = "modified", "modified", "modified", "modified"
	again, err := query.Health(t.Context(), human, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	gotHealth, err := json.Marshal(marketplaceCollectorHealthFromQuery(again))
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(wantHealth), string(gotHealth))
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := query.Health(canceled, human, first.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("health ignored cancellation", err)
	}
	if _, err := query.ListPage(canceled, human, appquery.PageRequest{PageSize: 1, Sort: appquery.SortID, Direction: appquery.Ascending}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("marketplace page ignored cancellation", err)
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("marketplace read or returned nested data mutated authoritative fixture state", err)
	}
}

func TestPeripheralFixtureGuardsArePureAndHonorCancellation(t *testing.T) {
	ledger, factory := integrationRegressionLedger()
	owner := seedPeripheralFixtureScope(t, ledger, "Owner")
	commands := peripheralFixtureCommands{catalogFixtureCommands{ledger: ledger}}
	human := peripheralFixtureHuman(owner)
	requests := peripheralFixtureRequests(owner, owner.actor.TenantID)
	graph, err := decodeGraphSnapshotRequest([]byte(requests[0].body))
	if err != nil {
		t.Fatal(err)
	}
	saas, err := decodeSaaSProfileRequest([]byte(requests[1].body))
	if err != nil {
		t.Fatal(err)
	}
	marketplace, err := decodeMarketplaceCollectorRequest([]byte(requests[2].body))
	if err != nil {
		t.Fatal(err)
	}
	before, err := factory.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, authorize := range []func(context.Context) error{
		func(ctx context.Context) error { return commands.AuthorizeCreateGraphSnapshot(ctx, human, graph) },
		func(ctx context.Context) error { return commands.AuthorizeCreateSaaSProfile(ctx, human, saas) },
		func(ctx context.Context) error {
			return commands.AuthorizeCreateMarketplaceCollector(ctx, human, marketplace)
		},
	} {
		if err := authorize(t.Context()); err != nil {
			t.Fatal("real preflight denied owned command", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := authorize(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("preflight ignored cancellation", err)
		}
	}
	after, err := factory.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("pure guards inserted command, audit, outbox or replay records", err)
	}
}

func TestBindLedgerPreservesExplicitPeripheralPorts(t *testing.T) {
	first, _ := integrationRegressionLedger()
	second, _ := integrationRegressionLedger()
	graph, saas, marketplace, query := &graphHTTPFake{}, &saasHTTPCommands{}, &marketplaceHTTPCommands{}, &marketplaceCollectorQueryFake{}
	executor := &decisionHTTPExecutorFake{}
	s, err := newLegacyServerFixtureWithOptionsContext(t.Context(), first, ServerOptions{GraphSnapshotCommands: graph, SaaSProfileCommands: saas, MarketplaceCollectorCommands: marketplace, MarketplaceCollectorQuery: query, DurableCommandExecutor: executor})
	if err != nil {
		t.Fatal(err)
	}
	s.bindLegacyLedgerFixture(second)
	if s.graphSnapshotCommands != graph || s.saasProfileCommands != saas || s.marketplaceCollectorCommands != marketplace || s.marketplaceCollectorQuery != query || s.durableCommandExecutor != executor {
		t.Fatal("fixture rebinding overwrote explicitly configured peripheral ports")
	}
}

func TestPeripheralFixtureMappersPreserveEveryPublicFieldWithoutAliasing(t *testing.T) {
	ledger, _ := integrationRegressionLedger()
	owner := seedPeripheralFixtureScope(t, ledger, "Owner")
	graph, err := ledger.CreateGraphSnapshot(t.Context(), owner.actor, app.CreateGraphSnapshotInput{ProductID: owner.product.ID, ReleaseID: owner.release.ID})
	if err != nil || len(graph.Nodes) == 0 || len(graph.Edges) == 0 || len(graph.Limitations) == 0 {
		t.Fatal("graph mapper lacks nested source", err)
	}
	operator := owner.actor
	operator.Scopes = []string{"instance:admin"}
	saas, err := ledger.CreateSaaSEditionProfile(t.Context(), operator, app.CreateSaaSEditionProfileInput{Name: "Hosted", Region: "eu", AdminTenantID: owner.actor.TenantID, IsolationModel: "shared"})
	if err != nil || len(saas.Limitations) == 0 {
		t.Fatal(err)
	}
	in, err := decodeMarketplaceCollectorRequest([]byte(peripheralFixtureRequests(owner, owner.actor.TenantID)[2].body))
	if err != nil {
		t.Fatal(err)
	}
	collector, err := ledger.CreateMarketplaceCollector(t.Context(), owner.actor, marketplaceCollectorLegacyInput(in))
	if err != nil || len(collector.Limitations) == 0 {
		t.Fatal(err)
	}
	graphModel, saasModel, collectorModel := graphFixtureModel(graph), saasFixtureModel(saas), marketplaceFixtureModel(collector)
	for _, pair := range []struct {
		original any
		encode   func() ([]byte, error)
	}{
		{graph, func() ([]byte, error) { return packageapp.EncodeGraphSnapshot(graphModel) }},
		{saas, func() ([]byte, error) { return experimentalapp.EncodeSaaSProfile(saasModel) }},
		{collector, func() ([]byte, error) { return experimentalapp.EncodeMarketplaceCollector(collectorModel) }},
	} {
		want, err := json.Marshal(pair.original)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pair.encode()
		if err != nil {
			t.Fatal(err)
		}
		assertTrustHTTPReplay(t, string(want), string(got))
	}
	graphBefore, saasBefore, collectorBefore := graphFixtureModel(graph), saasFixtureModel(saas), marketplaceFixtureModel(collector)
	graphModel.Nodes[0].Label, graphModel.Edges[0].Relationship, graphModel.Limitations[0] = "modified", "modified", "modified"
	saasModel.Limitations[0], collectorModel.Limitations[0] = "modified", "modified"
	if !reflect.DeepEqual(graphBefore, graphFixtureModel(graph)) || !reflect.DeepEqual(saasBefore, saasFixtureModel(saas)) || !reflect.DeepEqual(collectorBefore, marketplaceFixtureModel(collector)) {
		t.Fatal("focused fixture mappers alias legacy mutable slices")
	}
}
