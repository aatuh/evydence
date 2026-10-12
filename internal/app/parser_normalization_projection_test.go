package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type parserNormalizationProjectionStoreStub struct {
	initial     PersistedState
	projections map[string]WorkerProjection
	loads       []string
}

func (s *parserNormalizationProjectionStoreStub) LoadState(context.Context) (PersistedState, bool, error) {
	state, err := cloneState(s.initial)
	return state, err == nil, err
}

func (*parserNormalizationProjectionStoreStub) SaveState(context.Context, PersistedState) error {
	return nil
}

func (s *parserNormalizationProjectionStoreStub) LoadWorkerProjection(_ context.Context, tenantID string) (WorkerProjection, error) {
	s.loads = append(s.loads, tenantID)
	return s.projections[tenantID], nil
}

func TestParserNormalizationProjectionMakesExternalReplayVisible(t *testing.T) {
	initial, projection, derivedID := parserNormalizationProjectionFixture(t, "ten_parser_projection")
	actor := domain.Actor{TenantID: "ten_parser_projection", KeyID: "key_parser_projection", Scopes: []string{ScopeEvidenceRead}}

	for _, test := range []struct {
		name string
		read func(*Ledger) error
	}{
		{
			name: "get",
			read: func(ledger *Ledger) error {
				item, err := ledger.GetEvidence(context.Background(), actor, derivedID)
				if err == nil && (item.ID != derivedID || item.Type != "parser_normalization") {
					t.Fatalf("GetEvidence returned %#v", item)
				}
				return err
			},
		},
		{
			name: "list",
			read: func(ledger *Ledger) error {
				items, err := ledger.ListEvidence(context.Background(), actor, "", "parser_normalization")
				if err == nil && (len(items) != 1 || items[0].ID != derivedID) {
					t.Fatalf("ListEvidence returned %#v", items)
				}
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &parserNormalizationProjectionStoreStub{
				initial: initial,
				projections: map[string]WorkerProjection{
					actor.TenantID: projection,
				},
			}
			ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test", Store: store})
			if _, exists := ledger.evidence[derivedID]; exists {
				t.Fatal("derived evidence was visible before projection refresh")
			}
			if err := test.read(ledger); err != nil {
				t.Fatalf("read externally appended parser normalization: %v", err)
			}
			if len(store.loads) != 1 || store.loads[0] != actor.TenantID {
				t.Fatalf("projection loads = %#v", store.loads)
			}
		})
	}
}

func TestParserNormalizationProjectionKeepsCrossTenantReadsUndisclosed(t *testing.T) {
	initial, projection, derivedID := parserNormalizationProjectionFixture(t, "ten_parser_owner")
	initial.Tenants["ten_parser_other"] = domain.Tenant{ID: "ten_parser_other", Name: "Other", CreatedAt: fixedNow()}
	store := &parserNormalizationProjectionStoreStub{
		initial: initial,
		projections: map[string]WorkerProjection{
			"ten_parser_owner": projection,
			"ten_parser_other": {},
		},
	}
	ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test", Store: store})
	owner := domain.Actor{TenantID: "ten_parser_owner", KeyID: "key_parser_owner", Scopes: []string{ScopeEvidenceRead}}
	other := domain.Actor{TenantID: "ten_parser_other", KeyID: "key_parser_other", Scopes: []string{ScopeEvidenceRead}}

	if _, err := ledger.GetEvidence(context.Background(), owner, derivedID); err != nil {
		t.Fatalf("owner read: %v", err)
	}
	if _, err := ledger.GetEvidence(context.Background(), other, derivedID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant read error = %v, want not found", err)
	}
	if len(store.loads) != 2 || store.loads[0] != owner.TenantID || store.loads[1] != other.TenantID {
		t.Fatalf("tenant-scoped projection loads = %#v", store.loads)
	}
}

func TestParserNormalizationProjectionFeedsCustomerPackageManifest(t *testing.T) {
	initial, projection, derivedID := parserNormalizationProjectionFixture(t, "ten_parser_package")
	profile := domain.RedactionProfile{
		ID: "rp_parser_package", TenantID: "ten_parser_package", Name: "Parser normalization",
		AllowedTypes: []string{"parser_normalization"}, SchemaVersion: domain.RedactionProfileSchemaVersion,
		CreatedAt: fixedNow(),
	}
	initial.RedactionProfiles = map[string]domain.RedactionProfile{profile.ID: profile}
	store := &parserNormalizationProjectionStoreStub{
		initial: initial,
		projections: map[string]WorkerProjection{
			"ten_parser_package": projection,
		},
	}
	ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test", Store: store, Now: fixedNow})
	actor := domain.Actor{TenantID: "ten_parser_package", KeyID: "key_parser_package", Scopes: []string{ScopePackageWrite}}

	pkg, err := ledger.CreateCustomerSecurityPackage(context.Background(), actor, CreateCustomerPackageInput{
		ProductID: "prod_parser", ReleaseID: "rel_test", RedactionProfileID: profile.ID,
		Title: "Parser evidence package", ExpiresAt: fixedNow().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCustomerSecurityPackage: %v", err)
	}
	ids, ok := pkg.Manifest["evidence_ids"].([]string)
	if !ok || len(ids) != 1 || ids[0] != derivedID {
		t.Fatalf("package evidence ids = %#v", pkg.Manifest["evidence_ids"])
	}
}

func TestParserNormalizationProjectionSurvivesSourceRelationshipMutation(t *testing.T) {
	initial, projection, derivedID := parserNormalizationProjectionFixture(t, "ten_parser_linked_source")
	linkedRelease := domain.Release{
		ID: "rel_linked", TenantID: "ten_parser_linked_source", ProductID: "prod_parser",
		Version: "2.0.0", State: "draft", Revision: 1, CreatedAt: fixedNow(),
	}
	initial.Releases[linkedRelease.ID] = linkedRelease
	source := initial.Evidence["ev_source"]
	source.ReleaseID = linkedRelease.ID
	source.RelatedEvidenceRefs = append(source.RelatedEvidenceRefs, domain.EvidenceRef{
		Type: "release", ID: linkedRelease.ID, Relationship: "linked_to",
	})
	initial.Evidence[source.ID] = source

	store := &parserNormalizationProjectionStoreStub{
		initial: initial,
		projections: map[string]WorkerProjection{
			"ten_parser_linked_source": projection,
		},
	}
	ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test", Store: store})
	actor := domain.Actor{TenantID: "ten_parser_linked_source", KeyID: "key_parser_linked_source", Scopes: []string{ScopeEvidenceRead}}

	item, err := ledger.GetEvidence(context.Background(), actor, derivedID)
	if err != nil {
		t.Fatalf("GetEvidence after source link: %v", err)
	}
	if item.ReleaseID != "rel_test" || len(item.RelatedEvidenceRefs) != 1 || item.RelatedEvidenceRefs[0].Relationship != "replayed_from" {
		t.Fatalf("immutable replay changed with source relationship projection: %#v", item)
	}
}

func TestParserNormalizationProjectionRejectsShrinkDivergenceAndInvalidRelationships(t *testing.T) {
	initial, projection, derivedID := parserNormalizationProjectionFixture(t, "ten_parser_integrity")

	tests := []struct {
		name          string
		initial       PersistedState
		projection    WorkerProjection
		requestedID   string
		wantStillSeen bool
	}{
		{
			name:          "row shrink",
			initial:       parserNormalizationStateWithProjection(t, initial, projection),
			projection:    WorkerProjection{AuditChainEntries: projection.AuditChainEntries},
			requestedID:   derivedID,
			wantStillSeen: true,
		},
		{
			name:    "existing row divergence",
			initial: parserNormalizationStateWithProjection(t, initial, projection),
			projection: mutateParserNormalizationProjection(t, projection, func(item *domain.EvidenceItem, _ *domain.AuditChainEntry) {
				item.Title = "Mutated replay title"
				item.CanonicalHash = mustEvidenceCanonicalHash(t, *item)
			}),
			requestedID:   derivedID,
			wantStillSeen: true,
		},
		{
			name:    "source relationship",
			initial: initial,
			projection: mutateParserNormalizationProjection(t, projection, func(item *domain.EvidenceItem, _ *domain.AuditChainEntry) {
				item.RelatedEvidenceRefs[0].ID = "ev_foreign_source"
				item.Metadata["replay_of"] = "ev_foreign_source"
				item.CanonicalHash = mustEvidenceCanonicalHash(t, *item)
			}),
			requestedID: derivedID,
		},
		{
			name:    "source scope coordinate",
			initial: initial,
			projection: mutateParserNormalizationProjection(t, projection, func(item *domain.EvidenceItem, _ *domain.AuditChainEntry) {
				item.BuildID = "build_foreign"
				item.CanonicalHash = mustEvidenceCanonicalHash(t, *item)
			}),
			requestedID: derivedID,
		},
		{
			name:    "source subject relationship",
			initial: initial,
			projection: mutateParserNormalizationProjection(t, projection, func(item *domain.EvidenceItem, _ *domain.AuditChainEntry) {
				item.SubjectRefs = append(item.SubjectRefs, domain.SubjectRef{Type: "artifact", ID: "art_foreign"})
				item.CanonicalHash = mustEvidenceCanonicalHash(t, *item)
			}),
			requestedID: derivedID,
		},
		{
			name:    "audit relationship",
			initial: initial,
			projection: mutateParserNormalizationProjection(t, projection, func(_ *domain.EvidenceItem, entry *domain.AuditChainEntry) {
				entry.SubjectID = "ev_other"
				if err := RehashAuditChainEntry(entry); err != nil {
					t.Fatalf("rehash tampered audit entry: %v", err)
				}
			}),
			requestedID: derivedID,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &parserNormalizationProjectionStoreStub{
				initial: test.initial,
				projections: map[string]WorkerProjection{
					"ten_parser_integrity": test.projection,
				},
			}
			ledger := newLedgerWithStore(t, Config{APIKeyPepper: "test", Store: store})
			actor := domain.Actor{TenantID: "ten_parser_integrity", KeyID: "key_parser_integrity", Scopes: []string{ScopeEvidenceRead}}
			_, err := ledger.GetEvidence(context.Background(), actor, test.requestedID)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("GetEvidence error = %v, want conflict", err)
			}
			_, stillSeen := ledger.evidence[derivedID]
			if stillSeen != test.wantStillSeen {
				t.Fatalf("derived evidence visibility after failed refresh = %v, want %v", stillSeen, test.wantStillSeen)
			}
		})
	}
}

func TestReplayParserEvidenceNormalizesPostgresTimestampPrecision(t *testing.T) {
	initial, _, _ := parserNormalizationProjectionFixture(t, "ten_parser_precision")
	request := ParserReplayRequest{
		TenantID:      "ten_parser_precision",
		EvidenceID:    "ev_source",
		ParserVersion: ParserVersionScannerAdaptersJSON,
		ActorID:       "operator_precision",
		Now:           time.Date(2026, 9, 4, 10, 11, 12, 123456789, time.UTC),
	}
	raw := parserNormalizationRaw()
	result, err := ReplayParserEvidence(&initial, raw, request)
	if err != nil {
		t.Fatalf("ReplayParserEvidence: %v", err)
	}
	item := initial.Evidence[result.EvidenceID]
	if item.CreatedAt.Nanosecond()%1000 != 0 || item.ObservedAt.Nanosecond()%1000 != 0 {
		t.Fatalf("evidence timestamps exceed PostgreSQL precision: created=%s observed=%s", item.CreatedAt, item.ObservedAt)
	}
	entry := initial.Chain[request.TenantID][0]
	if entry.OccurredAt.Nanosecond()%1000 != 0 {
		t.Fatalf("audit timestamp exceeds PostgreSQL precision: %s", entry.OccurredAt)
	}
	if got := mustEvidenceCanonicalHash(t, item); got != item.CanonicalHash {
		t.Fatalf("canonical hash after precision normalization = %q, want %q", got, item.CanonicalHash)
	}
}

func parserNormalizationProjectionFixture(t *testing.T, tenantID string) (PersistedState, WorkerProjection, string) {
	t.Helper()
	now := fixedNow().UTC().Truncate(time.Microsecond)
	raw := parserNormalizationRaw()
	source := domain.EvidenceItem{
		ID: "ev_source", TenantID: tenantID, ProductID: "prod_parser", ReleaseID: "rel_test",
		Type: "vulnerability_scan", Subtype: "generic",
		Title: "Source scan", SourceSystem: "scanner", UploadedBy: "collector_test",
		ObservedAt: now, EvidenceVersion: 1, SchemaVersion: domain.EvidenceItemSchemaVersion,
		PayloadRef: "object://tenants/" + tenantID + "/payloads/source", PayloadHash: hashBytes(raw),
		PayloadMediaType: "application/json", PayloadSize: int64(len(raw)),
		CanonicalHash: hashBytes([]byte("source canonical")), Canonicalization: domain.CanonicalizationProfileVersion,
		TrustLevel: "L2", VerificationStatus: "pending", CreatedAt: now,
	}
	initial := PersistedState{
		Tenants:  map[string]domain.Tenant{tenantID: {ID: tenantID, Name: "Parser projection", CreatedAt: now}},
		Products: map[string]domain.Product{"prod_parser": {ID: "prod_parser", TenantID: tenantID, Name: "Parser product", Slug: "parser-product", CreatedAt: now}},
		Releases: map[string]domain.Release{"rel_test": {ID: "rel_test", TenantID: tenantID, ProductID: "prod_parser", Version: "1.0.0", State: "draft", Revision: 1, CreatedAt: now}},
		Evidence: map[string]domain.EvidenceItem{source.ID: source},
		Chain:    map[string][]domain.AuditChainEntry{},
	}
	replayed, err := cloneState(initial)
	if err != nil {
		t.Fatalf("clone initial state: %v", err)
	}
	result, err := ReplayParserEvidence(&replayed, raw, ParserReplayRequest{
		TenantID: tenantID, EvidenceID: source.ID, ParserVersion: ParserVersionScannerAdaptersJSON,
		ActorID: "operator_test", Now: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("ReplayParserEvidence: %v", err)
	}
	return initial, WorkerProjection{
		ParserNormalizations: []domain.EvidenceItem{replayed.Evidence[result.EvidenceID]},
		AuditChainEntries:    append([]domain.AuditChainEntry(nil), replayed.Chain[tenantID]...),
	}, result.EvidenceID
}

func parserNormalizationRaw() []byte {
	return []byte(`{"scanner":"generic","target_ref":"pkg:oci/api","release_id":"rel_test","findings":[]}`)
}

func parserNormalizationStateWithProjection(t *testing.T, initial PersistedState, projection WorkerProjection) PersistedState {
	t.Helper()
	state, err := cloneState(initial)
	if err != nil {
		t.Fatalf("clone initial state: %v", err)
	}
	for _, item := range projection.ParserNormalizations {
		state.Evidence[item.ID] = item
	}
	for _, entry := range projection.AuditChainEntries {
		state.Chain[entry.TenantID] = append(state.Chain[entry.TenantID], entry)
	}
	return state
}

func mutateParserNormalizationProjection(t *testing.T, projection WorkerProjection, mutate func(*domain.EvidenceItem, *domain.AuditChainEntry)) WorkerProjection {
	t.Helper()
	clonedState := PersistedState{Evidence: map[string]domain.EvidenceItem{}, Chain: map[string][]domain.AuditChainEntry{}}
	for _, item := range projection.ParserNormalizations {
		clonedState.Evidence[item.ID] = item
	}
	for _, entry := range projection.AuditChainEntries {
		clonedState.Chain[entry.TenantID] = append(clonedState.Chain[entry.TenantID], entry)
	}
	clonedState, err := cloneState(clonedState)
	if err != nil {
		t.Fatalf("clone projection: %v", err)
	}
	item := clonedState.Evidence[projection.ParserNormalizations[0].ID]
	entry := clonedState.Chain[item.TenantID][0]
	mutate(&item, &entry)
	return WorkerProjection{ParserNormalizations: []domain.EvidenceItem{item}, AuditChainEntries: []domain.AuditChainEntry{entry}}
}

func mustEvidenceCanonicalHash(t *testing.T, item domain.EvidenceItem) string {
	t.Helper()
	hash, err := canonicalHash(item)
	if err != nil {
		t.Fatalf("canonical hash: %v", err)
	}
	return hash
}
