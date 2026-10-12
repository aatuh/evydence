package httpapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/app"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func newNativeDiffAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativeEvidenceReadAuthorizationFixture(t)
	var err error
	f.targetSBOM, err = uploadSBOMFixture(t.Context(), f.ledger, f.owner.actor, f.owner.release.ID, "", []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"one","purl":"pkg:generic/one@1"},{"type":"library","name":"next","purl":"pkg:generic/next@2"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	f.targetContract, err = uploadOpenAPIContractFixture(t.Context(), f.ledger, f.owner.actor, f.owner.product.ID, f.owner.release.ID, "2", []byte(`{"openapi":"3.1.0","info":{"title":"API","version":"2"},"paths":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newNativeTransparencyAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory, fetcher := transparencyRegressionLedger()
	owner, foreign := seedTransparencyFixtureScope(t, ledger, "Owner"), seedTransparencyFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.transparency, f.proofFetcher = owner, fetcher
	fetcher.result = app.TransparencyProofResult{ExternalID: owner.entry.ExternalID, RootHash: owner.entry.EntryHash, TreeSize: 1}
	f.server.bindTransparencyFixtureResources(fetcher, transparencyFixtureClock())
	return f
}

func newNativeReportSigningAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory, objects, signer := reportSigningRegressionLedger(t)
	owner, foreign := seedReportSigningFixtureScope(t, ledger, "Owner"), seedReportSigningFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, owner.operationsFixtureScope, foreign.operationsFixtureScope)
	f.reportSigning, f.objects, f.providerSigner = owner, objects, signer
	f.server.bindReportSigningFixtureResources(objects, signer)
	return f
}

func newNativeSignatureAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	ledger, factory, objects := signatureRegressionLedger(t)
	owner, foreign := seedSignatureFixtureScope(t, ledger, "Owner"), seedSignatureFixtureScope(t, ledger, "Foreign")
	f := nativeAuthorizationFixtureFromScopes(t, ledger, factory, operationsFixtureScope{actor: owner.actor, product: owner.product, evidence: owner.original}, operationsFixtureScope{actor: foreign.actor, product: foreign.product, evidence: foreign.original})
	f.artifact, f.objects = owner.artifact, objects
	f.server.bindArtifactSignatureFixtureResources(objects)
	var err error
	f.signature, err = createFixtureArtifactSignature(t.Context(), ledger, objects, owner.actor, verificationapp.CreateArtifactSignatureInput{ArtifactID: owner.artifact.ID, Algorithm: "cosign", Signature: "recorded-only"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func newNativeMarketplaceAuthorizationFixture(t *testing.T) nativeAuthorizationFixture {
	t.Helper()
	f := newNativePeripheralAuthorizationFixture(t)
	p := f.peripheral
	value, err := (peripheralFixtureCommands{catalogFixtureCommands{ledger: f.ledger}}).CreateMarketplaceCollector(t.Context(), p.actor, experimentalapp.MarketplaceCollectorInput{Name: "Scanner", Provider: "Example", Version: "1", Publisher: "Team", ManifestHash: "sha256:" + strings.Repeat("a", 64), SignatureID: p.signatureID, SBOMID: p.sbom.ID, ScanID: p.scan.ID})
	if err != nil {
		t.Fatal(err)
	}
	f.marketplaceID = value.ID
	return f
}

func addNativeMetadataAuthorizationCases(cases map[string]func(*testing.T)) {
	for _, tc := range []struct {
		operation, path string
		body            func(nativeAuthorizationFixture) string
	}{
		{"createSBOMDiff", "/v1/sbom-diffs", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"base_sbom_id":%q,"target_sbom_id":%q,"release_id":%q}`, f.evidence.sbom.ID, f.targetSBOM.ID, f.owner.release.ID)
		}},
		{"createOpenAPIDiff", "/v1/openapi-diffs", func(f nativeAuthorizationFixture) string {
			return fmt.Sprintf(`{"base_contract_id":%q,"target_contract_id":%q,"release_id":%q}`, f.evidence.contract.ID, f.targetContract.ID, f.owner.release.ID)
		}},
	} {
		cases[tc.operation] = nativeWriteAuthorizationFixtureCase(tc.operation, newNativeDiffAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) { return tc.path, []byte(tc.body(f)) }, 201, 404)
	}
	for _, tc := range []struct {
		operation               string
		index, foreign, fetches int
	}{
		{"createPublicTransparencyLog", 0, 0, 0}, {"publishPublicTransparencyLogEntry", 1, 404, 0}, {"verifyPublicTransparencyLogEntry", 2, 404, 0}, {"fetchPublicTransparencyLogEntryProof", 3, 404, 1},
	} {
		status := 201
		if tc.index >= 2 {
			status = 200
		}
		// The fetcher is an explicit external-I/O fake, not an authorization
		// result or proof of a real external log. The local policy/hash check
		// and its owned receipt/audit run in native transactions.
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, newNativeTransparencyAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := transparencyFixtureRequests(f.transparency)[tc.index]
			return r.path, []byte(r.body)
		}, nativeMutationExpectation{status: status, foreignStatus: tc.foreign, auditDelta: 1, proofFetches: tc.fetches})
	}
	for _, tc := range []struct {
		operation            string
		index, stages, signs int
	}{
		{"createPDFReportPackage", 0, 1, 0}, {"generateAnomalyReport", 1, 0, 0}, {"createSigningOperation", 2, 0, 1},
	} {
		// The provider executor is a controlled I/O response. It never
		// substitutes for the actual application authorization policy.
		cases[tc.operation] = nativeMutationAuthorizationFixtureCase(tc.operation, newNativeReportSigningAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
			r := reportSigningFixtureRequests(f.reportSigning)[tc.index]
			return r.path, []byte(r.body)
		}, nativeMutationExpectation{status: 201, foreignStatus: 404, auditDelta: 1, payloadStages: tc.stages, providerSigns: tc.signs})
	}
	cases["createArtifactSignature"] = nativeWriteAuthorizationFixtureCase("createArtifactSignature", newNativeSignatureAuthorizationFixture, func(f nativeAuthorizationFixture) (string, []byte) {
		return "/v1/artifact-signatures", []byte(fmt.Sprintf(`{"artifact_id":%q,"algorithm":"cosign","key_id":"public-key","signature":"recorded-signature"}`, f.artifact.ID))
	}, 201, 404)
	cases["getArtifactSignature"] = nativeReadAuthorizationFixtureCase("getArtifactSignature", newNativeSignatureAuthorizationFixture, func(f nativeAuthorizationFixture) string { return "/v1/artifact-signatures/" + f.signature.ID }, func(f nativeAuthorizationFixture) string { return f.signature.ID }, 404)
	for _, tc := range []struct {
		operation, path string
		foreign         int
	}{
		{"listMarketplaceCollectors", "/v1/marketplace-collectors", 200}, {"marketplaceCollectorHealth", "/v1/marketplace-collectors/", 404},
	} {
		cases[tc.operation] = nativeReadAuthorizationFixtureCase(tc.operation, newNativeMarketplaceAuthorizationFixture, func(f nativeAuthorizationFixture) string {
			if tc.foreign == 404 {
				return tc.path + f.marketplaceID + "/health"
			}
			return tc.path
		}, func(f nativeAuthorizationFixture) string { return f.marketplaceID }, tc.foreign)
	}
}
