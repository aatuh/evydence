package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

func TestFutureExtensionsAreEvidenceBackedAndTenantScoped(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	actor, release, artifact := setupReleaseRiskFixture(t, ledger)
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:   release.ProductID,
		ReleaseID:   release.ID,
		Type:        "security_review",
		Title:       "Release review",
		PayloadHash: sampleDigest("review"),
	})
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	template, err := ledger.CreateQuestionnaireTemplate(ctx, actor, CreateQuestionnaireTemplateInput{Name: "customer", Version: "1", Questions: []domain.QuestionnaireQuestion{{ID: "q1", Prompt: "Is review evidence available?", EvidenceType: "security_review"}}})
	if err != nil {
		t.Fatalf("template: %v", err)
	}

	summary, err := ledger.CreateEvidenceSummary(ctx, actor, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}})
	if err != nil {
		t.Fatalf("summary: %v", err)
	}
	if !strings.Contains(summary.Summary, "Release review") || len(summary.Citations) != 1 || summary.Citations[0].EvidenceID != evidence.ID {
		t.Fatalf("summary is not evidence-cited: %#v", summary)
	}
	if strings.Contains(strings.ToLower(summary.Summary), "compliant") {
		t.Fatalf("summary used compliance conclusion language: %s", summary.Summary)
	}

	draft, err := ledger.CreateQuestionnaireDraft(ctx, actor, CreateQuestionnaireDraftInput{TemplateID: template.ID, ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("questionnaire draft: %v", err)
	}
	if len(draft.Responses) != 1 || len(draft.Responses[0].EvidenceIDs) != 1 || draft.Responses[0].Answer == "" {
		t.Fatalf("draft responses = %#v", draft.Responses)
	}

	graph, err := ledger.CreateGraphSnapshot(ctx, actor, CreateGraphSnapshotInput{ProductID: release.ProductID, ReleaseID: release.ID})
	if err != nil {
		t.Fatalf("graph: %v", err)
	}
	if len(graph.Nodes) == 0 || len(graph.Edges) == 0 {
		t.Fatalf("graph should expose release adjacency: %#v", graph)
	}

	pdf, err := ledger.CreatePDFReportPackage(ctx, actor, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: release.ProductID, ReleaseID: release.ID, Title: "Readiness"})
	if err != nil {
		t.Fatalf("pdf: %v", err)
	}
	if !strings.HasPrefix(pdf.PayloadHash, "sha256:") || pdf.PayloadSize == 0 || len(pdf.Limitations) == 0 {
		t.Fatalf("pdf package = %#v", pdf)
	}

	anomaly, err := ledger.GenerateAnomalyReport(ctx, actor, AnomalyReportInput{SubjectType: "release", SubjectID: release.ID})
	if err != nil {
		t.Fatalf("anomaly report: %v", err)
	}
	if anomaly.Result == "" || len(anomaly.Limitations) == 0 {
		t.Fatalf("anomaly report = %#v", anomaly)
	}

	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatalf("auth other: %v", err)
	}
	if _, err := ledger.CreateEvidenceSummary(ctx, other, CreateEvidenceSummaryInput{SubjectType: "release", SubjectID: release.ID, EvidenceIDs: []string{evidence.ID}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant summary err=%v, want not found", err)
	}
	if _, err := ledger.CreateQuestionnaireDraft(ctx, other, CreateQuestionnaireDraftInput{TemplateID: template.ID, ProductID: release.ProductID, ReleaseID: release.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant draft err=%v, want not found", err)
	}
	if _, err := ledger.CreatePDFReportPackage(ctx, other, CreatePDFReportPackageInput{ReportType: "release_readiness", ProductID: release.ProductID, ReleaseID: release.ID, Title: "Bad"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant pdf err=%v, want not found", err)
	}
	_ = artifact
}

func TestFutureOperationalExtensionsAndPartialTrustClosures(t *testing.T) {
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow})
	ctx := context.Background()
	_, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*", ScopeInstanceAdmin})
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	product, err := ledger.CreateProduct(ctx, actor, "API", "api")
	if err != nil {
		t.Fatalf("product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1")
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := ledger.CreateSaaSEditionProfile(ctx, actor, CreateSaaSEditionProfileInput{Name: "hosted-eu", Region: "eu", AdminTenantID: actor.TenantID, IsolationModel: "shared-control-plane"}); err != nil {
		t.Fatalf("saas profile: %v", err)
	}

	batch, err := ledger.CreateMerkleBatch(ctx, actor, CreateMerkleBatchInput{})
	if err != nil {
		t.Fatalf("merkle batch: %v", err)
	}
	log, err := ledger.CreatePublicTransparencyLog(ctx, actor, CreatePublicTransparencyLogInput{Name: "public-test", Endpoint: "https://transparency.example.test", PublicKey: "pub"})
	if err != nil {
		t.Fatalf("public log: %v", err)
	}
	checkpoint, err := ledger.CreateTransparencyCheckpoint(ctx, actor, CreateTransparencyCheckpointInput{BatchID: batch.ID, Provider: "internal", ExternalID: "ts-1"})
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	entry, err := ledger.PublishPublicTransparencyLogEntry(ctx, actor, PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: checkpoint.ID, ExternalID: "entry-1"})
	if err != nil {
		t.Fatalf("public log entry: %v", err)
	}
	if entry.MerkleBatchID != batch.ID || entry.EntryHash == "" {
		t.Fatalf("public log entry = %#v", entry)
	}

	provider, err := ledger.CreateSigningProvider(ctx, actor, CreateSigningProviderInput{Name: "kms", Type: "aws_kms", KeyRef: "arn:aws:kms:example", Encrypted: true})
	if err != nil {
		t.Fatalf("signing provider: %v", err)
	}
	op, err := ledger.CreateSigningOperation(ctx, actor, CreateSigningOperationInput{ProviderID: provider.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload"), ExternalSignature: "sig"})
	if err != nil {
		t.Fatalf("signing operation: %v", err)
	}
	if op.Result != "passed" || op.SignatureRef == "" {
		t.Fatalf("signing operation = %#v", op)
	}

	oidcProvider, err := ledger.CreateSSOProvider(ctx, actor, CreateSSOProviderInput{Name: "OIDC", Type: "oidc", Issuer: "https://idp.example.test", ClientID: "client"})
	if err != nil {
		t.Fatalf("sso provider: %v", err)
	}
	org, err := ledger.CreateOrganization(ctx, actor, CreateOrganizationInput{Name: "Example", Slug: "example"})
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	user, err := ledger.CreateUser(ctx, actor, CreateUserInput{OrganizationID: org.ID, Email: "user@example.test", DisplayName: "User"})
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := ledger.LinkSSOIdentity(ctx, actor, LinkSSOIdentityInput{UserID: user.ID, ProviderID: oidcProvider.ID, Subject: "sub-1", Email: user.Email, Verified: true}); err != nil {
		t.Fatalf("identity link: %v", err)
	}
	verification, err := ledger.VerifyProviderIdentity(ctx, actor, VerifyProviderIdentityInput{ProviderType: "oidc", ProviderID: oidcProvider.ID, Subject: "sub-1"})
	if err != nil {
		t.Fatalf("provider verification: %v", err)
	}
	if verification.Result != "passed" {
		t.Fatalf("provider verification = %#v", verification)
	}

	marketplace, err := ledger.CreateMarketplaceCollector(ctx, actor, CreateMarketplaceCollectorInput{Name: "scanner", Provider: "scannerco", Version: "1.0.0", Publisher: "scannerco", ManifestHash: sampleDigest("collector")})
	if err != nil {
		t.Fatalf("marketplace collector: %v", err)
	}
	listed, err := ledger.ListMarketplaceCollectors(ctx, actor)
	if err != nil {
		t.Fatalf("list marketplace: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != marketplace.ID {
		t.Fatalf("marketplace list = %#v", listed)
	}

	policy, err := ledger.CreateObjectRetentionPolicy(ctx, actor, CreateObjectRetentionPolicyInput{Name: "objects", ObjectPrefix: "tenants/" + actor.TenantID + "/", Mode: "compliance", RetentionDays: 90})
	if err != nil {
		t.Fatalf("retention policy: %v", err)
	}
	verified, err := ledger.VerifyObjectRetentionPolicy(ctx, actor, policy.ID)
	if err != nil {
		t.Fatalf("verify retention: %v", err)
	}
	if verified.Status != "verified" || verified.VerificationHash == "" {
		t.Fatalf("verified retention = %#v", verified)
	}

	_, _, otherSecret, err := ledger.BootstrapTenant(ctx, "Other", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap other: %v", err)
	}
	other, err := ledger.Authenticate(ctx, otherSecret)
	if err != nil {
		t.Fatalf("auth other: %v", err)
	}
	if _, err := ledger.PublishPublicTransparencyLogEntry(ctx, other, PublishPublicTransparencyLogEntryInput{LogID: log.ID, CheckpointID: checkpoint.ID, ExternalID: "bad"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant transparency err=%v, want not found", err)
	}
	if _, err := ledger.CreateSigningOperation(ctx, other, CreateSigningOperationInput{ProviderID: provider.ID, SubjectType: "release", SubjectID: release.ID, PayloadHash: sampleDigest("payload"), ExternalSignature: "sig"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross tenant signing operation err=%v, want not found", err)
	}
	if _, err := ledger.CreateSaaSEditionProfile(ctx, other, CreateSaaSEditionProfileInput{Name: "bad", Region: "eu", AdminTenantID: other.TenantID, IsolationModel: "shared-control-plane"}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-instance saas profile err=%v, want forbidden", err)
	}
}
