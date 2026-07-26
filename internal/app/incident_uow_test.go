package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
)

type failingIncidentRepository struct{ RiskRepository }

func (failingIncidentRepository) InsertIncident(context.Context, domain.Incident) error {
	return errInjectedRepositoryFailure
}

func (failingIncidentRepository) InsertIncidentTimelineEvent(context.Context, domain.IncidentTimelineEvent) error {
	return errInjectedRepositoryFailure
}

func (failingIncidentRepository) InsertIncidentWebhookReceiver(context.Context, domain.IncidentWebhookReceiver) error {
	return errInjectedRepositoryFailure
}

func (failingIncidentRepository) InsertIncidentWebhookEvent(context.Context, domain.IncidentWebhookEvent, domain.IncidentTimelineEvent) error {
	return errInjectedRepositoryFailure
}

func (failingIncidentRepository) InsertRemediationTask(context.Context, domain.RemediationTask) error {
	return errInjectedRepositoryFailure
}

func TestIncidentWritesUseUnitOfWorkAndPublishOnlyAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Incidents", "incidents")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ReleaseID: release.ID, Type: "security_review", Title: "Incident evidence", PayloadHash: sampleDigest("incident-evidence")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	beforeAudit := len(ledger.chain[actor.TenantID])
	incident, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: product.ID, ReleaseID: release.ID, Title: "Critical finding", Severity: "critical"})
	if err != nil {
		t.Fatalf("create incident: %v", err)
	}
	timeline, err := ledger.RecordIncidentTimelineEvent(ctx, actor, incident.ID, RecordIncidentTimelineInput{EventType: "detected", Summary: "finding detected", EvidenceID: evidence.ID})
	if err != nil {
		t.Fatalf("record incident timeline: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate webhook key: %v", err)
	}
	receiver, err := ledger.CreateIncidentWebhookReceiver(ctx, actor, CreateIncidentWebhookReceiverInput{IncidentID: incident.ID, Name: "Pager", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))})
	if err != nil {
		t.Fatalf("create webhook receiver: %v", err)
	}
	body := []byte(`{"event_type":"acknowledged","summary":"pager acknowledged"}`)
	signature := ed25519.Sign(privateKey, incidentWebhookSignedPayload(fixedNow(), "evt-uow", body))
	webhook, webhookTimeline, err := ledger.HandleIncidentWebhook(ctx, HandleIncidentWebhookInput{ReceiverID: receiver.ID, EventID: "evt-uow", Timestamp: fixedNow(), Signature: "ed25519=" + base64.RawStdEncoding.EncodeToString(signature), Body: body})
	if err != nil {
		t.Fatalf("handle incident webhook: %v", err)
	}
	dueAt := fixedNow().Add(time.Hour)
	task, err := ledger.CreateRemediationTask(ctx, actor, CreateRemediationTaskInput{IncidentID: incident.ID, ReleaseID: release.ID, Title: "Patch", Owner: "security", DueAt: &dueAt, EvidenceID: evidence.ID})
	if err != nil {
		t.Fatalf("create remediation task: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after incident writes: %v", err)
	}
	if snapshot.Incidents[incident.ID].ID != incident.ID || snapshot.IncidentTimelineEvents[timeline.ID].ID != timeline.ID || snapshot.IncidentTimelineEvents[webhookTimeline.ID].ID != webhookTimeline.ID || snapshot.IncidentWebhookReceivers[receiver.ID].ID != receiver.ID || snapshot.IncidentWebhookEvents[webhook.ID].ID != webhook.ID || snapshot.RemediationTasks[task.ID].ID != task.ID || len(snapshot.AuditEntries[actor.TenantID]) != beforeAudit+5 {
		t.Fatalf("incident writes were not committed: %#v", snapshot)
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: func(repositories Repositories) Repositories {
		repositories.Risk = failingIncidentRepository{RiskRepository: repositories.Risk}
		return repositories
	}}
	beforeIncidents, beforeTimeline, beforeReceivers := len(ledger.incidents), len(ledger.timeline), len(ledger.webhookReceivers)
	beforeWebhooks, beforeTasks, beforeAudit := len(ledger.webhookEvents), len(ledger.tasks), len(ledger.chain[actor.TenantID])
	if _, err := ledger.CreateIncident(ctx, actor, CreateIncidentInput{ProductID: product.ID, ReleaseID: release.ID, Title: "Failed", Severity: "high"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed incident err=%v, want injected repository failure", err)
	}
	if _, err := ledger.RecordIncidentTimelineEvent(ctx, actor, incident.ID, RecordIncidentTimelineInput{EventType: "failed", Summary: "failed timeline"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed timeline err=%v, want injected repository failure", err)
	}
	if _, err := ledger.CreateIncidentWebhookReceiver(ctx, actor, CreateIncidentWebhookReceiverInput{IncidentID: incident.ID, Name: "Failed", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed receiver err=%v, want injected repository failure", err)
	}
	failedBody := []byte(`{"event_type":"failed","summary":"failed webhook"}`)
	failedSignature := ed25519.Sign(privateKey, incidentWebhookSignedPayload(fixedNow(), "evt-failed", failedBody))
	if _, _, err := ledger.HandleIncidentWebhook(ctx, HandleIncidentWebhookInput{ReceiverID: receiver.ID, EventID: "evt-failed", Timestamp: fixedNow(), Signature: "ed25519=" + base64.RawStdEncoding.EncodeToString(failedSignature), Body: failedBody}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed webhook err=%v, want injected repository failure", err)
	}
	if _, err := ledger.CreateRemediationTask(ctx, actor, CreateRemediationTaskInput{IncidentID: incident.ID, ReleaseID: release.ID, Title: "Failed", Owner: "security"}); !errors.Is(err, errInjectedRepositoryFailure) {
		t.Fatalf("failed remediation task err=%v, want injected repository failure", err)
	}
	if len(ledger.incidents) != beforeIncidents || len(ledger.timeline) != beforeTimeline || len(ledger.webhookReceivers) != beforeReceivers || len(ledger.webhookEvents) != beforeWebhooks || len(ledger.tasks) != beforeTasks || len(ledger.chain[actor.TenantID]) != beforeAudit {
		t.Fatal("failed incident write published cached state")
	}
	after, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failed incident writes: %v", err)
	}
	if len(after.Incidents) != len(snapshot.Incidents) || len(after.IncidentTimelineEvents) != len(snapshot.IncidentTimelineEvents) || len(after.IncidentWebhookReceivers) != len(snapshot.IncidentWebhookReceivers) || len(after.IncidentWebhookEvents) != len(snapshot.IncidentWebhookEvents) || len(after.RemediationTasks) != len(snapshot.RemediationTasks) || len(after.AuditEntries[actor.TenantID]) != len(snapshot.AuditEntries[actor.TenantID]) {
		t.Fatalf("failed incident write published durable state: before=%#v after=%#v", snapshot, after)
	}
}
