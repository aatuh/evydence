package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
)

func TestIncidentWebhookPolicyCharacterizesBoundReceiverAndEvidenceBeforeRefactor(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*incidentWebhookFixture)
		want error
	}{
		{"inactive receiver", func(f *incidentWebhookFixture) { f.receiver.Status = "revoked" }, ErrNotFound},
		{"missing provider", func(f *incidentWebhookFixture) { f.receiver.Provider = " " }, ErrNotFound},
		{"foreign incident", func(f *incidentWebhookFixture) {
			s := f.subjects["incident:incident"]
			s.TenantID = "foreign"
			f.subjects["incident:incident"] = s
		}, ErrNotFound},
		{"foreign evidence tenant", func(f *incidentWebhookFixture) {
			s := f.subjects["evidence:evidence"]
			s.TenantID = "foreign"
			f.subjects["evidence:evidence"] = s
		}, ErrNotFound},
		{"different evidence product", func(f *incidentWebhookFixture) {
			s := f.subjects["evidence:evidence"]
			s.Resources.ProductID = "other"
			f.subjects["evidence:evidence"] = s
		}, ErrNotFound},
		{"different evidence release", func(f *incidentWebhookFixture) {
			s := f.subjects["evidence:evidence"]
			s.Resources.ReleaseID = "other"
			f.subjects["evidence:evidence"] = s
		}, ErrNotFound},
		{"product-wide evidence", func(f *incidentWebhookFixture) {
			s := f.subjects["evidence:evidence"]
			s.Resources.ReleaseID = ""
			f.subjects["evidence:evidence"] = s
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f, _, private, now := webhookFixture(t)
			tc.edit(f)
			r, e, err := c.HandleIncidentWebhook(t.Context(), signedWebhookInput(private, now, `{"event_type":"noted","summary":"Note","evidence_id":"evidence"}`))
			if !errors.Is(err, tc.want) {
				t.Fatal("receiver/evidence binding contract changed", err)
			}
			if tc.want != nil {
				if r.ID != "" || e.ID != "" || f.record.ID != "" || f.event.ID != "" || len(f.audits) != 0 {
					t.Fatal("wrong authority published incident/audit effects")
				}
			} else if r.ID == "" || e.EvidenceID != "evidence" || len(f.audits) != 1 {
				t.Fatal("permitted product-wide evidence lost its atomic receipt and audit")
			}
		})
	}
}

type delayedWebhookTransactions struct {
	base    IncidentWebhookTransactions
	phase   string
	advance func()
}

func (r delayedWebhookTransactions) ExecuteIncidentWebhook(ctx context.Context, fn func(context.Context, IncidentWebhookTransaction) error) error {
	return r.base.ExecuteIncidentWebhook(ctx, func(ctx context.Context, tx IncidentWebhookTransaction) error {
		return fn(ctx, delayedWebhookTransaction{tx, r.phase, r.advance})
	})
}

type delayedWebhookTransaction struct {
	IncidentWebhookTransaction
	phase   string
	advance func()
}

func (t delayedWebhookTransaction) ReadIncidentWebhookReceiver(ctx context.Context, tenant, id string) (operationsdomain.IncidentWebhookReceiver, error) {
	v, err := t.IncidentWebhookTransaction.ReadIncidentWebhookReceiver(ctx, tenant, id)
	if t.phase == "receiver" {
		t.advance()
	}
	return v, err
}

func (t delayedWebhookTransaction) ReadIncidentSubject(ctx context.Context, tenant, kind, id string) (IncidentSubject, error) {
	v, err := t.IncidentWebhookTransaction.ReadIncidentSubject(ctx, tenant, kind, id)
	if t.phase == kind {
		t.advance()
	}
	return v, err
}

func (t delayedWebhookTransaction) ReadIncidentWebhookReplay(ctx context.Context, tenant, receiver, event string) (operationsdomain.IncidentWebhookEvent, operationsdomain.IncidentTimelineEvent, error) {
	r, e, err := t.IncidentWebhookTransaction.ReadIncidentWebhookReplay(ctx, tenant, receiver, event)
	if t.phase == "replay" {
		t.advance()
	}
	return r, e, err
}

func TestIncidentWebhookPolicyRechecksFreshnessAfterBlockingReadsBeforeFreshWritesAndReplay(t *testing.T) {
	for _, phase := range []string{"receiver", "incident", "replay", "evidence"} {
		for _, replay := range []bool{false, true} {
			t.Run(phase+map[bool]string{false: "/fresh", true: "/replay"}[replay], func(t *testing.T) {
				c, f, _, private, now := webhookFixture(t)
				in := signedWebhookInput(private, now, `{"event_type":"noted","summary":"Note","evidence_id":"evidence"}`)
				if replay {
					if _, _, err := c.HandleIncidentWebhook(t.Context(), in); err != nil {
						t.Fatal(err)
					}
				}
				beforeRecord, beforeEvent := f.record, f.event
				beforeAudit := append([]application.AuditEvent(nil), f.audits...)
				at := now
				c.config.Clock = application.ClockFunc(func() time.Time { return at })
				c.config.Transactions = delayedWebhookTransactions{f, phase, func() { at = now.Add(IncidentWebhookTimestampTolerance + time.Microsecond) }}
				r, e, err := c.HandleIncidentWebhook(t.Context(), in)
				if !errors.Is(err, application.ErrUnauthorized) || r.ID != "" || e.ID != "" || f.record != beforeRecord || f.event != beforeEvent || !reflect.DeepEqual(beforeAudit, f.audits) {
					t.Fatal("expired signed authority survived blocking storage or changed receipt/audit state", err)
				}
			})
		}
	}
}

type cancelAfterWebhookCommit struct {
	base   IncidentWebhookTransactions
	cancel context.CancelFunc
}

func (r cancelAfterWebhookCommit) ExecuteIncidentWebhook(ctx context.Context, fn func(context.Context, IncidentWebhookTransaction) error) error {
	if err := r.base.ExecuteIncidentWebhook(ctx, fn); err != nil {
		return err
	}
	r.cancel()
	return nil
}

func TestIncidentWebhookPolicyWithholdsFreshAndReplayReceiptsAfterCommitCancellation(t *testing.T) {
	for _, replay := range []bool{false, true} {
		c, f, _, private, now := webhookFixture(t)
		in := signedWebhookInput(private, now, `{"event_type":"noted","summary":"Note"}`)
		if replay {
			if _, _, err := c.HandleIncidentWebhook(t.Context(), in); err != nil {
				t.Fatal(err)
			}
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		c.config.Transactions = cancelAfterWebhookCommit{f, cancel}
		r, e, err := c.HandleIncidentWebhook(ctx, in)
		if !errors.Is(err, context.Canceled) || r.ID != "" || e.ID != "" {
			t.Error("post-commit cancellation exposed a webhook receipt", err)
		}
		if f.record.ID == "" || f.event.ID == "" || len(f.audits) != 1 {
			t.Fatal("cancellation falsely undid a committed natural replay/event audit")
		}
	}
}

func TestIncidentWebhookPolicyWithholdsReceiverAfterCommitCancellation(t *testing.T) {
	c, f, actor, private, _ := webhookFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c.config.Transactions = cancelAfterWebhookCommit{f, cancel}
	v, err := c.CreateIncidentWebhookReceiver(ctx, actor, CreateIncidentWebhookReceiverInput{IncidentID: "incident", Name: "Pager", Provider: "pager", PublicKey: base64.RawStdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))})
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, operationsdomain.IncidentWebhookReceiver{}) || f.receiver.ID != "iwr_new" || len(f.audits) != 1 {
		t.Fatal("late canceled receiver creation exposed a result or misreported committed effects", err)
	}
}
