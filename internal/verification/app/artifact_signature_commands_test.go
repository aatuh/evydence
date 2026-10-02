package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

type signatureCreationFake struct {
	artifact                    SignatureArtifact
	failure                     string
	stages, reads, transactions int
	signatures                  []verificationdomain.ArtifactSignature
	payloads                    []SignaturePayload
	audit                       []application.AuditEvent
	jobs                        []application.OutboxEvent
}

var errSignatureCreationTest = errors.New("signature creation failure")

func (f *signatureCreationFake) Authorize(_ context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if !a.HasScope("evidence:write") || f.failure == "authorize" || !r.ScopeOnly && f.failure == "grant" {
		return ErrForbidden
	}
	if r.Scope != "evidence:write" || r.TenantWide || r.ScopeOnly && r.Resources != (application.ResourceReferences{}) || !r.ScopeOnly && r.Resources != (application.ResourceReferences{ArtifactID: "artifact"}) {
		return ErrForbidden
	}
	return nil
}
func (f *signatureCreationFake) ExecuteArtifactSignature(ctx context.Context, fn func(context.Context, ArtifactSignatureTransaction) error) error {
	f.transactions++
	tx := *f
	if err := fn(ctx, &tx); err != nil {
		return err
	}
	if f.failure == "commit" {
		return errSignatureCreationTest
	}
	f.signatures, f.payloads, f.audit, f.jobs = tx.signatures, tx.payloads, tx.audit, tx.jobs
	return nil
}
func (f *signatureCreationFake) LockSignatureArtifact(context.Context, string, string) (SignatureArtifact, error) {
	f.reads++
	if f.failure == "read" {
		return SignatureArtifact{}, errSignatureCreationTest
	}
	return f.artifact, nil
}
func (f *signatureCreationFake) StageSignaturePayload(_ context.Context, tenant, media, digest string, raw []byte, at time.Time) (SignaturePayload, error) {
	f.stages++
	if f.failure == "stage" {
		return SignaturePayload{}, errSignatureCreationTest
	}
	p := SignaturePayload{TenantID: tenant, Digest: digest, MediaType: media, Size: int64(len(raw)), StagingKey: "staged", FinalKey: "final", CreatedAt: at, UpdatedAt: at}
	if f.failure == "binding" {
		p.TenantID = "other"
	}
	return p, nil
}
func (f *signatureCreationFake) RecordSignaturePayload(_ context.Context, p SignaturePayload) error {
	if f.failure == "payload" {
		return errSignatureCreationTest
	}
	f.payloads = append(f.payloads, p)
	return nil
}
func (f *signatureCreationFake) InsertArtifactSignature(_ context.Context, s verificationdomain.ArtifactSignature) error {
	if f.failure == "insert" {
		return errSignatureCreationTest
	}
	f.signatures = append(f.signatures, s)
	return nil
}
func (f *signatureCreationFake) AppendAudit(_ context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	if f.failure == "audit" {
		return application.AuditReceipt{}, errSignatureCreationTest
	}
	f.audit = append(f.audit, a)
	return application.AuditReceipt{}, nil
}
func (f *signatureCreationFake) EnqueueOutbox(_ context.Context, j application.OutboxEvent) error {
	if f.failure == "outbox" {
		return errSignatureCreationTest
	}
	f.jobs = append(f.jobs, j)
	return nil
}
func newSignatureCreationFixture(t *testing.T) (*ArtifactSignatureCommands, *signatureCreationFake, identitydomain.Actor, CreateArtifactSignatureInput) {
	t.Helper()
	f := &signatureCreationFake{artifact: SignatureArtifact{ID: "artifact", TenantID: "tenant", Digest: "sha256:" + strings.Repeat("a", 64)}}
	ids := 0
	s, err := NewArtifactSignatureCommands(ArtifactSignatureConfig{Transactions: f, Authorizer: f, Objects: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { ids++; return fmt.Sprintf("%s_%d", prefix, ids) })})
	if err != nil {
		t.Fatal(err)
	}
	return s, f, identitydomain.Actor{TenantID: "tenant", KeyID: "key", Scopes: []string{"evidence:write"}}, CreateArtifactSignatureInput{ArtifactID: " artifact ", Algorithm: " cosign ", KeyID: " signer ", Signature: " recorded ", RawPayload: []byte(`{"bundle":"recorded"}`)}
}

func TestArtifactSignatureCreationCommitsRecordedMetadataPayloadAndAudit(t *testing.T) {
	for _, payload := range []bool{false, true} {
		s, f, a, in := newSignatureCreationFixture(t)
		if !payload {
			in.RawPayload = nil
		}
		v, err := s.CreateArtifactSignature(t.Context(), a, in)
		if err != nil || v.ID == "" || v.ArtifactID != "artifact" || v.TenantID != a.TenantID || v.SubjectDigest != f.artifact.Digest || v.Algorithm != "cosign" || v.Signature != "recorded" || v.KeyID != "signer" || v.VerificationStatus != "recorded" || v.SchemaVersion != verificationdomain.ArtifactSignatureSchemaVersion || len(f.signatures) != 1 || len(f.audit) != 1 {
			t.Fatal(v, f, err)
		}
		if f.audit[0].PayloadHash != v.SubjectDigest || f.audit[0].EntryType != "artifact_signature.created" || f.audit[0].ActorID != a.KeyID {
			t.Fatal(f.audit)
		}
		if payload {
			if len(f.payloads) != 1 || len(f.jobs) != 1 || v.PayloadRef != "object://final" || v.PayloadHash != f.payloads[0].Digest || f.payloads[0].MediaType != "application/octet-stream" || f.jobs[0].Kind != "finalize_payload" || f.jobs[0].SubjectID != v.PayloadHash || len(f.jobs[0].Payload) != 2 {
				t.Fatal(v, f)
			}
		} else if v.PayloadRef != "" || v.PayloadHash != "" || len(f.payloads) != 0 || len(f.jobs) != 0 {
			t.Fatal(v, f)
		}
	}
}

func TestArtifactSignatureCreationNeverPublishesFailedTransaction(t *testing.T) {
	for _, failure := range []string{"authorize", "grant", "read", "stage", "binding", "payload", "outbox", "insert", "audit", "commit"} {
		t.Run(failure, func(t *testing.T) {
			s, f, a, in := newSignatureCreationFixture(t)
			f.failure = failure
			v, err := s.CreateArtifactSignature(t.Context(), a, in)
			if err == nil || v != (verificationdomain.ArtifactSignature{}) || len(f.signatures)+len(f.payloads)+len(f.audit)+len(f.jobs) != 0 {
				t.Fatal(v, f, err)
			}
			if failure == "authorize" && f.transactions != 0 {
				t.Fatal("authorization followed data access")
			}
		})
	}
}

func TestArtifactSignatureCreationRejectsBadInputAndForeignArtifact(t *testing.T) {
	for _, mutate := range []func(*CreateArtifactSignatureInput){
		func(v *CreateArtifactSignatureInput) { v.ArtifactID = " " },
		func(v *CreateArtifactSignatureInput) { v.Algorithm = " " },
		func(v *CreateArtifactSignatureInput) { v.Signature = " " },
		func(v *CreateArtifactSignatureInput) { v.Signature = "sig\x00private" },
		func(v *CreateArtifactSignatureInput) { v.ArtifactID = strings.Repeat("i", 1025) },
		func(v *CreateArtifactSignatureInput) { v.KeyID = string([]byte{0xff}) },
		func(v *CreateArtifactSignatureInput) { v.PayloadMediaType = "application/json\r\nprivate" },
		func(v *CreateArtifactSignatureInput) { v.PayloadMediaType = "not a media type" },
		func(v *CreateArtifactSignatureInput) {
			v.Algorithm = strings.Repeat("a", MaxArtifactSignatureTextBytes+1)
		},
		func(v *CreateArtifactSignatureInput) { v.RawPayload = make([]byte, MaxArtifactSignaturePayloadBytes+1) },
	} {
		s, f, a, in := newSignatureCreationFixture(t)
		mutate(&in)
		if _, err := s.CreateArtifactSignature(t.Context(), a, in); !errors.Is(err, ErrValidation) || f.transactions != 0 {
			t.Fatal("bad input reached transaction", err, f)
		}
	}
	for _, artifact := range []SignatureArtifact{{ID: "artifact", TenantID: "other", Digest: "digest"}, {ID: "wrong", TenantID: "tenant", Digest: "digest"}} {
		s, f, a, in := newSignatureCreationFixture(t)
		f.artifact = artifact
		if _, err := s.CreateArtifactSignature(t.Context(), a, in); !errors.Is(err, ErrNotFound) || len(f.signatures) != 0 {
			t.Fatal(err)
		}
	}
	s, _, a, in := newSignatureCreationFixture(t)
	var missingContext context.Context
	if _, err := s.CreateArtifactSignature(missingContext, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.CreateArtifactSignature(ctx, a, in); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestArtifactSignatureCreationRequiresEveryDependency(t *testing.T) {
	for _, mutate := range []func(*ArtifactSignatureConfig){
		func(c *ArtifactSignatureConfig) { c.Transactions = nil },
		func(c *ArtifactSignatureConfig) { c.Authorizer = nil },
		func(c *ArtifactSignatureConfig) { c.Objects = nil },
		func(c *ArtifactSignatureConfig) { c.Clock = nil },
		func(c *ArtifactSignatureConfig) { c.IDs = nil },
	} {
		s, _, _, _ := newSignatureCreationFixture(t)
		config := s.config
		mutate(&config)
		if _, err := NewArtifactSignatureCommands(config); !errors.Is(err, ErrValidation) {
			t.Fatal(err)
		}
	}
}
