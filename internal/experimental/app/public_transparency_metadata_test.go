package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type transparencyMetadataFixture struct {
	source  PublicTransparencyPublicationSource
	phase   string
	reads   int
	logs    []d.PublicTransparencyLog
	entries []d.PublicTransparencyLogEntry
	audits  []application.AuditEvent
	cancel  context.CancelFunc
}

var errTransparencyMetadataFixture = errors.New("metadata fixture failure")

func (f *transparencyMetadataFixture) ExecutePublicTransparencyMetadata(ctx context.Context, _ string, fn func(context.Context, PublicTransparencyMetadataTransaction) error) error {
	n, m, k := len(f.logs), len(f.entries), len(f.audits)
	err := fn(ctx, f)
	if err == nil && f.phase == "commit" {
		err = errTransparencyMetadataFixture
	}
	if err != nil {
		f.logs, f.entries, f.audits = f.logs[:n], f.entries[:m], f.audits[:k]
	}
	return err
}
func (f *transparencyMetadataFixture) ReadPublicTransparencyTenant(context.Context, string) error {
	f.reads++
	if f.phase == "read" {
		return errTransparencyMetadataFixture
	}
	return nil
}
func (f *transparencyMetadataFixture) ReadPublicTransparencyPublication(context.Context, string, string, string) (PublicTransparencyPublicationSource, error) {
	f.reads++
	if f.phase == "read" {
		return PublicTransparencyPublicationSource{}, errTransparencyMetadataFixture
	}
	return f.source, nil
}
func (f *transparencyMetadataFixture) InsertPublicTransparencyLog(_ context.Context, v d.PublicTransparencyLog) error {
	if f.phase == "insert" {
		return errTransparencyMetadataFixture
	}
	f.logs = append(f.logs, v)
	return nil
}
func (f *transparencyMetadataFixture) InsertPublicTransparencyEntry(_ context.Context, v d.PublicTransparencyLogEntry) error {
	if f.phase == "insert" {
		return errTransparencyMetadataFixture
	}
	f.entries = append(f.entries, v)
	return nil
}
func (f *transparencyMetadataFixture) AppendAudit(_ context.Context, v application.AuditEvent) (application.AuditReceipt, error) {
	if f.phase == "audit" {
		return application.AuditReceipt{}, errTransparencyMetadataFixture
	}
	f.audits = append(f.audits, v)
	if f.phase == "cancel" {
		f.cancel()
	}
	return application.AuditReceipt{}, nil
}
func transparencyMetadataCommandFixture(t *testing.T) (*PublicTransparencyMetadataCommands, *transparencyMetadataFixture, identitydomain.Actor) {
	t.Helper()
	f := &transparencyMetadataFixture{source: PublicTransparencyPublicationSource{TenantID: "tenant", LogID: "log", CheckpointID: "checkpoint", BatchID: "batch", RootHash: "sha256:" + strings.Repeat("A", 64)}}
	c, err := NewPublicTransparencyMetadataCommands(PublicTransparencyMetadataConfig{Transactions: f, Clock: application.ClockFunc(func() time.Time { return time.Date(2026, 10, 4, 12, 0, 0, 123456789, time.UTC) }), IDs: application.IDGeneratorFunc(func(prefix string) string { return prefix + "-id" })})
	if err != nil {
		t.Fatal(err)
	}
	return c, f, identitydomain.Actor{TenantID: "tenant", KeyID: "operator", Scopes: []string{"keys:admin"}}
}
func TestPublicTransparencyMetadataCommandsPreserveHashAndRecordOnlySemantics(t *testing.T) {
	c, f, a := transparencyMetadataCommandFixture(t)
	in := PublicTransparencyLogInput{Name: " public ", Endpoint: " https://log.example.test/base ", PublicKey: " pub "}
	if err := c.AuthorizeCreatePublicTransparencyLog(t.Context(), a, in); err != nil || len(f.logs)+len(f.audits) != 0 {
		t.Fatal("guard writes", err)
	}
	v, err := c.CreatePublicTransparencyLog(t.Context(), a, in)
	if err != nil || v.Name != "public" || v.PublicKey != "pub" || v.State != "configured" || v.CreatedAt.Nanosecond() != 123456000 || len(f.logs) != 1 || f.audits[0].PayloadHash != "" {
		t.Fatal("log metadata changed", v, err)
	}
	p := PublicTransparencyPublicationInput{LogID: " log ", CheckpointID: " checkpoint ", ExternalID: " entry "}
	if err := c.AuthorizePublishPublicTransparencyLogEntry(t.Context(), a, p); err != nil || len(f.entries) != 0 {
		t.Fatal("publication guard writes", err)
	}
	e, err := c.PublishPublicTransparencyLogEntry(t.Context(), a, p)
	want, _ := application.NormalizedJSONHash(struct {
		LogID        string `json:"log_id"`
		CheckpointID string `json:"checkpoint_id"`
		MerkleRoot   string `json:"merkle_root"`
		ExternalID   string `json:"external_id"`
	}{"log", "checkpoint", f.source.RootHash, "entry"})
	if err != nil || e.EntryHash != want || e.State != "published" || e.MerkleBatchID != "batch" || len(f.entries) != 1 || f.audits[1].PayloadHash != want || f.audits[1].SubjectID != e.ID {
		t.Fatal("publication hash/audit changed", e, err)
	}
	raw, err := EncodePublicTransparencyPublication(e)
	if err != nil || strings.Contains(string(raw), "inclusion_") || strings.Contains(string(raw), "verification_") || strings.Contains(string(raw), "LogID") {
		t.Fatal("unverified metadata gained assurance fields", string(raw), err)
	}
}
func TestPublicTransparencyMetadataCommandsRejectBeforeReadsAndRollBack(t *testing.T) {
	for _, mode := range []string{"human-product", "anonymous", "name", "endpoint", "key", "credentials", "fragment", "empty-host", "nul", "utf8", "read", "insert", "audit", "commit", "foreign", "root"} {
		t.Run(mode, func(t *testing.T) {
			c, f, a := transparencyMetadataCommandFixture(t)
			in := PublicTransparencyLogInput{Name: "public", Endpoint: "https://log.example.test", PublicKey: "pub"}
			publish := false
			switch mode {
			case "human-product":
				a.KeyID, a.UserID = "", "user"
				a.ResourceGrants = []identitydomain.ResourceGrant{{ResourceType: "product", ResourceID: "product", Scopes: a.Scopes}}
			case "anonymous":
				a.KeyID = ""
			case "name":
				in.Name = strings.Repeat(" ", 257) + "n"
			case "endpoint":
				in.Endpoint = "http://log.example.test"
			case "key":
				in.PublicKey = strings.Repeat("k", 16385)
			case "credentials":
				in.Endpoint = "https://user:password@log.example.test"
			case "fragment":
				in.Endpoint += "#private"
			case "empty-host":
				in.Endpoint = "https://"
			case "nul":
				in.Name += "\x00"
			case "utf8":
				in.Name = string([]byte{255})
			case "read", "insert", "audit", "commit":
				f.phase = mode
			case "foreign":
				f.source.TenantID = "other"
				publish = true
			case "root":
				f.source.RootHash = "sha256:bad"
				publish = true
			}
			var err error
			if publish {
				v, e := c.PublishPublicTransparencyLogEntry(t.Context(), a, PublicTransparencyPublicationInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "entry"})
				err = e
				if v.ID != "" {
					t.Fatal("published failure")
				}
			} else {
				v, e := c.CreatePublicTransparencyLog(t.Context(), a, in)
				err = e
				if v.ID != "" {
					t.Fatal("published failure")
				}
			}
			if err == nil || len(f.logs)+len(f.entries)+len(f.audits) != 0 {
				t.Fatal("unsafe/partial metadata", err)
			}
			if !publish && f.phase == "" && f.reads != 0 {
				t.Fatal("invalid input reached storage")
			}
		})
	}
	for _, phase := range []string{"read", "insert", "audit", "commit"} {
		c, f, a := transparencyMetadataCommandFixture(t)
		f.phase = phase
		if v, err := c.PublishPublicTransparencyLogEntry(t.Context(), a, PublicTransparencyPublicationInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "entry"}); err == nil || v.ID != "" || len(f.entries)+len(f.audits) != 0 {
			t.Fatal("partial publication", phase, v, err)
		}
	}
}

func TestPublicTransparencyMetadataCommandsPortsCancellationAndGeneratedBounds(t *testing.T) {
	for _, missing := range []string{"transactions", "clock", "ids"} {
		c, _, _ := transparencyMetadataCommandFixture(t)
		config := c.config
		switch missing {
		case "transactions":
			config.Transactions = nil
		case "clock":
			config.Clock = nil
		case "ids":
			config.IDs = nil
		}
		if v, err := NewPublicTransparencyMetadataCommands(config); !errors.Is(err, ErrValidation) || v != nil {
			t.Fatal("missing metadata port accepted", missing)
		}
	}
	for _, mode := range []string{"pre-cancel", "post-audit-cancel", "id", "time"} {
		c, f, a := transparencyMetadataCommandFixture(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		want := ErrValidation
		switch mode {
		case "pre-cancel":
			cancel()
			want = context.Canceled
		case "post-audit-cancel":
			f.phase, f.cancel = "cancel", cancel
			want = context.Canceled
		case "id":
			c.config.IDs = application.IDGeneratorFunc(func(string) string { return "bad\x00" })
		case "time":
			c.config.Clock = application.ClockFunc(func() time.Time { return time.Time{} })
		}
		if v, err := c.PublishPublicTransparencyLogEntry(ctx, a, PublicTransparencyPublicationInput{LogID: "log", CheckpointID: "checkpoint", ExternalID: "external"}); !errors.Is(err, want) || v.ID != "" || len(f.entries)+len(f.audits) != 0 {
			t.Fatal("invalid/canceled publication escaped transaction", mode, v, err)
		}
	}
}
