package app

import (
	"context"
	"errors"
	"testing"
	"time"

	application "github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

func TestStandaloneArtifactCommandsPreserveDigestDeduplicationAndAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	commands, err := NewArtifactCommands(ArtifactCommandConfig{
		Authorizer:   fixture.authorizer,
		Transactions: releaseArtifactTransactions{runner: fixture.transactions},
		Clock:        application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:          application.IDGeneratorFunc(func(prefix string) string { return prefix + "_standalone" }),
	})
	if err != nil {
		t.Fatal(err)
	}
	input := RegisterArtifactInput{Name: " Output ", MediaType: " application/octet-stream ", Digest: testSHA256('a'), Size: 1}
	artifact, err := commands.RegisterArtifact(context.Background(), fixture.actor, input)
	if err != nil || artifact.ID != "art_standalone" || artifact.Name != "Output" || artifact.MediaType != "application/octet-stream" {
		t.Fatalf("register artifact=%#v err=%v", artifact, err)
	}
	if len(fixture.transactions.state.artifacts) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("artifact and audit not committed together: %#v", fixture.transactions.state)
	}
	replayed, err := commands.RegisterArtifact(context.Background(), fixture.actor, input)
	if err != nil || replayed.ID != artifact.ID || len(fixture.transactions.state.artifacts) != 1 || len(fixture.transactions.state.audit) != 1 {
		t.Fatalf("same digest did not return original: %#v err=%v state=%#v", replayed, err, fixture.transactions.state)
	}
	before := fixture.transactions.calls
	if _, err := commands.RegisterArtifact(context.Background(), fixture.actor, RegisterArtifactInput{
		Name: "Invalid", MediaType: "application/octet-stream", Digest: "sha256:short", Size: 1,
	}); !errors.Is(err, ErrValidation) || fixture.transactions.calls != before {
		t.Fatalf("invalid digest err=%v transactions=%d, want pre-transaction rejection", err, fixture.transactions.calls)
	}
}

type conflictingArtifactTransactions struct {
	artifact   releasedomain.Artifact
	lookups    int
	authorized int
	audits     int
}

func (t *conflictingArtifactTransactions) ExecuteArtifact(ctx context.Context, command func(context.Context, ArtifactTransaction) error) error {
	return command(ctx, t)
}

func (t *conflictingArtifactTransactions) ArtifactByDigest(context.Context, string, string) (releasedomain.Artifact, bool, error) {
	t.lookups++
	if t.lookups == 1 {
		return releasedomain.Artifact{}, false, nil
	}
	return t.artifact, true, nil
}

func (t *conflictingArtifactTransactions) InsertArtifact(context.Context, releasedomain.Artifact) error {
	return ErrConflict
}

func (t *conflictingArtifactTransactions) AuthorizeExisting(context.Context, identitydomain.Actor, string) error {
	t.authorized++
	return nil
}

func (t *conflictingArtifactTransactions) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	t.audits++
	return application.AuditReceipt{}, nil
}

func TestArtifactCommandsResolveConcurrentDigestConflictWithoutNewAudit(t *testing.T) {
	fixture := newServiceFixture(t)
	digest := testSHA256('b')
	transactions := &conflictingArtifactTransactions{artifact: releasedomain.Artifact{
		ID: "art_winner", TenantID: fixture.actor.TenantID, Name: "Winner",
		MediaType: "application/octet-stream", Digest: digest, Size: 1, CreatedAt: fixture.now,
	}}
	commands, err := NewArtifactCommands(ArtifactCommandConfig{
		Authorizer: fixture.authorizer, Transactions: transactions,
		Clock: application.ClockFunc(func() time.Time { return fixture.now }),
		IDs:   application.IDGeneratorFunc(func(prefix string) string { return prefix + "_loser" }),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := commands.RegisterArtifact(t.Context(), fixture.actor, RegisterArtifactInput{
		Name: "Loser", MediaType: "application/octet-stream", Digest: digest, Size: 1,
	})
	if err != nil || artifact.ID != transactions.artifact.ID || transactions.lookups != 2 || transactions.authorized != 1 || transactions.audits != 0 {
		t.Fatalf("race resolution artifact=%#v err=%v tx=%#v", artifact, err, transactions)
	}
}
