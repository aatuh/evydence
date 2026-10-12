package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

type artifactRegistrationGuardFake struct {
	identity        ArtifactRegistrationIdentity
	found           bool
	lookups, grants int
	denied          bool
}

func (f *artifactRegistrationGuardFake) ExecuteArtifact(ctx context.Context, fn func(context.Context, ArtifactTransaction) error) error {
	return fn(ctx, f)
}
func (f *artifactRegistrationGuardFake) ArtifactIdentityByDigest(context.Context, string, string) (ArtifactRegistrationIdentity, bool, error) {
	f.lookups++
	return f.identity, f.found, nil
}
func (f *artifactRegistrationGuardFake) AuthorizeExisting(_ context.Context, _ identitydomain.Actor, id string) error {
	if id != f.identity.ID {
		return ErrNotFound
	}
	f.grants++
	if f.denied {
		return application.ErrForbidden
	}
	return nil
}
func (*artifactRegistrationGuardFake) ReadArtifactMetadata(context.Context, string, string) (releasedomain.Artifact, error) {
	panic("guard read private artifact metadata")
}
func (*artifactRegistrationGuardFake) InsertArtifact(context.Context, releasedomain.Artifact) error {
	panic("guard inserted artifact")
}
func (*artifactRegistrationGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard appended artifact audit")
}

func TestArtifactRegistrationGuardChecksCurrentIdentityWithoutMetadataOrWrites(t *testing.T) {
	f := newServiceFixture(t)
	tx := &artifactRegistrationGuardFake{identity: ArtifactRegistrationIdentity{ID: "artifact", TenantID: f.actor.TenantID, Digest: testSHA256('a')}, found: true}
	s, err := NewArtifactCommands(ArtifactCommandConfig{Authorizer: f.authorizer, Transactions: tx, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	in := RegisterArtifactInput{Name: " Original ", MediaType: " text/plain ", Digest: testSHA256('a'), Size: 1}
	if err := s.AuthorizeArtifactRegistration(t.Context(), f.actor, in); err != nil || tx.lookups != 1 || tx.grants != 1 {
		t.Fatal("guard skipped current identity/grant", err, tx)
	}
	tx.denied = true
	if err := s.AuthorizeArtifactRegistration(t.Context(), f.actor, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("removed grant retained replay", err)
	}
	tx.denied = false
	tx.identity.TenantID = "foreign"
	before := tx.grants
	if err := s.AuthorizeArtifactRegistration(t.Context(), f.actor, in); !errors.Is(err, ErrNotFound) || tx.grants != before {
		t.Fatal("foreign identity reached grant check", err, tx)
	}
	tx.identity.TenantID = f.actor.TenantID
	tx.identity.Digest = testSHA256('b')
	if err := s.AuthorizeArtifactRegistration(t.Context(), f.actor, in); !errors.Is(err, ErrConflict) {
		t.Fatal("inconsistent lookup retained replay", err)
	}
	tx.found = false
	if err := s.AuthorizeArtifactRegistration(t.Context(), f.actor, in); err != nil || tx.grants != before {
		t.Fatal("new digest required an existing artifact grant", err, tx)
	}
	before = tx.lookups
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.AuthorizeArtifactRegistration(ctx, f.actor, in); !errors.Is(err, context.Canceled) || tx.lookups != before {
		t.Fatal("cancelled guard opened transaction", err, tx)
	}
}

type imageRegistrationGuardFake struct {
	identity      ContainerImageRegistrationIdentity
	found         bool
	artifacts     map[string]releasedomain.Artifact
	reads, grants []string
	denied        string
}

func (f *imageRegistrationGuardFake) ExecuteContainerImage(ctx context.Context, fn func(context.Context, ContainerImageTransaction) error) error {
	return fn(ctx, f)
}
func (f *imageRegistrationGuardFake) Authorize(_ context.Context, _ identitydomain.Actor, r application.AuthorizationRequest) error {
	if r.ScopeOnly {
		return nil
	}
	f.grants = append(f.grants, r.Resources.ArtifactID)
	if f.denied == r.Resources.ArtifactID {
		return application.ErrForbidden
	}
	return nil
}
func (f *imageRegistrationGuardFake) ContainerImageRegistrationIdentityByKey(context.Context, string, string, string) (ContainerImageRegistrationIdentity, bool, error) {
	return f.identity, f.found, nil
}
func (f *imageRegistrationGuardFake) ReadContainerImageRegistrationArtifact(_ context.Context, _ string, id string) (releasedomain.Artifact, error) {
	f.reads = append(f.reads, id)
	v, ok := f.artifacts[id]
	if !ok {
		return releasedomain.Artifact{}, ErrNotFound
	}
	return v, nil
}
func (*imageRegistrationGuardFake) GetArtifact(context.Context, string, string) (releasedomain.Artifact, error) {
	panic("guard read current digest")
}
func (*imageRegistrationGuardFake) ContainerImageByRepositoryDigest(context.Context, string, string, string) (releasedomain.ContainerImage, bool, error) {
	panic("guard read private image metadata")
}
func (*imageRegistrationGuardFake) InsertContainerImage(context.Context, releasedomain.ContainerImage) error {
	panic("guard inserted image")
}
func (*imageRegistrationGuardFake) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("guard appended image audit")
}

func TestContainerImageRegistrationGuardChecksSubmittedAndExistingArtifactsWithoutMetadata(t *testing.T) {
	a := identitydomain.Actor{TenantID: "tenant", KeyID: "caller", Scopes: []string{ScopeEvidenceWrite}}
	tx := &imageRegistrationGuardFake{identity: ContainerImageRegistrationIdentity{ID: "image", TenantID: a.TenantID, ArtifactID: "existing"}, found: true, artifacts: map[string]releasedomain.Artifact{
		"submitted": {ID: "submitted", TenantID: a.TenantID}, "existing": {ID: "existing", TenantID: a.TenantID},
	}}
	s, err := NewContainerImageCommands(ContainerImageCommandConfig{Reader: tx, Authorizer: tx, Transactions: tx, Clock: application.ClockFunc(func() time.Time { panic("guard used clock") }), IDs: application.IDGeneratorFunc(func(string) string { panic("guard allocated ID") })})
	if err != nil {
		t.Fatal(err)
	}
	in := RegisterContainerImageInput{ArtifactID: "submitted", Repository: "registry.example.test/api", Digest: testSHA256('a')}
	if err := s.AuthorizeContainerImageRegistration(t.Context(), a, in); err != nil || !reflect.DeepEqual(tx.reads, []string{"submitted", "existing"}) || !reflect.DeepEqual(tx.grants, tx.reads) {
		t.Fatal("guard omitted submitted or reused association", err, tx)
	}
	tx.reads, tx.grants = nil, nil
	in.ArtifactID = "existing"
	if err := s.AuthorizeContainerImageRegistration(t.Context(), a, in); err != nil || len(tx.reads) != 1 || len(tx.grants) != 1 {
		t.Fatal("guard repeated shared artifact check", err, tx)
	}
	in.ArtifactID = ""
	tx.denied = "existing"
	if err := s.AuthorizeContainerImageRegistration(t.Context(), a, in); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("omitted artifact bypassed existing association", err)
	}
	tx.denied = ""
	tx.artifacts["existing"] = releasedomain.Artifact{ID: "existing", TenantID: "foreign"}
	if err := s.AuthorizeContainerImageRegistration(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign existing artifact retained replay", err)
	}
	tx.identity.ArtifactID = ""
	if err := s.AuthorizeContainerImageRegistration(t.Context(), a, in); err != nil {
		t.Fatal("detached image replay required an artifact", err)
	}
	tx.identity.TenantID = "foreign"
	if err := s.AuthorizeContainerImageRegistration(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign image retained replay", err)
	}
}
