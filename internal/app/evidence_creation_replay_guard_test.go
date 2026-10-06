package app

import (
	"errors"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestLocalEvidenceCreationGuardChecksCurrentParentsWithoutEffects(t *testing.T) {
	l := NewLedger(Config{Now: fixedNow, APIKeyPepper: "test-pepper"})
	_, _, _, a := bootstrapEnterpriseTestTenant(t, l)
	p, err := l.CreateProduct(t.Context(), a, "Parent", "parent")
	if err != nil {
		t.Fatal(err)
	}
	r, err := l.CreateRelease(t.Context(), a, p.ID, "1")
	if err != nil {
		t.Fatal(err)
	}
	l.artifacts["artifact"] = domain.Artifact{ID: "artifact", TenantID: a.TenantID, Digest: sampleDigest("artifact")}
	in := evidenceapp.CreateEvidenceInput{ReleaseID: r.ID, Type: "manual", Title: "Evidence", PayloadHash: sampleDigest("evidence"), SubjectRefs: []evidencedomain.SubjectRef{{Type: "artifact", ID: "artifact"}, {Type: "release", ID: r.ID}, {Type: "opaque", ID: "label"}}}
	counts := func() [2]int { return [2]int{len(l.evidence), len(l.chain[a.TenantID])} }
	baseline := counts()
	l.now = func() time.Time { panic("evidence guard used clock") }
	if err := l.AuthorizeEvidenceCreation(t.Context(), a, in); err != nil {
		t.Fatal(err)
	}
	human := domain.Actor{TenantID: a.TenantID, UserID: "human", Scopes: []string{ScopeEvidenceWrite}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "tenant", ResourceID: a.TenantID, Scopes: []string{ScopeEvidenceWrite}}}}
	if err := l.AuthorizeEvidenceCreation(t.Context(), human, in); err != nil {
		t.Fatal(err)
	}
	human.ResourceGrants = nil
	if err := l.AuthorizeEvidenceCreation(t.Context(), human, in); !errors.Is(err, ErrForbidden) {
		t.Fatal("removed grant retained replay", err)
	}
	changed := p
	changed.TenantID = "other"
	l.products[p.ID] = changed
	if err := l.AuthorizeEvidenceCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign inferred product retained replay", err)
	}
	l.products[p.ID] = p
	v := l.artifacts["artifact"]
	v.TenantID = "other"
	l.artifacts["artifact"] = v
	if err := l.AuthorizeEvidenceCreation(t.Context(), a, in); !errors.Is(err, ErrNotFound) {
		t.Fatal("foreign artifact retained replay", err)
	}
	if counts() != baseline {
		t.Fatal("evidence guard wrote effects", counts(), baseline)
	}
}
