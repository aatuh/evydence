package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

func TestMemoryEvidenceVerificationBoundsCombinedFactsAndRejectsInvalidProvenance(t *testing.T) {
	for name, mutate := range map[string]func(*memoryUnitOfWork, *domain.EvidenceItem){
		"oversized-item": func(_ *memoryUnitOfWork, e *domain.EvidenceItem) {
			e.Metadata = map[string]any{"large": strings.Repeat("x", verificationapp.MaxEvidenceVerificationBytes)}
		},
		"combined-item-and-origin": func(tx *memoryUnitOfWork, e *domain.EvidenceItem) {
			e.Metadata = map[string]any{"large": strings.Repeat("x", verificationapp.MaxEvidenceVerificationBytes/2)}
			tx.state.EvidenceLifecycle["origin"] = domain.EvidenceLifecycleEvent{ID: "origin", TenantID: e.TenantID, EvidenceID: e.ID, SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"large": strings.Repeat("x", verificationapp.MaxEvidenceVerificationBytes/2)}}}
		},
		"too-many-origins": func(tx *memoryUnitOfWork, e *domain.EvidenceItem) {
			for i := range verificationapp.MaxEvidenceVerificationOrigins + 1 {
				id := fmt.Sprintf("origin-%04d", i)
				tx.state.EvidenceLifecycle[id] = domain.EvidenceLifecycleEvent{ID: id, TenantID: e.TenantID, EvidenceID: e.ID, SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{}}}
			}
		},
		"invalid-parser-provenance": func(_ *memoryUnitOfWork, e *domain.EvidenceItem) {
			e.Type, e.Metadata = "parser_normalization", map[string]any{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx, _, _, _ := memoryLifecycleFixture(t)
			r := tx.Repositories().Verification.(verificationapp.EvidenceVerificationReader)
			e := tx.state.Evidence["tenant-evidence"]
			e.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
			mutate(tx, &e)
			tx.state.Evidence[e.ID] = e
			subject, err := r.ResolveEvidenceVerificationSubject(t.Context(), "tenant", e.ID)
			if err != nil {
				t.Fatal("ownership resolution inspected canonical facts", err)
			}
			if v, err := r.ReadEvidenceVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.EvidenceVerificationSnapshot{}) {
				t.Fatal("invalid/oversized canonical facts returned partial snapshot", err)
			}
		})
	}
}

func TestMemoryArtifactMetadataVerificationSelectsDigestLabelsAndPresenceOnly(t *testing.T) {
	tx, _, sig := memoryArtifactSignatureFixture(t)
	r, ok := tx.Repositories().Verification.(verificationapp.ArtifactSignatureVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks focused artifact metadata reader")
	}
	sig.Signature, sig.Algorithm, sig.PayloadRef = strings.Repeat("unselected-private-marker", 50000), strings.Repeat("unselected", 1000), "unselected-private-marker"
	tx.state.ArtifactSignatures[sig.ID] = sig
	subject, err := r.ResolveArtifactSignatureVerificationSubject(t.Context(), "tenant", sig.ID)
	if err != nil || subject.Resources != (application.ResourceReferences{ArtifactID: sig.ArtifactID}) {
		t.Fatal("artifact metadata resolution lost current owned parent", err)
	}
	v, err := r.ReadArtifactSignatureVerification(t.Context(), subject)
	if err != nil || !v.AlgorithmPresent || !v.SignaturePresent || v.SignatureDigest != sig.SubjectDigest || v.ArtifactDigest != sig.SubjectDigest {
		t.Fatal("metadata snapshot lost digest labels or presence flags", err)
	}
	raw, err := json.Marshal(v)
	if err != nil || strings.Contains(string(raw), "unselected-private-marker") {
		t.Fatal("metadata verification selected raw signature or payload", err)
	}
	sig.SubjectDigest = strings.Repeat("x", 1025)
	tx.state.ArtifactSignatures[sig.ID] = sig
	if v, err := r.ReadArtifactSignatureVerification(t.Context(), subject); !errors.Is(err, ErrConflict) || !reflect.DeepEqual(v, verificationapp.ArtifactSignatureVerificationSnapshot{}) {
		t.Fatal("oversized digest returned partial metadata", err)
	}
	artifact := tx.state.Artifacts[sig.ArtifactID]
	artifact.TenantID = "foreign"
	tx.state.Artifacts[sig.ArtifactID] = artifact
	if v, err := r.ResolveArtifactSignatureVerificationSubject(t.Context(), "tenant", sig.ID); !errors.Is(err, ErrNotFound) || !reflect.DeepEqual(v, verificationapp.SubjectReference{}) {
		t.Fatal("foreign artifact parent resolved", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := r.ReadArtifactSignatureVerification(ctx, subject); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, verificationapp.ArtifactSignatureVerificationSnapshot{}) {
		t.Fatal("cancelled metadata verification returned facts", err)
	}
}

func TestMemoryEvidenceVerificationSharesCurrentDetachedProvenanceAndLegacyOrigins(t *testing.T) {
	tx, _, _, _ := memoryLifecycleFixture(t)
	r, ok := tx.Repositories().Verification.(verificationapp.EvidenceVerificationReader)
	if !ok {
		t.Fatal("memory verification lacks focused canonical evidence reader")
	}
	e := tx.state.Evidence["tenant-evidence"]
	e.Metadata = map[string]any{"exact": json.Number("9007199254740993")}
	e.Canonicalization = evidencedomain.LegacyEvidenceCanonicalizationProfileVersion
	tx.state.Evidence[e.ID] = e
	tx.state.EvidenceLifecycle["origin"] = domain.EvidenceLifecycleEvent{ID: "origin", TenantID: "tenant", EvidenceID: e.ID, SchemaVersion: evidencedomain.EvidenceRelationshipLifecycleSchemaVersion, Details: map[string]any{evidencedomain.LegacyCanonicalOriginDetailKey: map[string]any{"product_id": e.ProductID}, "ignored": "unselected-private-marker"}}
	subject, err := r.ResolveEvidenceVerificationSubject(t.Context(), "tenant", e.ID)
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.ReadEvidenceVerification(t.Context(), subject)
	if err != nil || v.Subject != subject || len(v.Lifecycle) != 1 || v.Lifecycle[0].Details["ignored"] != nil {
		t.Fatal("canonical snapshot lost selected origin or selected unused details", err)
	}
	if n, ok := v.Item.Metadata["exact"].(json.Number); !ok || n.String() != "9007199254740993" {
		t.Fatal("canonical evidence read rounded recorded number")
	}
	v.Item.Metadata["exact"] = "caller"
	v.Lifecycle[0].Details[evidencedomain.LegacyCanonicalOriginDetailKey].(map[string]any)["product_id"] = "caller"
	if tx.state.Evidence[e.ID].Metadata["exact"] != json.Number("9007199254740993") || tx.state.EvidenceLifecycle["origin"].Details[evidencedomain.LegacyCanonicalOriginDetailKey].(map[string]any)["product_id"] != e.ProductID {
		t.Fatal("canonical snapshot aliases stored item or origin")
	}
	tx.state.Products[e.ProductID] = domain.Product{ID: e.ProductID, TenantID: "foreign"}
	if v, err := r.ReadEvidenceVerification(t.Context(), subject); err == nil || !reflect.DeepEqual(v, verificationapp.EvidenceVerificationSnapshot{}) {
		t.Fatal("reparented canonical evidence retained old snapshot", err)
	}
}
