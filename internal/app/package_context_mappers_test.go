package app

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

func TestPackageContextMappersPreserveFieldsAndDetachRedactionLists(t *testing.T) {
	v := domain.RedactionProfile{ID: "profile", TenantID: "tenant", Name: "Public", Description: "Explicit fields", AllowedTypes: []string{"document"}, ExcludedFields: []string{"private"}, SchemaVersion: "redaction-profile.v1.0.0", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	got := redactionProfileToPackageContext(v)
	if !reflect.DeepEqual(domain.RedactionProfile(got), v) {
		t.Fatal("redaction translation changed fields")
	}
	got.AllowedTypes[0], got.ExcludedFields[0] = "changed", "changed"
	if v.AllowedTypes[0] != "document" || v.ExcludedFields[0] != "private" {
		t.Fatal("redaction translation aliases caller lists")
	}
	zero := redactionProfileToPackageContext(domain.RedactionProfile{})
	if zero.AllowedTypes != nil || zero.ExcludedFields != nil {
		t.Fatal("redaction translation changed nil lists")
	}
}

func TestPackageContextErrorTranslationPreservesPublicClassesAndCancellation(t *testing.T) {
	other := errors.New("unclassified")
	cancelled := fmt.Errorf("request stopped: %w", context.Canceled)
	for _, tc := range []struct{ in, want error }{
		{nil, nil}, {fmt.Errorf("wrapped: %w", packageapp.ErrValidation), ErrValidation},
		{fmt.Errorf("wrapped: %w", packageapp.ErrForbidden), ErrForbidden},
		{fmt.Errorf("wrapped: %w", packageapp.ErrNotFound), ErrNotFound},
		{fmt.Errorf("wrapped: %w", packageapp.ErrConflict), ErrConflict},
		{other, other}, {cancelled, cancelled},
	} {
		if got := fromPackageContextError(tc.in); got != tc.want {
			t.Fatal("package error translation changed", got, tc.want)
		}
	}
}

func TestSignatureSnapshotCloneDetachesMapMembershipAndValues(t *testing.T) {
	v := domain.Signature{ID: "signature", TenantID: "tenant", SubjectType: "evidence_bundle", SubjectID: "bundle", KeyID: "public-key", Algorithm: "Ed25519", Value: "public-signature", CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	input := map[string]domain.Signature{v.ID: v}
	got := cloneSignatureMap(input)
	if !reflect.DeepEqual(input, got) {
		t.Fatal("signature snapshot changed fields")
	}
	changed := got[v.ID]
	changed.SubjectID = "changed"
	got[v.ID] = changed
	delete(got, v.ID)
	if input[v.ID] != v {
		t.Fatal("signature snapshot aliases source")
	}
}
