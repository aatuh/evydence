package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type artifactSignatureQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *artifactSignatureQueryFake) GetArtifactSignature(_ context.Context, actor identitydomain.Actor, id string) (verificationdomain.ArtifactSignature, error) {
	f.calls++
	f.actor = actor
	f.id = id
	if f.err != nil {
		return verificationdomain.ArtifactSignature{}, f.err
	}
	return verificationdomain.ArtifactSignature{
		ID: id, TenantID: actor.TenantID, ArtifactID: "art_database", SubjectDigest: "sha256:subject",
		Algorithm: "ed25519", Signature: "signed", PayloadRef: "private/object/ref",
		VerificationStatus: "recorded", SchemaVersion: verificationdomain.ArtifactSignatureSchemaVersion,
		CreatedAt: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}, nil
}

func TestArtifactSignatureHandlerUsesFocusedQueryAndSafeErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &artifactSignatureQueryFake{}
	server.artifactSignatureQuery = query
	response := getRaw(t, server, secret, "/v1/artifact-signatures/sig_database", http.StatusOK)
	var result struct {
		Data struct {
			ID         string `json:"id"`
			PayloadRef string `json:"payload_ref"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Data.ID != "sig_database" || result.Data.PayloadRef != "private/object/ref" || query.id != "sig_database" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("signature response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	getRawNoAuth(t, server, "/v1/artifact-signatures/sig_database", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated request reached query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{verificationquery.ErrSignatureValidation, http.StatusBadRequest},
		{verificationquery.ErrSignatureNotFound, http.StatusNotFound},
		{verificationquery.ErrSignatureProjection, http.StatusConflict},
		{application.ErrForbidden, http.StatusForbidden},
		{errors.New("private-signature-database-detail"), http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/artifact-signatures/sig_database", test.status)
		if strings.Contains(response.Body.String(), "private-signature-database-detail") {
			t.Fatalf("internal detail leaked: %s", response.Body.String())
		}
	}
}
