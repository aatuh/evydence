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
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	operationsquery "github.com/aatuh/evydence/internal/operations/query"
)

type deploymentPointQueryFake struct {
	actor identitydomain.Actor
	id    string
	calls int
	err   error
}

func (f *deploymentPointQueryFake) GetDeployment(_ context.Context, actor identitydomain.Actor, id string) (operationsdomain.DeploymentEvent, error) {
	f.actor, f.id = actor, id
	f.calls++
	if f.err != nil {
		return operationsdomain.DeploymentEvent{}, f.err
	}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	return operationsdomain.DeploymentEvent{
		ID: id, TenantID: actor.TenantID, EnvironmentID: "env_database", ReleaseID: "rel_database",
		ArtifactIDs: []string{"art_1"}, Status: "succeeded", StartedAt: now,
		FinishedAt: &now, EvidenceID: "ev_1", SchemaVersion: "v1", CreatedAt: now,
	}, nil
}

func TestDeploymentPointHandlerUsesFocusedQueryAndMapsErrors(t *testing.T) {
	server, secret := testServer(t)
	query := &deploymentPointQueryFake{}
	server.deploymentPointQuery = query
	response := getRaw(t, server, secret, "/v1/deployments/dep_database_only", http.StatusOK)
	var deployment struct {
		Data struct {
			ID          string   `json:"id"`
			Environment string   `json:"environment_id"`
			Artifacts   []string `json:"artifact_ids"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &deployment); err != nil || deployment.Data.ID != "dep_database_only" || deployment.Data.Environment != "env_database" || len(deployment.Data.Artifacts) != 1 || query.id != "dep_database_only" || query.actor.TenantID == "" || query.calls != 1 {
		t.Fatalf("focused deployment response=%s query=%#v error=%v", response.Body.String(), query, err)
	}
	getRawNoAuth(t, server, "/v1/deployments/dep_database_only", http.StatusUnauthorized)
	if query.calls != 1 {
		t.Fatalf("unauthenticated request reached deployment query %d times", query.calls)
	}
	for _, test := range []struct {
		err    error
		status int
	}{
		{err: operationsquery.ErrNotFound, status: http.StatusNotFound},
		{err: operationsquery.ErrValidation, status: http.StatusBadRequest},
		{err: application.ErrUnauthorized, status: http.StatusUnauthorized},
		{err: application.ErrForbidden, status: http.StatusForbidden},
		{err: errors.New("postgres-private-detail"), status: http.StatusInternalServerError},
	} {
		query.err = test.err
		response := getRaw(t, server, secret, "/v1/deployments/dep_database_only", test.status)
		if strings.Contains(response.Body.String(), "postgres") {
			t.Fatalf("internal detail in deployment error: %s", response.Body.String())
		}
	}
}
