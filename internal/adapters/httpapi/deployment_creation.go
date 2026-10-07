package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	operationsapp "github.com/aatuh/evydence/internal/operations/app"
)

func decodeEnvironmentCreation(body []byte) (operationsapp.CreateEnvironmentInput, error) {
	var req struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
		Kind      string `json:"kind"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return operationsapp.CreateEnvironmentInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "product_id", "name", "kind"); err != nil {
		return operationsapp.CreateEnvironmentInput{}, err
	}
	in := operationsapp.CreateEnvironmentInput{ProductID: req.ProductID, Name: req.Name, Kind: req.Kind}
	_, err := operationsapp.NormalizeEnvironmentCreationInput(in)
	return in, mapDeploymentCommandError(err)
}
func decodeDeploymentRecording(body []byte) (operationsapp.RecordDeploymentInput, error) {
	var req struct {
		EnvironmentID string     `json:"environment_id"`
		ReleaseID     string     `json:"release_id"`
		ArtifactIDs   []string   `json:"artifact_ids"`
		Status        string     `json:"status"`
		StartedAt     time.Time  `json:"started_at"`
		FinishedAt    *time.Time `json:"finished_at"`
		RollbackOf    string     `json:"rollback_of"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return operationsapp.RecordDeploymentInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "environment_id", "release_id", "artifact_ids", "status", "started_at", "finished_at", "rollback_of"); err != nil {
		return operationsapp.RecordDeploymentInput{}, err
	}
	if err := validateNonNullableArrayItems(body, "artifact_ids"); err != nil {
		return operationsapp.RecordDeploymentInput{}, err
	}
	in := operationsapp.RecordDeploymentInput{EnvironmentID: req.EnvironmentID, ReleaseID: req.ReleaseID, ArtifactIDs: req.ArtifactIDs, Status: req.Status, StartedAt: req.StartedAt, FinishedAt: req.FinishedAt, RollbackOf: req.RollbackOf}
	_, err := operationsapp.NormalizeDeploymentRecordingInput(in)
	return in, mapDeploymentCommandError(err)
}
func (s *Server) createDeploymentEnvironment(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in operationsapp.CreateEnvironmentInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeEnvironmentCreation(body)
		if err != nil {
			return err
		}
		return mapDeploymentCommandError(s.deploymentEnvironmentCommands.AuthorizeEnvironmentCreation(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.deploymentEnvironmentCommands.CreateDeploymentEnvironment(ctx, a, in)
		return 201, deploymentEnvironmentFromQuery(v), mapDeploymentCommandError(err)
	})
}
func (s *Server) recordDeployment(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in operationsapp.RecordDeploymentInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeDeploymentRecording(body)
		if err != nil {
			return err
		}
		return mapDeploymentCommandError(s.deploymentCommands.AuthorizeDeploymentRecording(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.deploymentCommands.RecordDeployment(ctx, a, in)
		return 201, deploymentEventFromQuery(v), mapDeploymentCommandError(err)
	})
}
