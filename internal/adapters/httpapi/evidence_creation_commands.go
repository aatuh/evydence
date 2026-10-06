package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

// EvidenceCreationCommands does not expose parsers, lifecycle mutations or
// unrelated queries to the generic evidence creation handler.
type EvidenceCreationCommands interface {
	AuthorizeEvidenceCreation(context.Context, identitydomain.Actor, evidenceapp.CreateEvidenceInput) error
	CreateEvidence(context.Context, identitydomain.Actor, evidenceapp.CreateEvidenceInput) (evidencedomain.EvidenceItem, error)
}

type localEvidenceCreationCommands interface {
	AuthorizeEvidenceCreation(context.Context, domain.Actor, evidenceapp.CreateEvidenceInput) error
	CreateEvidence(context.Context, domain.Actor, app.CreateEvidenceInput) (domain.EvidenceItem, error)
}

func decodeEvidenceCreation(body []byte) (evidenceapp.CreateEvidenceInput, error) {
	var r struct {
		ProductID        string                      `json:"product_id"`
		ProjectID        string                      `json:"project_id"`
		ReleaseID        string                      `json:"release_id"`
		BuildID          string                      `json:"build_id"`
		DeploymentID     string                      `json:"deployment_id"`
		Type             string                      `json:"type"`
		Subtype          string                      `json:"subtype"`
		Title            string                      `json:"title"`
		SourceSystem     string                      `json:"source_system"`
		SourceIdentity   map[string]any              `json:"source_identity"`
		CollectorID      string                      `json:"collector_id"`
		ObservedAt       time.Time                   `json:"observed_at"`
		PayloadRef       string                      `json:"payload_ref"`
		PayloadHash      string                      `json:"payload_hash"`
		PayloadMediaType string                      `json:"payload_media_type"`
		PayloadSize      int64                       `json:"payload_size"`
		SubjectRefs      []evidencedomain.SubjectRef `json:"subject_refs"`
		Metadata         map[string]any              `json:"metadata"`
		Tags             []string                    `json:"tags"`
		Limitations      []string                    `json:"limitations"`
	}
	if !utf8.Valid(body) || jsonbounds.Validate(body, jsonbounds.DefaultLimits()) != nil {
		return evidenceapp.CreateEvidenceInput{}, app.ErrValidation
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(&r); err != nil {
		return evidenceapp.CreateEvidenceInput{}, jsonValidationError(err)
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return evidenceapp.CreateEvidenceInput{}, app.ErrValidation
	}
	if err := validateExactNonNullableObjectFields(body, "product_id", "project_id", "release_id", "build_id", "deployment_id", "type", "subtype", "title", "source_system", "source_identity", "collector_id", "observed_at", "payload_ref", "payload_hash", "payload_media_type", "payload_size", "subject_refs", "metadata", "tags", "limitations"); err != nil {
		return evidenceapp.CreateEvidenceInput{}, err
	}
	for _, field := range []string{"subject_refs", "tags", "limitations"} {
		if err := validateNonNullableArrayItems(body, field); err != nil {
			return evidenceapp.CreateEvidenceInput{}, err
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return evidenceapp.CreateEvidenceInput{}, app.ErrValidation
	}
	var subjects []json.RawMessage
	if fields["subject_refs"] != nil && json.Unmarshal(fields["subject_refs"], &subjects) != nil {
		return evidenceapp.CreateEvidenceInput{}, app.ErrValidation
	}
	for _, subject := range subjects {
		if err := validateExactNonNullableObjectFields(subject, "type", "id", "digest"); err != nil {
			return evidenceapp.CreateEvidenceInput{}, err
		}
	}
	in := evidenceapp.CreateEvidenceInput{ProductID: r.ProductID, ProjectID: r.ProjectID, ReleaseID: r.ReleaseID, BuildID: r.BuildID, DeploymentID: r.DeploymentID, Type: r.Type, Subtype: r.Subtype, Title: r.Title, SourceSystem: r.SourceSystem, SourceIdentity: r.SourceIdentity, CollectorID: r.CollectorID, ObservedAt: r.ObservedAt, PayloadRef: r.PayloadRef, PayloadHash: r.PayloadHash, PayloadMediaType: r.PayloadMediaType, PayloadSize: r.PayloadSize, SubjectRefs: r.SubjectRefs, Metadata: r.Metadata, Tags: r.Tags, Limitations: r.Limitations}
	_, err := evidenceapp.NormalizeGenericEvidenceCreation(in)
	return in, mapEvidenceCreationCommandError(err)
}

func (s *Server) createEvidence(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in evidenceapp.CreateEvidenceInput
	if s.evidenceCreationCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeEvidenceCreation(body)
			if err != nil {
				return err
			}
			return mapEvidenceCreationCommandError(s.evidenceCreationCommands.AuthorizeEvidenceCreation(ctx, a, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.evidenceCreationCommands.CreateEvidence(ctx, a, in)
			return http.StatusCreated, domain.EvidenceFromContextModel(v), mapEvidenceCreationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		refs := make([]domain.SubjectRef, 0, len(in.SubjectRefs))
		for _, ref := range in.SubjectRefs {
			refs = append(refs, domain.SubjectRef{Type: ref.Type, ID: ref.ID, Digest: ref.Digest})
		}
		v, err := s.localEvidenceCreation.CreateEvidence(ctx, a, app.CreateEvidenceInput{ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID, BuildID: in.BuildID, DeploymentID: in.DeploymentID, Type: in.Type, Subtype: in.Subtype, Title: in.Title, SourceSystem: in.SourceSystem, SourceIdentity: in.SourceIdentity, CollectorID: in.CollectorID, ObservedAt: in.ObservedAt, PayloadRef: in.PayloadRef, PayloadHash: in.PayloadHash, PayloadMediaType: in.PayloadMediaType, PayloadSize: in.PayloadSize, SubjectRefs: refs, Metadata: in.Metadata, Tags: in.Tags, Limitations: in.Limitations})
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeEvidenceCreation(body)
		if err != nil {
			return nil, err
		}
		return body, s.localEvidenceCreation.AuthorizeEvidenceCreation(r.Context(), a, in)
	})
}

func mapEvidenceCreationCommandError(err error) error {
	switch {
	case errors.Is(err, evidenceapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, evidenceapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, evidenceapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
