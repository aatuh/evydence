package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	"github.com/aatuh/evydence/internal/platform/jsonbounds"
)

// Guard methods use only current ownership and grants, including on a completed
// replay. They do not rehash legacy origins or read lifecycle/metadata payloads.
type EvidenceRelationshipCommands interface {
	AuthorizeSupersedeEvidence(context.Context, identitydomain.Actor, string, string, string) error
	AuthorizeLinkEvidence(context.Context, identitydomain.Actor, string, string, string) error
	AuthorizeLifecycleEvent(context.Context, identitydomain.Actor, string, evidenceapp.RecordLifecycleInput) error
	SupersedeEvidence(context.Context, identitydomain.Actor, string, string, string) (evidencedomain.EvidenceItem, error)
	LinkEvidence(context.Context, identitydomain.Actor, string, string, string) (evidencedomain.EvidenceItem, error)
	RecordLifecycleEvent(context.Context, identitydomain.Actor, string, evidenceapp.RecordLifecycleInput) (evidencedomain.EvidenceLifecycleEvent, error)
}
type localEvidenceRelationshipCommands interface {
	AuthorizeSupersedeEvidence(context.Context, domain.Actor, string, string, string) error
	AuthorizeLinkEvidence(context.Context, domain.Actor, string, string, string) error
	AuthorizeLifecycleEvent(context.Context, domain.Actor, string, evidenceapp.RecordLifecycleInput) error
	SupersedeEvidence(context.Context, domain.Actor, string, string, string) (domain.EvidenceItem, error)
	LinkEvidence(context.Context, domain.Actor, string, string, string) (domain.EvidenceItem, error)
	RecordEvidenceLifecycleEvent(context.Context, domain.Actor, string, app.RecordEvidenceLifecycleInput) (domain.EvidenceLifecycleEvent, error)
}

func decodeEvidenceRelationship(body []byte, target any, fields ...string) error {
	if !utf8.Valid(body) || jsonbounds.Validate(body, jsonbounds.DefaultLimits()) != nil {
		return app.ErrValidation
	}
	if err := validateExactNonNullableObjectFields(body, fields...); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(target); err != nil {
		return jsonValidationError(err)
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return app.ErrValidation
	}
	return nil
}

func (s *Server) supersedeEvidence(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in struct {
		Replacement string `json:"replacement_evidence_id"`
		Reason      string `json:"reason"`
	}
	id := r.PathValue("id")
	decode := func(body []byte) error {
		if err := decodeEvidenceRelationship(body, &in, "replacement_evidence_id", "reason"); err != nil {
			return err
		}
		var err error
		id, in.Replacement, in.Reason, err = evidenceapp.NormalizeEvidenceSupersession(id, in.Replacement, in.Reason)
		return mapEvidenceCreationCommandError(err)
	}
	if s.evidenceRelationshipCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			if err := decode(body); err != nil {
				return err
			}
			return mapEvidenceCreationCommandError(s.evidenceRelationshipCommands.AuthorizeSupersedeEvidence(ctx, a, id, in.Replacement, in.Reason))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.evidenceRelationshipCommands.SupersedeEvidence(ctx, a, id, in.Replacement, in.Reason)
			return http.StatusCreated, domain.EvidenceFromContextModel(v), mapEvidenceCreationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.localEvidenceRelationships.SupersedeEvidence(ctx, a, id, in.Replacement, in.Reason)
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if err := decode(body); err != nil {
			return nil, err
		}
		return body, s.localEvidenceRelationships.AuthorizeSupersedeEvidence(r.Context(), a, id, in.Replacement, in.Reason)
	})
}

func (s *Server) linkEvidence(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in struct {
		Kind   string `json:"target_type"`
		Target string `json:"target_id"`
	}
	id := r.PathValue("id")
	decode := func(body []byte) error {
		if err := decodeEvidenceRelationship(body, &in, "target_type", "target_id"); err != nil {
			return err
		}
		var err error
		id, in.Kind, in.Target, err = evidenceapp.NormalizeEvidenceLink(id, in.Kind, in.Target)
		return mapEvidenceCreationCommandError(err)
	}
	if s.evidenceRelationshipCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			if err := decode(body); err != nil {
				return err
			}
			return mapEvidenceCreationCommandError(s.evidenceRelationshipCommands.AuthorizeLinkEvidence(ctx, a, id, in.Kind, in.Target))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.evidenceRelationshipCommands.LinkEvidence(ctx, a, id, in.Kind, in.Target)
			return http.StatusCreated, domain.EvidenceFromContextModel(v), mapEvidenceCreationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.localEvidenceRelationships.LinkEvidence(ctx, a, id, in.Kind, in.Target)
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if err := decode(body); err != nil {
			return nil, err
		}
		return body, s.localEvidenceRelationships.AuthorizeLinkEvidence(r.Context(), a, id, in.Kind, in.Target)
	})
}

func (s *Server) recordEvidenceLifecycleEvent(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var req struct {
		Action      string         `json:"action"`
		Reason      string         `json:"reason"`
		Details     map[string]any `json:"details"`
		Replacement string         `json:"replacement_id"`
	}
	var in evidenceapp.RecordLifecycleInput
	id := r.PathValue("id")
	decode := func(body []byte) error {
		if err := decodeEvidenceRelationship(body, &req, "action", "reason", "details", "replacement_id"); err != nil {
			return err
		}
		var err error
		id, in, err = evidenceapp.NormalizeEvidenceLifecycle(id, evidenceapp.RecordLifecycleInput{Action: req.Action, Reason: req.Reason, Details: req.Details, ReplacementID: req.Replacement})
		return mapEvidenceCreationCommandError(err)
	}
	if s.evidenceRelationshipCommands != nil {
		s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			if err := decode(body); err != nil {
				return err
			}
			return mapEvidenceCreationCommandError(s.evidenceRelationshipCommands.AuthorizeLifecycleEvent(ctx, a, id, in))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.evidenceRelationshipCommands.RecordLifecycleEvent(ctx, a, id, in)
			return http.StatusCreated, evidenceRelationshipLifecycleDTO(v), mapEvidenceCreationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.localEvidenceRelationships.RecordEvidenceLifecycleEvent(ctx, a, id, app.RecordEvidenceLifecycleInput{Action: in.Action, Reason: in.Reason, Details: in.Details, ReplacementID: in.ReplacementID})
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if err := decode(body); err != nil {
			return nil, err
		}
		return body, s.localEvidenceRelationships.AuthorizeLifecycleEvent(r.Context(), a, id, in)
	})
}

func evidenceRelationshipLifecycleDTO(e evidencedomain.EvidenceLifecycleEvent) domain.EvidenceLifecycleEvent {
	return domain.EvidenceLifecycleEvent{ID: e.ID, TenantID: e.TenantID, EvidenceID: e.EvidenceID, Action: e.Action.String(), Reason: e.Reason, Details: e.Details, ReplacementID: e.ReplacementID, ActorID: e.ActorID, SchemaVersion: e.SchemaVersion, CreatedAt: e.CreatedAt}
}
