package httpapi

import (
	"bytes"
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
)

func decodeReleaseTransition(r *http.Request, body []byte) (string, int64, error) {
	if len(bytes.TrimSpace(body)) != 0 {
		var empty struct{}
		if err := decodeMembershipJSON(body, &empty); err != nil {
			return "", 0, err
		}
		if err := validateExactNonNullableObjectFields(body); err != nil {
			return "", 0, err
		}
	}
	rev, err := expectedRevisionFromIfMatch(r)
	if err != nil {
		return "", 0, err
	}
	id, err := releaseapp.NormalizeTransitionID(r.PathValue("id"))
	return id, rev, mapReleaseStateCommandError(err)
}
func decodeCandidateTransition(r *http.Request, state string, body []byte) (releaseapp.CandidateTransitionInput, error) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return releaseapp.CandidateTransitionInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "reason"); err != nil {
		return releaseapp.CandidateTransitionInput{}, err
	}
	rev, err := expectedRevisionFromIfMatch(r)
	if err != nil {
		return releaseapp.CandidateTransitionInput{}, err
	}
	v, err := releaseapp.NormalizeCandidateTransitionInput(releaseapp.CandidateTransitionInput{ID: r.PathValue("id"), State: state, Reason: req.Reason, ExpectedRevision: rev})
	return v, mapReleaseStateCommandError(err)
}
func (s *Server) freezeRelease(w http.ResponseWriter, r *http.Request) {
	s.transitionRelease(w, r, false)
}
func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	s.transitionRelease(w, r, true)
}
func (s *Server) transitionRelease(w http.ResponseWriter, r *http.Request, approve bool) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var id string
	var rev int64
	if s.releaseStateCommands != nil {
		s.createDurableWithFingerprint(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			id, rev, err = decodeReleaseTransition(r, body)
			if err != nil {
				return err
			}
			return mapReleaseStateCommandError(s.releaseStateCommands.AuthorizeReleaseTransition(ctx, a, id))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			if approve {
				v, err := s.releaseStateCommands.ApproveRelease(ctx, a, id, rev)
				return 200, releaseFromCommand(v), mapReleaseStateCommandError(err)
			}
			v, err := s.releaseStateCommands.FreezeRelease(ctx, a, id, rev)
			return 200, releaseFromCommand(v), mapReleaseStateCommandError(err)
		}, nil, func(_ domain.Actor, body []byte) ([]byte, error) { return conditionalActionFingerprint(r, body) })
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		if approve {
			v, err := s.releaseCatalog.ApproveRelease(ctx, a, id, rev)
			return 200, v, err
		}
		v, err := s.releaseCatalog.FreezeRelease(ctx, a, id, rev)
		return 200, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		id, rev, err = decodeReleaseTransition(r, body)
		if err != nil {
			return nil, err
		}
		if err := s.releaseCatalog.AuthorizeReleaseTransition(r.Context(), a, id); err != nil {
			return nil, err
		}
		return conditionalActionFingerprint(r, body)
	})
}
func (s *Server) transitionReleaseCandidate(w http.ResponseWriter, r *http.Request, state string) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	var in releaseapp.CandidateTransitionInput
	if s.candidateStateCommands != nil {
		s.createDurableWithFingerprint(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
			var err error
			in, err = decodeCandidateTransition(r, state, body)
			if err != nil {
				return err
			}
			return mapReleaseStateCommandError(s.candidateStateCommands.AuthorizeCandidateTransition(ctx, a, in.ID))
		}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
			v, err := s.candidateStateCommands.UpdateReleaseCandidateState(ctx, a, in.ID, in.State, in.Reason, in.ExpectedRevision)
			return 200, releaseCandidateFromQuery(v), mapReleaseStateCommandError(err)
		}, nil, func(_ domain.Actor, body []byte) ([]byte, error) { return conditionalActionFingerprint(r, body) })
		return
	}
	s.createWithActorFingerprint(w, r, app.SmallJSONRequestLimit, func(s *Server, ctx requestContext, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.releaseCatalog.UpdateReleaseCandidateState(ctx, a, in.ID, in.State, in.Reason, in.ExpectedRevision)
		return 200, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		var err error
		in, err = decodeCandidateTransition(r, state, body)
		if err != nil {
			return nil, err
		}
		if err := s.releaseCatalog.AuthorizeCandidateTransition(r.Context(), a, in.ID); err != nil {
			return nil, err
		}
		return conditionalActionFingerprint(r, body)
	})
}
