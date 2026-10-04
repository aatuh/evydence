package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type PublicTransparencyProofCommands interface {
	AuthorizeVerifyPublicTransparencyLogEntry(context.Context, identitydomain.Actor, string, e.PublicTransparencyProofInput) error
	VerifyPublicTransparencyLogEntry(context.Context, identitydomain.Actor, string, e.PublicTransparencyProofInput) (d.PublicTransparencyLogEntry, error)
}

func decodePublicTransparencyProof(body []byte, id string) (e.PublicTransparencyProofInput, error) {
	var v struct {
		LeafHash       string   `json:"leaf_hash"`
		RootHash       string   `json:"root_hash"`
		LeafIndex      int      `json:"leaf_index"`
		TreeSize       int      `json:"tree_size"`
		InclusionProof []string `json:"inclusion_proof"`
	}
	if err := decodeMembershipJSON(body, &v); err != nil {
		return e.PublicTransparencyProofInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "leaf_hash", "root_hash", "leaf_index", "tree_size", "inclusion_proof"); err != nil {
		return e.PublicTransparencyProofInput{}, err
	}
	if err := validateNonNullableArrayItems(body, "inclusion_proof"); err != nil {
		return e.PublicTransparencyProofInput{}, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		return e.PublicTransparencyProofInput{}, app.ErrValidation
	}
	for _, name := range []string{"root_hash", "leaf_index", "tree_size", "inclusion_proof"} {
		if fields[name] == nil {
			return e.PublicTransparencyProofInput{}, app.ErrValidation
		}
	}
	in, err := e.NormalizePublicTransparencyProofInput(id, e.PublicTransparencyProofInput{LeafHash: v.LeafHash, RootHash: v.RootHash, LeafIndex: v.LeafIndex, TreeSize: v.TreeSize, InclusionProof: v.InclusionProof})
	return in, mapAnomalyReportError(err)
}
func legacyPublicTransparencyProofInput(v e.PublicTransparencyProofInput) app.VerifyPublicTransparencyLogEntryInput {
	return app.VerifyPublicTransparencyLogEntryInput{LeafHash: v.LeafHash, RootHash: v.RootHash, LeafIndex: v.LeafIndex, TreeSize: v.TreeSize, InclusionProof: v.InclusionProof}
}
func (s *Server) verifyDurablePublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	var in e.PublicTransparencyProofInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodePublicTransparencyProof(body, r.PathValue("id"))
		if err != nil {
			return err
		}
		return mapAnomalyReportError(s.publicTransparencyProofs.AuthorizeVerifyPublicTransparencyLogEntry(ctx, a, r.PathValue("id"), in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.publicTransparencyProofs.VerifyPublicTransparencyLogEntry(ctx, a, r.PathValue("id"), in)
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := e.EncodePublicTransparencyVerification(v)
		return http.StatusOK, json.RawMessage(raw), err
	})
}
