package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type GraphSnapshotCommands interface {
	AuthorizeCreateGraphSnapshot(context.Context, identitydomain.Actor, packageapp.CreateGraphSnapshotInput) error
	CreateGraphSnapshot(context.Context, identitydomain.Actor, packageapp.CreateGraphSnapshotInput) (packagedomain.EvidenceGraphSnapshot, error)
}

func decodeGraphSnapshotRequest(body []byte) (packageapp.CreateGraphSnapshotInput, error) {
	var in struct {
		ProductID string `json:"product_id"`
		ReleaseID string `json:"release_id"`
	}
	if err := decodeMembershipJSON(body, &in); err != nil {
		return packageapp.CreateGraphSnapshotInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "product_id", "release_id"); err != nil {
		return packageapp.CreateGraphSnapshotInput{}, err
	}
	v, err := packageapp.NormalizeGraphSnapshotInput(packageapp.CreateGraphSnapshotInput{ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	return v, mapCustomerPackageAccessError(err)
}
func (s *Server) createDurableGraphSnapshot(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateGraphSnapshotInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeGraphSnapshotRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.graphSnapshotCommands.AuthorizeCreateGraphSnapshot(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.graphSnapshotCommands.CreateGraphSnapshot(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		raw, err := packageapp.EncodeGraphSnapshot(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
