package query

import (
	"context"
	"errors"

	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

var (
	ErrSigningKeyValidation = errors.New("invalid signing key query")
	ErrSigningKeyProjection = errors.New("invalid signing key projection")
)

type SigningKeyPageRequest struct {
	TenantID string
	Page     appquery.PageRequest
	After    *appquery.SortKey
}

// SigningKeyReader must enforce the tenant and page limit in SQL and omit
// encrypted private key material from its projection.
type SigningKeyReader interface {
	PageSigningKeys(context.Context, SigningKeyPageRequest) (appquery.Result[verificationdomain.SigningKey], error)
}

type SigningKeys struct{ reader SigningKeyReader }

func NewSigningKeys(reader SigningKeyReader) (*SigningKeys, error) {
	if reader == nil {
		return nil, ErrSigningKeyValidation
	}
	return &SigningKeys{reader: reader}, nil
}

func (s *SigningKeys) ListPage(ctx context.Context, actor identitydomain.Actor, page appquery.PageRequest, after *appquery.SortKey) (appquery.Result[verificationdomain.SigningKey], error) {
	var empty appquery.Result[verificationdomain.SigningKey]
	if s == nil || ctx == nil {
		return empty, ErrSigningKeyValidation
	}
	if err := application.AuthorizeTenantWideScope(ctx, actor, "verify:read"); err != nil {
		return empty, err
	}
	if err := appquery.Validate(page, after); err != nil {
		return empty, ErrSigningKeyValidation
	}
	result, err := s.reader.PageSigningKeys(ctx, SigningKeyPageRequest{TenantID: actor.TenantID, Page: page, After: after})
	if err != nil {
		return empty, err
	}
	if len(result.Items) > page.PageSize {
		return empty, ErrSigningKeyProjection
	}
	for _, key := range result.Items {
		if key.ID == "" || key.TenantID != actor.TenantID || key.KID == "" ||
			key.Provider == "" || key.Algorithm == "" || key.PublicKey == "" ||
			key.Version < 1 || key.Status.IsZero() || key.ValidFrom.IsZero() || key.CreatedAt.IsZero() {
			return empty, ErrSigningKeyProjection
		}
	}
	if result.Next != nil {
		if len(result.Items) == 0 || *result.Next != appquery.RecordSortKey(result.Items[len(result.Items)-1].ID, result.Items[len(result.Items)-1].CreatedAt, page.Sort) {
			return empty, ErrSigningKeyProjection
		}
	}
	return result, nil
}
