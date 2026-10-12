package app

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
)

// Unchanged aggregate behavior is retained only as a characterization oracle.
type CreateCustomerPackageInput struct {
	ProductID          string
	ReleaseID          string
	RedactionProfileID string
	Title              string
	ExpiresAt          time.Time
}

func (l *Ledger) CreateCustomerSecurityPackage(ctx context.Context, actor domain.Actor, in CreateCustomerPackageInput) (domain.CustomerSecurityPackage, error) {
	value, err := l.legacyPackageCommands().CreateCustomerSecurityPackage(ctx, actor, packageapp.CreateCustomerPackageInput{
		ProductID: in.ProductID, ReleaseID: in.ReleaseID, RedactionProfileID: in.RedactionProfileID,
		Title: in.Title, ExpiresAt: in.ExpiresAt,
	})
	return customerSecurityPackageFromContext(value), fromPackageContextError(err)
}
