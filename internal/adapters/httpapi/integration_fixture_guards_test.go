package httpapi

import (
	"context"

	"github.com/aatuh/evydence/internal/domain"
	integrationapp "github.com/aatuh/evydence/internal/integration/app"
)

func (f integrationFixtureCommands) AuthorizeCreateCollector(ctx context.Context, a domain.Actor, in integrationapp.CreateCollectorInput) error {
	guard, err := f.nativeCollectorCreation(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateCollector(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizeRecordCollectorRelease(ctx context.Context, a domain.Actor, in integrationapp.RecordCollectorReleaseInput) error {
	guard, err := f.nativeCollectorRelease(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeRecordCollectorRelease(ctx, a, in)
}
func (f integrationFixtureCommands) AuthorizeCreateCommercialCollectorDefinition(ctx context.Context, a domain.Actor, in integrationapp.CreateCommercialCollectorInput) error {
	guard, err := f.nativeCommercialCollector(true)
	if err != nil {
		return err
	}
	return guard.AuthorizeCreateCommercialCollectorDefinition(ctx, a, in)
}
