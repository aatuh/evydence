package app

import (
	"context"

	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	"github.com/aatuh/evydence/internal/platform/telemetry"
)

// Measurements preserve command/parser results, transaction ownership and context.
func (p *ExportCommands) ExportEvidenceBundle(ctx context.Context, actor identitydomain.Actor, releaseID string, evidenceIDs []string) (packagedomain.EvidenceBundle, error) {
	return telemetry.Measure(ctx, telemetry.OperationPackageGeneration, func(callCtx context.Context) (packagedomain.EvidenceBundle, error) {
		return p.exportEvidenceBundle(callCtx, actor, releaseID, evidenceIDs)
	})
}

func measurePackageSigning(ctx context.Context, signer PackageSigner, request PackageSigningRequest) (PackageSignature, error) {
	return telemetry.Measure(ctx, telemetry.OperationPackageSign, func(callCtx context.Context) (PackageSignature, error) {
		return signer.SignPackage(callCtx, request)
	})
}

func (p *CustomerPackageCommands) CreateCustomerSecurityPackage(ctx context.Context, a identitydomain.Actor, in CreateCustomerPackageInput) (packagedomain.CustomerSecurityPackage, error) {
	return telemetry.Measure(ctx, telemetry.OperationPackageGeneration, func(callCtx context.Context) (packagedomain.CustomerSecurityPackage, error) {
		return p.createCustomerSecurityPackage(callCtx, a, in)
	})
}

func (p *ReleaseBundleCommands) CreateReleaseBundle(ctx context.Context, actor identitydomain.Actor, releaseID string) (packagedomain.ReleaseBundle, error) {
	return telemetry.Measure(ctx, telemetry.OperationPackageGeneration, func(callCtx context.Context) (packagedomain.ReleaseBundle, error) {
		return p.createReleaseBundle(callCtx, actor, releaseID)
	})
}
