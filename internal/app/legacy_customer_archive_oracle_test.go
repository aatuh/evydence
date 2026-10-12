package app

import (
	"github.com/aatuh/evydence/internal/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Historical characterization tests share the owned record-only renderer.
// No production type or function forwards through this package facade.
type CustomerPackageArchive = packageapp.CustomerPackageArchive

func customerPackageArchive(pkg domain.CustomerSecurityPackage) (CustomerPackageArchive, error) {
	v, err := packageapp.RenderCustomerPackageArchive(packagedomain.CustomerSecurityPackage(pkg))
	return v, fromPackageContextError(err)
}
