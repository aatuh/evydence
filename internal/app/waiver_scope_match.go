package app

import "github.com/aatuh/evydence/internal/domain"

// The existing VEX readiness path and historical package tests share this pure
// selector. It carries no Ledger lookup, authorization or mutable state.
func waiverBelongsToPackage(waiver domain.Waiver, productID, releaseID string) bool {
	switch waiver.ScopeType {
	case "release":
		return releaseID != "" && waiver.ScopeID == releaseID
	case "product":
		return waiver.ScopeID == productID
	default:
		return false
	}
}
