package domain

import evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"

func ContractDiffFromContext(v evidencedomain.ContractDiff) ContractDiff {
	return ContractDiff{ID: v.ID, TenantID: v.TenantID, BaseContractID: v.BaseContractID, TargetContractID: v.TargetContractID, ProductID: v.ProductID, ReleaseID: v.ReleaseID, Result: v.Result, BreakingChanges: append([]string(nil), v.BreakingChanges...), NonBreakingChanges: append([]string(nil), v.NonBreakingChanges...), SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}
