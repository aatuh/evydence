package app

import (
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
)

func PublicTransparencyLogLegacyRecord(v d.PublicTransparencyLog) domain.PublicTransparencyLog {
	return domain.PublicTransparencyLog{ID: v.ID, TenantID: v.TenantID, Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func PublicTransparencyPublicationLegacyRecord(v d.PublicTransparencyLogEntry) domain.PublicTransparencyLogEntry {
	return domain.PublicTransparencyLogEntry{ID: v.ID, TenantID: v.TenantID, LogID: v.LogID, CheckpointID: v.CheckpointID, MerkleBatchID: v.MerkleBatchID, ExternalID: v.ExternalID, EntryHash: v.EntryHash, State: v.State, SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt}
}

func PublicTransparencyVerificationLegacyRecord(v d.PublicTransparencyLogEntry) domain.PublicTransparencyLogEntry {
	v = e.ClonePublicTransparencyEntry(v)
	out := PublicTransparencyPublicationLegacyRecord(v)
	out.InclusionRootHash, out.InclusionProofHash, out.InclusionVerifiedAt = v.InclusionRootHash, v.InclusionProofHash, v.InclusionVerifiedAt
	out.VerificationLimitations = v.VerificationLimitations
	for _, c := range v.VerificationChecks {
		out.VerificationChecks = append(out.VerificationChecks, domain.VerifyCheck{Name: c.Name, Result: c.Result, Detail: c.Detail})
	}
	return out
}
