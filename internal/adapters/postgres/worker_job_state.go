package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	packagequery "github.com/aatuh/evydence/internal/package/query"
)

// LoadWorkerJobState is a transitional adapter for the worker's legacy job
// functions. It loads only the claimed subject, never a tenant-wide snapshot.
// Parser mutations must be persisted through ApplyClaimedReleaseLedgerMutation.
func (s *Store) LoadWorkerJobState(ctx context.Context, job ClaimedJob) (app.PersistedState, bool, error) {
	emptySubjectAllowed := job.Kind == "verify_subject" && job.SubjectType == "audit_chain"
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(job.TenantID) == "" ||
		(strings.TrimSpace(job.SubjectID) == "" && !emptySubjectAllowed) ||
		strings.TrimSpace(job.TenantID) != job.TenantID ||
		strings.TrimSpace(job.SubjectID) != job.SubjectID {
		return app.PersistedState{}, false, app.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return app.PersistedState{}, false, err
	}
	state := app.PersistedState{}
	var err error
	switch job.Kind {
	case "parse_sbom":
		if job.SubjectType != "" && job.SubjectType != "sbom" {
			return state, false, app.ErrValidation
		}
		var point evidencequery.SBOMPoint
		point, err = s.GetSBOMPoint(ctx, job.TenantID, job.SubjectID)
		if err == nil {
			state.SBOMs = map[string]domain.SBOM{job.SubjectID: parserSBOM(point.SBOM)}
		}
	case "parse_vulnerability_scan":
		if job.SubjectType != "" && job.SubjectType != "vulnerability_scan" {
			return state, false, app.ErrValidation
		}
		var point evidencequery.VulnerabilityScanPoint
		point, err = s.GetVulnerabilityScanPoint(ctx, job.TenantID, job.SubjectID)
		if err == nil {
			state.Scans = map[string]domain.VulnerabilityScan{job.SubjectID: parserVulnerabilityScan(point.Scan)}
		}
	case "parse_openapi_contract":
		if job.SubjectType != "" && job.SubjectType != "openapi_contract" {
			return state, false, app.ErrValidation
		}
		var point evidencequery.OpenAPIContractPoint
		point, err = s.GetOpenAPIContractPoint(ctx, job.TenantID, job.SubjectID)
		if err == nil {
			state.Contracts = map[string]domain.OpenAPIContract{job.SubjectID: parserOpenAPIContract(point.Contract)}
		}
	case "verify_attestation":
		if job.SubjectType != "" && job.SubjectType != "build_attestation" {
			return state, false, app.ErrValidation
		}
		var attestation domain.BuildAttestation
		attestation, err = s.loadWorkerAttestation(ctx, job.TenantID, job.SubjectID)
		if err == nil {
			state.BuildAttestations = map[string]domain.BuildAttestation{job.SubjectID: attestation}
		}
	case "sign_bundle":
		if job.SubjectType != "" && job.SubjectType != "release_bundle" {
			return state, false, app.ErrValidation
		}
		var point packagequery.ReleaseBundlePoint
		point, err = s.GetReleaseBundlePoint(ctx, job.TenantID, job.SubjectID)
		if err == nil {
			bundle := point.Bundle
			state.Bundles = map[string]domain.ReleaseBundle{job.SubjectID: {
				ID: bundle.ID, TenantID: bundle.TenantID, ReleaseID: bundle.ReleaseID,
				State: bundle.State.String(), Manifest: bundle.Manifest,
				ManifestHash: bundle.ManifestHash, SignatureRefs: append([]string(nil), bundle.SignatureRefs...),
				CreatedAt: bundle.CreatedAt, PublishedAt: bundle.PublishedAt, RevokedAt: bundle.RevokedAt,
			}}
		}
	case "verify_subject":
		if strings.TrimSpace(job.SubjectType) == "" || strings.TrimSpace(job.SubjectType) != job.SubjectType {
			return state, false, app.ErrValidation
		}
		resultID, _ := job.Payload["result_id"].(string)
		resultID = strings.TrimSpace(resultID)
		if resultID == "" {
			return state, true, nil
		}
		var result domain.VerificationResult
		result, err = s.loadWorkerVerificationResult(ctx, job.TenantID, resultID, job.SubjectType, job.SubjectID)
		if err == nil {
			state.Verifications = map[string]domain.VerificationResult{resultID: result}
		}
	default:
		return state, false, app.ErrValidation
	}
	if errors.Is(err, evidencequery.ErrNotFound) || errors.Is(err, packagequery.ErrReleaseBundleNotFound) || errors.Is(err, app.ErrNotFound) {
		return state, true, nil
	}
	if err != nil {
		return app.PersistedState{}, false, err
	}
	return state, true, nil
}

func parserSBOM(value evidencedomain.SBOM) domain.SBOM {
	out := domain.SBOM{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, ArtifactID: value.ArtifactID, Format: value.Format,
		SpecVersion: value.SpecVersion, ComponentCount: value.ComponentCount,
		CreatedAt: value.CreatedAt, Components: make([]domain.SBOMComponent, 0, len(value.Components)),
	}
	for _, component := range value.Components {
		out.Components = append(out.Components, domain.SBOMComponent{
			Identity: component.Identity, Name: component.Name, Version: component.Version, PURL: component.PURL,
		})
	}
	return out
}

func parserVulnerabilityScan(value evidencedomain.VulnerabilityScan) domain.VulnerabilityScan {
	out := domain.VulnerabilityScan{
		ID: value.ID, TenantID: value.TenantID, EvidenceID: value.EvidenceID,
		ReleaseID: value.ReleaseID, Scanner: value.Scanner, Adapter: value.Adapter,
		AdapterVersion: value.AdapterVersion, SourceSchema: value.SourceSchema,
		TargetRef: value.TargetRef, CreatedAt: value.CreatedAt,
	}
	if value.Summary != nil {
		out.Summary = make(map[string]int, len(value.Summary))
		for key, count := range value.Summary {
			out.Summary[key] = count
		}
	}
	if value.Findings != nil {
		out.Findings = make([]domain.VulnerabilityFinding, 0, len(value.Findings))
	}
	for _, finding := range value.Findings {
		out.Findings = append(out.Findings, domain.VulnerabilityFinding{
			ID: finding.ID, Vulnerability: finding.Vulnerability, Component: finding.Component,
			Severity: finding.Severity, State: finding.State, SeveritySource: finding.SeveritySource,
			FixVersion: finding.FixVersion, Identity: domain.VulnerabilityIdentity{
				CVE: finding.Identity.CVE, GHSA: finding.Identity.GHSA, OSV: finding.Identity.OSV,
				VendorAdvisory: finding.Identity.VendorAdvisory, PURL: finding.Identity.PURL, CPE: finding.Identity.CPE,
			},
		})
	}
	return out
}

func parserOpenAPIContract(value evidencedomain.OpenAPIContract) domain.OpenAPIContract {
	out := domain.OpenAPIContract{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID,
		ReleaseID: value.ReleaseID, Version: value.Version, Hash: value.Hash,
		PathCount: value.PathCount, EvidenceID: value.EvidenceID, CreatedAt: value.CreatedAt,
		Operations: make([]domain.OpenAPIOperation, 0, len(value.Operations)),
	}
	for _, operation := range value.Operations {
		out.Operations = append(out.Operations, domain.OpenAPIOperation{
			Path: operation.Path, Method: operation.Method, OperationID: operation.OperationID,
			Deprecated: operation.Deprecated, RequestBodyRequired: operation.RequestBodyRequired,
			RequiredRequestFields: append([]string(nil), operation.RequiredRequestFields...),
			ResponseStatuses:      append([]string(nil), operation.ResponseStatuses...),
		})
	}
	return out
}
