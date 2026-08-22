package domain

import (
	"fmt"
	"time"

	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	integrationdomain "github.com/aatuh/evydence/internal/integration/domain"
	operationsdomain "github.com/aatuh/evydence/internal/operations/domain"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

func ActorToIdentityModel(value Actor) identitydomain.Actor {
	grants := make([]identitydomain.ResourceGrant, 0, len(value.ResourceGrants))
	for _, grant := range value.ResourceGrants {
		grants = append(grants, identitydomain.ResourceGrant{
			Role: grant.Role, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID,
			Scopes: append([]string(nil), grant.Scopes...),
		})
	}
	return identitydomain.Actor{
		TenantID: value.TenantID, KeyID: value.KeyID, UserID: value.UserID,
		SessionID: value.SessionID, Name: value.Name, Scopes: append([]string(nil), value.Scopes...),
		CollectorID: value.CollectorID, ResourceGrants: grants,
	}
}

func ActorFromIdentityModel(value identitydomain.Actor) Actor {
	grants := make([]ResourceGrant, 0, len(value.ResourceGrants))
	for _, grant := range value.ResourceGrants {
		grants = append(grants, ResourceGrant{
			Role: grant.Role, ResourceType: grant.ResourceType, ResourceID: grant.ResourceID,
			Scopes: append([]string(nil), grant.Scopes...),
		})
	}
	return Actor{
		TenantID: value.TenantID, KeyID: value.KeyID, UserID: value.UserID,
		SessionID: value.SessionID, Name: value.Name, Scopes: append([]string(nil), value.Scopes...),
		CollectorID: value.CollectorID, ResourceGrants: grants,
	}
}

func ReleaseToContextModel(value Release) (releasedomain.Release, error) {
	state, err := releasedomain.ParseReleaseState(value.State)
	if err != nil {
		return releasedomain.Release{}, fmt.Errorf("release state: %w", err)
	}
	return releasedomain.Release{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID,
		Version: value.Version, Revision: value.Revision, State: state, CreatedAt: value.CreatedAt,
		FrozenAt: cloneTimePointer(value.FrozenAt), ApprovedAt: cloneTimePointer(value.ApprovedAt),
	}, nil
}

func ReleaseFromContextModel(value releasedomain.Release) Release {
	return Release{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID,
		Version: value.Version, Revision: value.Revision, State: value.State.String(), CreatedAt: value.CreatedAt,
		FrozenAt: cloneTimePointer(value.FrozenAt), ApprovedAt: cloneTimePointer(value.ApprovedAt),
	}
}

func SubjectRefToEvidenceModel(value SubjectRef) (evidencedomain.SubjectRef, error) {
	return evidencedomain.NewSubjectReference(value.Type, value.ID, value.Digest)
}

func SubjectRefFromEvidenceModel(value evidencedomain.SubjectRef) SubjectRef {
	return SubjectRef{Type: value.Type, ID: value.ID, Digest: value.Digest}
}

func VulnerabilityDecisionToContextModel(value VulnerabilityDecision) (riskdomain.VulnerabilityDecision, error) {
	status, err := riskdomain.ParseDecisionStatus(value.Status)
	if err != nil {
		return riskdomain.VulnerabilityDecision{}, fmt.Errorf("vulnerability decision status: %w", err)
	}
	references := make([]riskdomain.SupportingReference, 0, len(value.SupportingRefs))
	for _, reference := range value.SupportingRefs {
		references = append(references, riskdomain.SupportingReference{Type: reference.Type, ID: reference.ID, Digest: reference.Digest})
	}
	return riskdomain.VulnerabilityDecision{
		ID: value.ID, TenantID: value.TenantID, FindingID: value.FindingID, ScanID: value.ScanID,
		ReleaseID: value.ReleaseID, Vulnerability: value.Vulnerability, Component: value.Component,
		SBOMID: value.SBOMID, SBOMComponentPURL: value.SBOMComponentPURL, SBOMComponentName: value.SBOMComponentName,
		Status: status, Justification: value.Justification, ImpactStatement: value.ImpactStatement,
		ActionStatement: value.ActionStatement, CustomerVisible: value.CustomerVisible, InternalNotes: value.InternalNotes,
		Source: value.Source, EvidenceID: value.EvidenceID, EvidenceIDs: append([]string(nil), value.EvidenceIDs...),
		SupportingRefs: references, VEXDocumentID: value.VEXDocumentID, Supersedes: value.Supersedes,
		SupersededBy: value.SupersededBy, ApprovedBy: value.ApprovedBy,
		ReviewedAt: cloneTimePointer(value.ReviewedAt), ReviewDueAt: cloneTimePointer(value.ReviewDueAt),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}, nil
}

func VulnerabilityDecisionFromContextModel(value riskdomain.VulnerabilityDecision) VulnerabilityDecision {
	references := make([]SubjectRef, 0, len(value.SupportingRefs))
	for _, reference := range value.SupportingRefs {
		references = append(references, SubjectRef{Type: reference.Type, ID: reference.ID, Digest: reference.Digest})
	}
	return VulnerabilityDecision{
		ID: value.ID, TenantID: value.TenantID, FindingID: value.FindingID, ScanID: value.ScanID,
		ReleaseID: value.ReleaseID, Vulnerability: value.Vulnerability, Component: value.Component,
		SBOMID: value.SBOMID, SBOMComponentPURL: value.SBOMComponentPURL, SBOMComponentName: value.SBOMComponentName,
		Status: value.Status.String(), Justification: value.Justification, ImpactStatement: value.ImpactStatement,
		ActionStatement: value.ActionStatement, CustomerVisible: value.CustomerVisible, InternalNotes: value.InternalNotes,
		Source: value.Source, EvidenceID: value.EvidenceID, EvidenceIDs: append([]string(nil), value.EvidenceIDs...),
		SupportingRefs: references, VEXDocumentID: value.VEXDocumentID, Supersedes: value.Supersedes,
		SupersededBy: value.SupersededBy, ApprovedBy: value.ApprovedBy,
		ReviewedAt: cloneTimePointer(value.ReviewedAt), ReviewDueAt: cloneTimePointer(value.ReviewDueAt),
		SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func ReleaseBundleToContextModel(value ReleaseBundle) (packagedomain.ReleaseBundle, error) {
	state, err := packagedomain.ParseBundleState(value.State)
	if err != nil {
		return packagedomain.ReleaseBundle{}, fmt.Errorf("release bundle state: %w", err)
	}
	return packagedomain.ReleaseBundle{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, State: state,
		Manifest: cloneJSONMap(value.Manifest), ManifestHash: value.ManifestHash,
		SignatureRefs: append([]string(nil), value.SignatureRefs...), CreatedAt: value.CreatedAt,
		PublishedAt: cloneTimePointer(value.PublishedAt), RevokedAt: cloneTimePointer(value.RevokedAt),
	}, nil
}

func ReleaseBundleFromContextModel(value packagedomain.ReleaseBundle) ReleaseBundle {
	return ReleaseBundle{
		ID: value.ID, TenantID: value.TenantID, ReleaseID: value.ReleaseID, State: value.State.String(),
		Manifest: cloneJSONMap(value.Manifest), ManifestHash: value.ManifestHash,
		SignatureRefs: append([]string(nil), value.SignatureRefs...), CreatedAt: value.CreatedAt,
		PublishedAt: cloneTimePointer(value.PublishedAt), RevokedAt: cloneTimePointer(value.RevokedAt),
	}
}

func VerificationResultToContextModel(value VerificationResult) (verificationdomain.VerificationResult, error) {
	state, err := verificationdomain.ParseVerificationState(value.Result)
	if err != nil {
		return verificationdomain.VerificationResult{}, fmt.Errorf("verification result state: %w", err)
	}
	return verificationdomain.VerificationResult{
		ID: value.ID, TenantID: value.TenantID, SubjectType: value.SubjectType, SubjectID: value.SubjectID,
		Result: state, Checks: verificationChecksToContext(value.Checks),
		Profile: verificationProfileToContext(value.Profile), Limitations: append([]string(nil), value.Limitations...),
		SchemaVersion: value.SchemaVersion, VerifiedAt: value.VerifiedAt,
	}, nil
}

func VerificationResultFromContextModel(value verificationdomain.VerificationResult) VerificationResult {
	return VerificationResult{
		ID: value.ID, TenantID: value.TenantID, SubjectType: value.SubjectType, SubjectID: value.SubjectID,
		Result: value.Result.String(), Checks: verificationChecksFromContext(value.Checks),
		Profile: verificationProfileFromContext(value.Profile), Limitations: append([]string(nil), value.Limitations...),
		SchemaVersion: value.SchemaVersion, VerifiedAt: value.VerifiedAt,
	}
}

func signingKeyToContextModel(value SigningKey) (verificationdomain.SigningKey, error) {
	statusValue := value.Status
	if statusValue == "" {
		statusValue = verificationdomain.SigningKeyStatusLegacyUnspecifiedValue
	}
	status, err := verificationdomain.ParseSigningKeyStatus(statusValue)
	if err != nil {
		return verificationdomain.SigningKey{}, fmt.Errorf("signing key status: %w", err)
	}
	return verificationdomain.SigningKey{
		ID: value.ID, TenantID: value.TenantID, KID: value.KID, Version: value.Version,
		Provider: value.Provider, Algorithm: value.Algorithm, Status: status,
		PublicKey: value.PublicKey, PublicKeyFingerprint: value.PublicKeyFingerprint,
		ValidFrom: value.ValidFrom, ValidUntil: cloneTimePointer(value.ValidUntil), CreatedAt: value.CreatedAt,
		RevokedAt: cloneTimePointer(value.RevokedAt), RevocationReason: value.RevocationReason,
		RevocationSemantics: value.RevocationSemantics, HistoricalValidityPolicy: value.HistoricalValidityPolicy,
		CompromisedAt: cloneTimePointer(value.CompromisedAt),
	}, nil
}

func IncidentToContextModel(value Incident) (operationsdomain.Incident, error) {
	status, err := operationsdomain.ParseIncidentStatus(value.Status)
	if err != nil {
		return operationsdomain.Incident{}, fmt.Errorf("incident status: %w", err)
	}
	return operationsdomain.Incident{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID,
		Title: value.Title, Severity: value.Severity, Status: status, OpenedAt: value.OpenedAt,
		ClosedAt: cloneTimePointer(value.ClosedAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}, nil
}

func IncidentFromContextModel(value operationsdomain.Incident) Incident {
	return Incident{
		ID: value.ID, TenantID: value.TenantID, ProductID: value.ProductID, ReleaseID: value.ReleaseID,
		Title: value.Title, Severity: value.Severity, Status: value.Status.String(), OpenedAt: value.OpenedAt,
		ClosedAt: cloneTimePointer(value.ClosedAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func CollectorToContextModel(value Collector) (integrationdomain.Collector, error) {
	status, err := integrationdomain.ParseCollectorStatus(value.Status)
	if err != nil {
		return integrationdomain.Collector{}, fmt.Errorf("collector status: %w", err)
	}
	return integrationdomain.Collector{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Version: value.Version,
		APIKeyID: value.APIKeyID, Status: status, AllowedScopes: append([]string(nil), value.AllowedScopes...),
		LastSeenAt: cloneTimePointer(value.LastSeenAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}, nil
}

func CollectorFromContextModel(value integrationdomain.Collector) Collector {
	return Collector{
		ID: value.ID, TenantID: value.TenantID, Name: value.Name, Type: value.Type, Version: value.Version,
		APIKeyID: value.APIKeyID, Status: value.Status.String(), AllowedScopes: append([]string(nil), value.AllowedScopes...),
		LastSeenAt: cloneTimePointer(value.LastSeenAt), SchemaVersion: value.SchemaVersion, CreatedAt: value.CreatedAt,
	}
}

func verificationChecksToContext(values []VerifyCheck) []verificationdomain.VerifyCheck {
	result := make([]verificationdomain.VerifyCheck, 0, len(values))
	for _, value := range values {
		result = append(result, verificationdomain.VerifyCheck{Name: value.Name, Result: value.Result, Detail: value.Detail})
	}
	return result
}

func verificationChecksFromContext(values []verificationdomain.VerifyCheck) []VerifyCheck {
	result := make([]VerifyCheck, 0, len(values))
	for _, value := range values {
		result = append(result, VerifyCheck{Name: value.Name, Result: value.Result, Detail: value.Detail})
	}
	return result
}

func verificationProfileToContext(value VerificationProfile) verificationdomain.VerificationProfile {
	return verificationdomain.VerificationProfile{
		ID: value.ID, Version: value.Version, RequiredChecks: append([]string(nil), value.RequiredChecks...),
		TrustMaterial: append([]string(nil), value.TrustMaterial...), IdentityPolicy: value.IdentityPolicy,
		TransparencyProof: value.TransparencyProof, PayloadScope: value.PayloadScope, PayloadDigest: value.PayloadDigest,
		Limitations: append([]string(nil), value.Limitations...),
	}
}

func verificationProfileFromContext(value verificationdomain.VerificationProfile) VerificationProfile {
	return VerificationProfile{
		ID: value.ID, Version: value.Version, RequiredChecks: append([]string(nil), value.RequiredChecks...),
		TrustMaterial: append([]string(nil), value.TrustMaterial...), IdentityPolicy: value.IdentityPolicy,
		TransparencyProof: value.TransparencyProof, PayloadScope: value.PayloadScope, PayloadDigest: value.PayloadDigest,
		Limitations: append([]string(nil), value.Limitations...),
	}
}

func cloneTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneJSONMap(value map[string]any) map[string]any {
	if value == nil {
		return nil
	}
	cloned := make(map[string]any, len(value))
	for key, nested := range value {
		cloned[key] = cloneJSONValue(nested)
	}
	return cloned
}

func cloneJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneJSONMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, nested := range typed {
			cloned[index] = cloneJSONValue(nested)
		}
		return cloned
	case []string:
		return append([]string(nil), typed...)
	default:
		return value
	}
}
