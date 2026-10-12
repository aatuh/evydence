package domain

// BuiltinTemplatePacks returns fresh values because callers may edit a pack
// before installing it for one tenant. These starter packs organize technical
// evidence; they do not establish framework compliance or control efficacy.
func BuiltinTemplatePacks() []ControlFrameworkTemplatePack {
	return []ControlFrameworkTemplatePack{
		{ID: "tpl_cra_readiness", Name: "Evydence CRA Readiness", Slug: "evydence-cra-readiness", Version: "2026.05", Description: "Starter technical evidence controls for CRA readiness tracking.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []SecurityControl{
			{Code: "CRA-SBOM", Title: "SBOM evidence", Objective: "Release records SBOM evidence.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "sbom", Required: true}}, Limitations: []string{"SBOM presence does not prove completeness."}},
			{Code: "CRA-VULN", Title: "Vulnerability evidence", Objective: "Release records vulnerability scan and decisions.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "vulnerability_scan", Required: true}}},
		}},
		{ID: "tpl_nist_ssdf_lite", Name: "NIST SSDF Lite", Slug: "nist-ssdf-lite", Version: "2026.05", Description: "Small starter control pack for secure development evidence.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []SecurityControl{
			{Code: "SSDF-BUILD", Title: "Build provenance", Objective: "Release has build and attestation evidence.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "build", Required: true}, {Type: "build_attestation", Required: true}}},
		}},
		{ID: "tpl_soc2_technical_lite", Name: "SOC 2 Technical Evidence Lite", Slug: "soc2-technical-lite", Version: "2026.05", Description: "Starter technical evidence controls for SOC 2-style review preparation.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []SecurityControl{
			{Code: "SOC2-CHANGE", Title: "Change evidence", Objective: "Release records source, build, and approval evidence for change review.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "build", Required: true}, {Type: "artifact", Required: true}, {Type: "release_bundle", Required: true}}, Limitations: []string{"This pack organizes technical evidence only and does not state SOC 2 control effectiveness."}},
			{Code: "SOC2-VULN", Title: "Vulnerability review evidence", Objective: "Release records vulnerability scan evidence and decisions or exceptions.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "vulnerability_scan", Required: true}, {Type: "vulnerability_decision", Required: false}, {Type: "exception", Required: false}}},
		}},
		{ID: "tpl_iso27001_technical_lite", Name: "ISO 27001 Technical Evidence Lite", Slug: "iso27001-technical-lite", Version: "2026.05", Description: "Starter technical evidence controls for ISO 27001-style evidence organization.", SchemaVersion: "control-framework-template-pack.v1.0.0", Controls: []SecurityControl{
			{Code: "ISO-ASSET", Title: "Software asset evidence", Objective: "Release records artifacts, SBOM, and dependency evidence.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "artifact", Required: true}, {Type: "sbom", Required: true}}, Limitations: []string{"Artifact and SBOM evidence does not prove inventory completeness."}},
			{Code: "ISO-CHANGE", Title: "Release change evidence", Objective: "Release records build provenance and bundle verification evidence.", EvidenceRequirements: []ControlEvidenceRequirement{{Type: "build", Required: true}, {Type: "build_attestation", Required: false}, {Type: "release_bundle", Required: true}}},
		}},
	}
}
