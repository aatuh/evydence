package repositories

import (
	"context"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var _ packageapp.QuestionnairePackageReader = enterprise{}

func (r enterprise) ReadQuestionnairePackageScope(ctx context.Context, tenant string, in packageapp.CreateQuestionnairePackageInput) (packageapp.QuestionnairePackageScope, error) {
	var s packageapp.QuestionnairePackageScope
	if ctx == nil {
		return s, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	in, err := packageapp.NormalizeQuestionnairePackageInput(in)
	if err != nil {
		return s, err
	}
	d := futureExtensions(r)
	s.Selection, err = d.ReadQuestionnaireDraftScope(ctx, tenant, packageapp.CreateQuestionnaireDraftInput{TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID})
	if err != nil {
		return s, err
	}
	if in.PackageID != "" {
		root, err := d.ReadEvidenceSummaryScope(ctx, tenant, "customer_package", in.PackageID)
		if err != nil {
			return s, mapPackageDraftRepositoryError(err)
		}
		s.PackageID, s.PackageResources = in.PackageID, root.Resources
	}
	return s, packageapp.ValidateQuestionnairePackageScope(tenant, in, s)
}

// Only current scope coordinates, ordered question selectors and cited evidence
// ownership are rechecked. Template prompts and package manifests are not read.
func (r enterprise) InsertFocusedQuestionnairePackage(ctx context.Context, v packagedomain.QuestionnairePackage) error {
	if err := packageapp.ValidateQuestionnairePackageRecord(v); err != nil {
		return err
	}
	s, err := r.ReadQuestionnairePackageScope(ctx, v.TenantID, packageapp.CreateQuestionnairePackageInput{TemplateID: v.TemplateID, PackageID: v.PackageID, ProductID: v.ProductID, ReleaseID: v.ReleaseID})
	if err != nil {
		return err
	}
	d := futureExtensions(r)
	questions, err := d.ReadQuestionnaireDraftQuestions(ctx, s.Selection)
	if err != nil {
		return err
	}
	if len(questions) != len(v.Responses) {
		return packageapp.ErrValidation
	}
	for i, response := range v.Responses {
		if response.QuestionID != questions[i].ID {
			return packageapp.ErrValidation
		}
		if err := d.ValidateQuestionnaireDraftEvidence(ctx, s.Selection, response.EvidenceIDs); err != nil {
			return err
		}
	}
	encoded, err := packageapp.EncodeQuestionnaireResponses(v.Responses)
	if err != nil {
		return err
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO questionnaire_packages(id,tenant_id,template_id,package_id,product_id,release_id,responses,manifest_hash,schema_version,created_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, v.ID, v.TenantID, v.TemplateID, nullableString(v.PackageID), nullableString(v.ProductID), nullableString(v.ReleaseID), encoded, v.ManifestHash, v.SchemaVersion, v.CreatedAt)
	return mapPackageDraftRepositoryError(writeError("insert focused questionnaire package", err))
}
