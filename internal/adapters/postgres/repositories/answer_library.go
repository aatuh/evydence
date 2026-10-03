package repositories

import (
	"context"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var _ packageapp.AnswerLibraryReader = enterprise{}

func answerLibraryCoordinate(v string, required bool) bool {
	return (!required || v != "") && v == strings.TrimSpace(v) && len(v) <= packageapp.MaxAnswerLibraryIDBytes && utf8.ValidString(v) && !strings.ContainsRune(v, 0)
}
func (r enterprise) ReadAnswerLibraryScope(ctx context.Context, tenant, product, release string) (packageapp.AnswerLibraryScope, error) {
	s := packageapp.AnswerLibraryScope{TenantID: tenant, ProductID: product, ReleaseID: release}
	if ctx == nil || !answerLibraryCoordinate(tenant, true) || !answerLibraryCoordinate(product, false) || !answerLibraryCoordinate(release, false) {
		return s, packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return s, err
	}
	kind, id := "tenant", tenant
	if release != "" {
		kind, id = "release", release
	} else if product != "" {
		kind, id = "product", product
	}
	root, err := futureExtensions(r).ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	if err != nil {
		return s, mapPackageDraftRepositoryError(err)
	}
	if product != "" && root.Resources.ProductID != product {
		return s, packageapp.ErrNotFound
	}
	s.Resources = application.ResourceReferences{ProductID: root.Resources.ProductID, ReleaseID: release}
	return s, nil
}

// Only bounded ownership coordinates cross this port. Control objectives,
// evidence title/metadata/payloads and private library answers are not selected.
func (r enterprise) ValidateAnswerLibraryReferences(ctx context.Context, s packageapp.AnswerLibraryScope, control string, ids []string) error {
	if ctx == nil || !answerLibraryCoordinate(s.TenantID, true) || !answerLibraryCoordinate(s.ProductID, false) || !answerLibraryCoordinate(s.ReleaseID, false) || !answerLibraryCoordinate(control, false) || len(ids) > packageapp.MaxAnswerLibraryEvidenceIDs {
		return packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	controls := []string{}
	if control != "" {
		controls = append(controls, control)
	}
	if err := r.ValidateQuestionnaireTemplateScope(ctx, s.TenantID, controls); err != nil {
		return err
	}
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	ids = slices.Compact(ids)
	total := 0
	for _, id := range ids {
		if !answerLibraryCoordinate(id, true) {
			return packageapp.ErrValidation
		}
		raw, err := ReadEvidenceBundleCoordinates(ctx, r.tx, s.TenantID, id, true)
		if err != nil {
			return mapPackageDraftRepositoryError(err)
		}
		if s.ProductID != "" && raw.ProductID != s.ProductID || s.ReleaseID != "" && raw.ReleaseID != s.ReleaseID {
			return packageapp.ErrNotFound
		}
		total += len(id) + len(raw.ProductID) + len(raw.ProjectID) + len(raw.ReleaseID) + len(raw.BuildID) + len(raw.DeploymentID)
		if total > packageapp.MaxGeneratedReportBytes {
			return packageapp.ErrValidation
		}
		if _, err := evidence(r).lockEvidenceBundleCoordinates(ctx, s.TenantID, raw); err != nil {
			return mapPackageDraftRepositoryError(err)
		}
	}
	return nil
}
func (r enterprise) InsertFocusedAnswerLibraryEntry(ctx context.Context, v packagedomain.QuestionnaireAnswerLibraryEntry) error {
	if err := packageapp.ValidateAnswerLibraryRecord(v); err != nil {
		return err
	}
	s, err := r.ReadAnswerLibraryScope(ctx, v.TenantID, v.ProductID, v.ReleaseID)
	if err != nil {
		return err
	}
	if err := r.ValidateAnswerLibraryReferences(ctx, s, v.ControlID, v.EvidenceIDs); err != nil {
		return err
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO questionnaire_answer_library(id,tenant_id,question_id,evidence_type,control_id,product_id,release_id,answer,evidence_ids,limitations,schema_version,created_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, v.ID, v.TenantID, nullableString(v.QuestionID), nullableString(v.EvidenceType), nullableString(v.ControlID), nullableString(v.ProductID), nullableString(v.ReleaseID), v.Answer, textArray(v.EvidenceIDs), textArray(v.Limitations), v.SchemaVersion, v.CreatedAt)
	return mapPackageDraftRepositoryError(writeError("insert focused questionnaire answer", err))
}
