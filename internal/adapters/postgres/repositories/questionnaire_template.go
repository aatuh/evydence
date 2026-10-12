package repositories

import (
	"context"
	"sort"
	"strings"
	"unicode/utf8"

	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

// Locks only ownership identifiers. Prompts, objectives, evidence, existing
// templates and unrelated tenant state are never read for creation/replay.
func (r enterprise) ValidateQuestionnaireTemplateScope(ctx context.Context, tenant string, ids []string) error {
	if ctx == nil || strings.TrimSpace(tenant) == "" || tenant != strings.TrimSpace(tenant) || !utf8.ValidString(tenant) || strings.ContainsRune(tenant, 0) || len(tenant) > packageapp.MaxQuestionnaireTemplateTextBytes || len(ids) > packageapp.MaxQuestionnaireTemplateQuestions {
		return packageapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM tenants WHERE id=$1 FOR SHARE`, tenant); err != nil {
		return mapPackageDraftRepositoryError(err)
	}
	if len(ids) == 0 {
		return nil
	}
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	for i, id := range ids {
		if id == "" || id != strings.TrimSpace(id) || !utf8.ValidString(id) || strings.ContainsRune(id, 0) || len(id) > packageapp.MaxQuestionnaireTemplateTextBytes || i > 0 && ids[i-1] == id {
			return packageapp.ErrValidation
		}
	}
	rows, err := r.tx.Query(ctx, `SELECT c.id FROM security_controls c JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id WHERE c.tenant_id=$1 AND c.id=ANY($2) ORDER BY c.id FOR SHARE OF c,f`, tenant, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		if i >= len(ids) || ids[i] != id {
			return packageapp.ErrNotFound
		}
		i++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if i != len(ids) {
		return packageapp.ErrNotFound
	}
	return nil
}

func (r enterprise) InsertFocusedQuestionnaireTemplate(ctx context.Context, v packagedomain.QuestionnaireTemplate) error {
	if err := packageapp.ValidateQuestionnaireTemplateRecord(v); err != nil {
		return err
	}
	if err := r.ValidateQuestionnaireTemplateScope(ctx, v.TenantID, packageapp.QuestionnaireTemplateControlIDs(v.Questions)); err != nil {
		return err
	}
	questions, err := packageapp.EncodeQuestionnaireQuestions(v.Questions)
	if err != nil {
		return err
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO questionnaire_templates(id,tenant_id,name,version,questions,schema_version,created_at)VALUES($1,$2,$3,$4,$5,$6,$7)`, v.ID, v.TenantID, v.Name, v.Version, questions, v.SchemaVersion, v.CreatedAt)
	return mapPackageDraftRepositoryError(writeError("insert questionnaire template", err))
}
