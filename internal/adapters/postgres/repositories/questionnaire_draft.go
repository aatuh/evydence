package repositories

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

var _ packageapp.QuestionnaireDraftReader = futureExtensions{}

func (r futureExtensions) ReadQuestionnaireDraftScope(ctx context.Context, tenant string, in packageapp.CreateQuestionnaireDraftInput) (packageapp.QuestionnaireDraftScope, error) {
	s := packageapp.QuestionnaireDraftScope{TenantID: tenant, TemplateID: in.TemplateID, ProductID: in.ProductID, ReleaseID: in.ReleaseID}
	kind, id := "tenant", tenant
	if in.ReleaseID != "" {
		kind, id = "release", in.ReleaseID
	} else if in.ProductID != "" {
		kind, id = "product", in.ProductID
	}
	root, err := r.ReadEvidenceSummaryScope(ctx, tenant, kind, id)
	if err != nil {
		return s, mapPackageDraftRepositoryError(err)
	}
	if in.ProductID != "" && root.Resources.ProductID != in.ProductID {
		return s, packageapp.ErrNotFound
	}
	if err := requireRow(ctx, r.tx, `SELECT 1 FROM questionnaire_templates WHERE tenant_id=$1 AND id=$2 FOR SHARE`, tenant, in.TemplateID); err != nil {
		return s, mapPackageDraftRepositoryError(err)
	}
	s.Resources = application.ResourceReferences{ProductID: root.Resources.ProductID, ReleaseID: in.ReleaseID}
	return s, nil
}

// Only the three selectors are transferred. Prompts, allowed_fields, template
// descriptions and arbitrary question metadata stay in PostgreSQL.
func (r futureExtensions) ReadQuestionnaireDraftQuestions(ctx context.Context, s packageapp.QuestionnaireDraftScope) ([]packageapp.DraftQuestion, error) {
	var count int
	err := r.tx.QueryRow(ctx, `SELECT CASE WHEN jsonb_typeof(questions)='array' THEN jsonb_array_length(questions) ELSE -1 END FROM questionnaire_templates WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.TenantID, s.TemplateID).Scan(&count)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, packageapp.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if count <= 0 || count > packageapp.MaxQuestionnaireDraftQuestions {
		return nil, packageapp.ErrValidation
	}
	rows, err := r.tx.Query(ctx, `SELECT left(coalesce(q->>'id',''),1025),left(coalesce(q->>'control_id',''),1025),left(coalesce(q->>'evidence_type',''),1025),
jsonb_typeof(q) IS DISTINCT FROM 'object' OR jsonb_typeof(q->'id') IS DISTINCT FROM 'string' OR
(q->'control_id' IS NOT NULL AND jsonb_typeof(q->'control_id') NOT IN ('string','null')) OR
(q->'evidence_type' IS NOT NULL AND jsonb_typeof(q->'evidence_type') NOT IN ('string','null')) OR
coalesce(octet_length(q->>'id')>1024,false) OR coalesce(octet_length(q->>'control_id')>1024,false) OR coalesce(octet_length(q->>'evidence_type')>1024,false)
FROM questionnaire_templates t CROSS JOIN LATERAL jsonb_array_elements(t.questions) WITH ORDINALITY x(q,n)
WHERE t.tenant_id=$1 AND t.id=$2 ORDER BY x.n`, s.TenantID, s.TemplateID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]packageapp.DraftQuestion, 0, count)
	for rows.Next() {
		var q packageapp.DraftQuestion
		var invalid bool
		if err := rows.Scan(&q.ID, &q.ControlID, &q.EvidenceType, &invalid); err != nil {
			return nil, err
		}
		if invalid {
			return nil, packageapp.ErrConflict
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

func (r futureExtensions) ReadQuestionnaireDraftCandidates(ctx context.Context, s packageapp.QuestionnaireDraftScope, q packageapp.DraftQuestion, remaining int) ([]packageapp.DraftAnswerCandidate, error) {
	if remaining < 0 || remaining > packageapp.MaxQuestionnaireDraftFacts {
		return nil, packageapp.ErrValidation
	}
	rows, err := r.tx.Query(ctx, `SELECT left(e.id,1025),left(coalesce(e.question_id,''),1025),left(coalesce(e.control_id,''),1025),left(coalesce(e.evidence_type,''),1025),left(coalesce(e.product_id,''),1025),left(coalesce(e.release_id,''),1025),e.created_at,
octet_length(e.id)>1024 OR coalesce(octet_length(e.question_id)>1024,false) OR coalesce(octet_length(e.control_id)>1024,false) OR coalesce(octet_length(e.evidence_type)>1024,false) OR coalesce(octet_length(e.product_id)>1024,false) OR coalesce(octet_length(e.release_id)>1024,false)
FROM questionnaire_answer_library e
LEFT JOIN releases r ON r.id=e.release_id AND r.tenant_id=e.tenant_id
LEFT JOIN products p ON p.id=coalesce(e.product_id,r.product_id) AND p.tenant_id=e.tenant_id
LEFT JOIN security_controls c ON c.id=e.control_id AND c.tenant_id=e.tenant_id
LEFT JOIN control_frameworks f ON f.id=c.framework_id AND f.tenant_id=c.tenant_id
WHERE e.tenant_id=$1 AND (coalesce(e.product_id,'')='' OR e.product_id=$2) AND (coalesce(e.release_id,'')='' OR e.release_id=$3)
AND ((e.question_id=$4 AND $4<>'') OR (e.control_id=$5 AND $5<>'') OR (e.evidence_type=$6 AND $6<>''))
AND (e.product_id IS NULL OR p.id IS NOT NULL) AND (e.release_id IS NULL OR r.id IS NOT NULL)
AND (e.product_id IS NULL OR e.release_id IS NULL OR e.product_id=r.product_id) AND (e.control_id IS NULL OR f.id IS NOT NULL)
ORDER BY e.id LIMIT $7 FOR SHARE OF e`, s.TenantID, s.ProductID, s.ReleaseID, q.ID, q.ControlID, q.EvidenceType, remaining+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []packageapp.DraftAnswerCandidate{}
	bytes := 0
	for rows.Next() {
		var v packageapp.DraftAnswerCandidate
		var oversized bool
		if err := rows.Scan(&v.ID, &v.QuestionID, &v.ControlID, &v.EvidenceType, &v.ProductID, &v.ReleaseID, &v.CreatedAt, &oversized); err != nil {
			return nil, err
		}
		if oversized {
			return nil, packageapp.ErrConflict
		}
		if len(out) == remaining {
			return nil, packageapp.ErrValidation
		}
		bytes += len(v.ID) + len(v.QuestionID) + len(v.ControlID) + len(v.EvidenceType) + len(v.ProductID) + len(v.ReleaseID)
		if bytes > packageapp.MaxGeneratedReportBytes {
			return nil, packageapp.ErrValidation
		}
		v.TenantID = s.TenantID
		v.Resources = application.ResourceReferences{ProductID: v.ProductID, ReleaseID: v.ReleaseID}
		if v.ReleaseID != "" {
			v.Resources.ProductID = s.Resources.ProductID
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r futureExtensions) ReadQuestionnaireDraftAnswer(ctx context.Context, s packageapp.QuestionnaireDraftScope, id string) (packageapp.DraftAnswer, error) {
	v := packageapp.DraftAnswer{ID: id, TenantID: s.TenantID}
	var valid bool
	err := r.tx.QueryRow(ctx, `SELECT octet_length(answer)<=65536 AND cardinality(evidence_ids)<=4096 AND cardinality(limitations)<=128
AND octet_length(answer)+octet_length(evidence_ids::text)+octet_length(limitations::text)<=4194304
AND NOT EXISTS(SELECT 1 FROM unnest(evidence_ids) x WHERE x IS NULL OR octet_length(x)>1024)
AND NOT EXISTS(SELECT 1 FROM unnest(limitations) x WHERE x IS NULL OR octet_length(x)>65536)
FROM questionnaire_answer_library WHERE tenant_id=$1 AND id=$2 FOR SHARE`, s.TenantID, id).Scan(&valid)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, packageapp.ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if !valid {
		return v, packageapp.ErrValidation
	}
	err = r.tx.QueryRow(ctx, `SELECT answer,evidence_ids,limitations FROM questionnaire_answer_library WHERE tenant_id=$1 AND id=$2`, s.TenantID, id).Scan(&v.Answer, &v.EvidenceIDs, &v.Limitations)
	return v, err
}

func (r futureExtensions) ReadQuestionnaireDraftEvidence(ctx context.Context, s packageapp.QuestionnaireDraftScope, q packageapp.DraftQuestion, remaining int) ([]string, error) {
	if remaining < 0 || remaining > packageapp.MaxQuestionnaireDraftFacts {
		return nil, packageapp.ErrValidation
	}
	statement := `SELECT left(id,1025),octet_length(id)>1024 FROM evidence_items WHERE tenant_id=$1 AND ($2='' OR product_id=$2) AND ($3='' OR release_id=$3) AND ($4='' OR type=$4) ORDER BY id LIMIT $5 FOR SHARE`
	selector := q.EvidenceType
	if q.ControlID != "" {
		selector = q.ControlID
		statement = `SELECT left(subject_id,1025),octet_length(subject_id)>1024 FROM control_evidence WHERE tenant_id=$1 AND ($2='' OR coalesce(product_id,'')='' OR product_id=$2) AND ($3='' OR coalesce(release_id,'')='' OR release_id=$3) AND control_id=$4 AND subject_type='evidence' ORDER BY subject_id,id LIMIT $5 FOR SHARE`
	}
	rows, err := r.tx.Query(ctx, statement, s.TenantID, s.ProductID, s.ReleaseID, selector, remaining+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		var oversized bool
		if err := rows.Scan(&id, &oversized); err != nil {
			return nil, err
		}
		if oversized {
			return nil, packageapp.ErrConflict
		}
		if len(out) == remaining {
			return nil, packageapp.ErrValidation
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r futureExtensions) ValidateQuestionnaireDraftEvidence(ctx context.Context, s packageapp.QuestionnaireDraftScope, ids []string) error {
	if len(ids) > packageapp.MaxQuestionnaireDraftFacts {
		return packageapp.ErrValidation
	}
	unique := make(map[string]bool, len(ids))
	for _, id := range ids {
		unique[id] = true
	}
	sorted := make([]string, 0, len(unique))
	for id := range unique {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	for _, id := range sorted {
		refs, err := evidence(r).LockEvidenceBundleEvidence(ctx, s.TenantID, id)
		if err != nil {
			return mapPackageDraftRepositoryError(err)
		}
		if s.Resources.ProductID != "" && refs.ProductID != s.Resources.ProductID || s.ReleaseID != "" && refs.ReleaseID != s.ReleaseID {
			return packageapp.ErrNotFound
		}
	}
	return nil
}

// This focused insert never reloads the full template document. Its bounded
// selector projection verifies response identity while citation guards preserve
// tenant/root integrity. The caller owns draft/audit/replay atomicity.
func (r futureExtensions) InsertFocusedQuestionnaireDraft(ctx context.Context, v packagedomain.QuestionnaireDraft) error {
	if err := packageapp.ValidateQuestionnaireDraftRecord(v); err != nil {
		return err
	}
	scope, err := r.ReadQuestionnaireDraftScope(ctx, v.TenantID, packageapp.CreateQuestionnaireDraftInput{TemplateID: v.TemplateID, ProductID: v.ProductID, ReleaseID: v.ReleaseID})
	if err != nil {
		return err
	}
	questions, err := r.ReadQuestionnaireDraftQuestions(ctx, scope)
	if err != nil {
		return err
	}
	if len(questions) != len(v.Responses) {
		return packageapp.ErrValidation
	}
	seen := make(map[string]bool, len(questions))
	total := 0
	for i, response := range v.Responses {
		if response.QuestionID != questions[i].ID || seen[response.QuestionID] || response.Answer == "" {
			return packageapp.ErrValidation
		}
		seen[response.QuestionID] = true
		total += len(response.EvidenceIDs)
		if total > packageapp.MaxQuestionnaireDraftFacts {
			return packageapp.ErrValidation
		}
		if err := r.ValidateQuestionnaireDraftEvidence(ctx, scope, response.EvidenceIDs); err != nil {
			return err
		}
	}
	encoded, err := packageapp.EncodeQuestionnaireResponses(v.Responses)
	if err != nil {
		return err
	}
	if len(encoded) > packageapp.MaxGeneratedReportBytes {
		return packageapp.ErrValidation
	}
	_, err = r.tx.Exec(ctx, `INSERT INTO questionnaire_drafts(id,tenant_id,template_id,product_id,release_id,responses,manifest_hash,limitations,schema_version,created_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, v.ID, v.TenantID, v.TemplateID, nullableString(v.ProductID), nullableString(v.ReleaseID), encoded, v.ManifestHash, textArray(v.Limitations), v.SchemaVersion, v.CreatedAt)
	return mapPackageDraftRepositoryError(writeError("insert focused questionnaire draft", err))
}
func mapPackageDraftRepositoryError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return packageapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return packageapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return packageapp.ErrConflict
	default:
		return err
	}
}
