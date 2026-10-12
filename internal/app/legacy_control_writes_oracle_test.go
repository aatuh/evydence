package app

import (
	"context"
	"sort"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical control algorithms; never production wiring.
type CreateControlFrameworkInput struct {
	Name        string
	Slug        string
	Version     string
	Description string
}

type CreateSecurityControlInput struct {
	FrameworkID          string
	Code                 string
	Title                string
	Objective            string
	EvidenceRequirements []domain.ControlEvidenceRequirement
	Applicability        []string
	Limitations          []string
}

type LinkControlEvidenceInput struct {
	EvidenceType string
	SubjectType  string
	SubjectID    string
	ProductID    string
	ReleaseID    string
	Confidence   string
	Notes        string
}

func (l *Ledger) CreateControlFramework(ctx context.Context, actor domain.Actor, in CreateControlFrameworkInput) (domain.ControlFramework, error) {
	if err := l.AuthorizeControlFrameworkCreation(ctx, actor, in); err != nil {
		return domain.ControlFramework{}, err
	}
	name := strings.TrimSpace(in.Name)
	slug := strings.TrimSpace(in.Slug)
	version := strings.TrimSpace(in.Version)
	if slug == "" {
		slug = slugify(name)
	}
	if name == "" || slug == "" || version == "" {
		return domain.ControlFramework{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, existing := range l.frameworks {
		if existing.TenantID == actor.TenantID && existing.Slug == slug && existing.Version == version {
			return domain.ControlFramework{}, ErrConflict
		}
	}
	framework := domain.ControlFramework{
		ID:            newID("fw"),
		TenantID:      actor.TenantID,
		Name:          name,
		Slug:          slug,
		Version:       version,
		Description:   strings.TrimSpace(in.Description),
		Status:        "active",
		SchemaVersion: domain.ControlFrameworkSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Controls.InsertControlFramework(ctx, framework); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(framework.CreatedAt, actor.TenantID, "control_framework.created", "control_framework", framework.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.ControlFramework{}, err
		}
		l.frameworks[framework.ID] = framework
		l.publishCommittedAuditEntryLocked(entry)
		return framework, nil
	}
	l.frameworks[framework.ID] = framework
	_, _ = l.appendChainLocked(actor.TenantID, "control_framework.created", "control_framework", framework.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlFramework{}, err
	}
	return framework, nil
}

func (l *Ledger) CreateSecurityControl(ctx context.Context, actor domain.Actor, in CreateSecurityControlInput) (domain.SecurityControl, error) {
	if err := l.AuthorizeSecurityControlCreation(ctx, actor, in); err != nil {
		return domain.SecurityControl{}, err
	}
	in.FrameworkID = strings.TrimSpace(in.FrameworkID)
	code := strings.TrimSpace(in.Code)
	title := strings.TrimSpace(in.Title)
	objective := strings.TrimSpace(in.Objective)
	if in.FrameworkID == "" || code == "" || title == "" || objective == "" {
		return domain.SecurityControl{}, ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	framework, ok := l.frameworks[in.FrameworkID]
	if !ok || framework.TenantID != actor.TenantID {
		return domain.SecurityControl{}, ErrNotFound
	}
	requirements, err := normalizeControlRequirements(in.EvidenceRequirements)
	if err != nil {
		return domain.SecurityControl{}, err
	}
	for _, existing := range l.controls {
		if existing.TenantID == actor.TenantID && existing.FrameworkID == framework.ID && existing.Code == code {
			return domain.SecurityControl{}, ErrConflict
		}
	}
	control := domain.SecurityControl{
		ID:                   newID("ctrl"),
		TenantID:             actor.TenantID,
		FrameworkID:          framework.ID,
		Code:                 code,
		Title:                title,
		Objective:            objective,
		EvidenceRequirements: requirements,
		Applicability:        sortedStrings(in.Applicability),
		Limitations:          cleanStrings(in.Limitations),
		SchemaVersion:        domain.SecurityControlSchemaVersion,
		CreatedAt:            l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Controls.InsertSecurityControl(ctx, control); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(control.CreatedAt, actor.TenantID, "security_control.created", "security_control", control.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.SecurityControl{}, err
		}
		l.controls[control.ID] = control
		l.publishCommittedAuditEntryLocked(entry)
		return control, nil
	}
	l.controls[control.ID] = control
	_, _ = l.appendChainLocked(actor.TenantID, "security_control.created", "security_control", control.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.SecurityControl{}, err
	}
	return control, nil
}

func (l *Ledger) LinkControlEvidence(ctx context.Context, actor domain.Actor, controlID string, in LinkControlEvidenceInput) (domain.ControlEvidence, error) {
	controlID, in, err := prepareLocalControlEvidenceLink(ctx, actor, controlID, in)
	if err != nil {
		return domain.ControlEvidence{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refreshWorkerProjectionLocked(ctx, actor.TenantID); err != nil {
		return domain.ControlEvidence{}, err
	}
	if err := l.authorizeControlEvidenceLinkLocked(actor, controlID, in); err != nil {
		return domain.ControlEvidence{}, err
	}
	control := l.controls[controlID]
	for _, existing := range l.controlLinks {
		if existing.TenantID == actor.TenantID && existing.ControlID == control.ID && existing.EvidenceType == in.EvidenceType && existing.SubjectType == in.SubjectType && existing.SubjectID == in.SubjectID && existing.ProductID == in.ProductID && existing.ReleaseID == in.ReleaseID {
			return existing, nil
		}
	}
	link := domain.ControlEvidence{
		ID:            newID("ce"),
		TenantID:      actor.TenantID,
		ControlID:     control.ID,
		EvidenceType:  in.EvidenceType,
		SubjectType:   in.SubjectType,
		SubjectID:     in.SubjectID,
		ProductID:     in.ProductID,
		ReleaseID:     in.ReleaseID,
		Confidence:    in.Confidence,
		Notes:         strings.TrimSpace(in.Notes),
		SchemaVersion: domain.ControlEvidenceSchemaVersion,
		CreatedAt:     l.now(),
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Controls.InsertControlEvidence(ctx, link); err != nil {
				return err
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(link.CreatedAt, actor.TenantID, "control_evidence.linked", "control_evidence", link.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.ControlEvidence{}, err
		}
		l.controlLinks[link.ID] = link
		l.publishCommittedAuditEntryLocked(entry)
		return link, nil
	}
	l.controlLinks[link.ID] = link
	_, _ = l.appendChainLocked(actor.TenantID, "control_evidence.linked", "control_evidence", link.ID, "api_key", actor.KeyID, "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlEvidence{}, err
	}
	return link, nil
}

func (l *Ledger) ListControlEvidence(ctx context.Context, actor domain.Actor, controlID, productID, releaseID string) ([]domain.ControlEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := require(actor, ScopeControlsRead); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := []domain.ControlEvidence{}
	for _, link := range l.controlLinks {
		if link.TenantID != actor.TenantID {
			continue
		}
		if controlID != "" && link.ControlID != controlID {
			continue
		}
		if productID != "" && link.ProductID != productID {
			continue
		}
		if releaseID != "" && link.ReleaseID != releaseID {
			continue
		}
		control, ok := l.controls[link.ControlID]
		if !ok || control.TenantID != actor.TenantID {
			continue
		}
		framework, ok := l.frameworks[control.FrameworkID]
		if !ok || framework.TenantID != actor.TenantID {
			continue
		}
		if err := l.ensureScopeLocked(actor.TenantID, link.ProductID, "", link.ReleaseID); err != nil {
			continue
		}
		if link.ProductID != "" && link.ReleaseID != "" && l.releases[link.ReleaseID].ProductID != link.ProductID {
			continue
		}
		if !l.controlSubjectExistsLocked(actor.TenantID, link.SubjectType, link.SubjectID, link.ProductID, link.ReleaseID) {
			continue
		}
		if !l.resourceAllowedLocked(actor, ScopeControlsRead, l.refsForControlEvidenceSubjectLocked(link.SubjectType, link.SubjectID, link.ProductID, link.ReleaseID)) {
			continue
		}
		out = append(out, link)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
