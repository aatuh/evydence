package app

import (
	"context"
	"strings"

	"github.com/aatuh/evydence/internal/domain"
)

// Unchanged historical control algorithms; never production wiring.
func (l *Ledger) InstallControlFrameworkTemplatePack(ctx context.Context, actor domain.Actor, slug string) (domain.ControlFramework, error) {
	if err := l.AuthorizeControlTemplateInstallation(ctx, actor, slug); err != nil {
		return domain.ControlFramework{}, err
	}
	var selected domain.ControlFrameworkTemplatePack
	for _, pack := range builtinTemplatePacks() {
		if pack.Slug == strings.TrimSpace(slug) {
			selected = pack
			break
		}
	}
	if selected.ID == "" {
		return domain.ControlFramework{}, ErrNotFound
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	framework := domain.ControlFramework{ID: newID("cf"), TenantID: actor.TenantID, Name: selected.Name, Slug: selected.Slug, Version: selected.Version, Description: selected.Description, Status: "active", SchemaVersion: domain.ControlFrameworkSchemaVersion, CreatedAt: l.now()}
	controls := make([]domain.SecurityControl, 0, len(selected.Controls))
	for _, templateControl := range selected.Controls {
		control := templateControl
		control.ID = newID("ctrl")
		control.TenantID = actor.TenantID
		control.FrameworkID = framework.ID
		control.SchemaVersion = domain.SecurityControlSchemaVersion
		control.CreatedAt = l.now()
		controls = append(controls, control)
	}
	if l.unitOfWork != nil {
		var entry domain.AuditChainEntry
		if err := l.ExecuteUnitOfWork(ctx, func(ctx context.Context, repos Repositories) error {
			if err := repos.Controls.InsertControlFramework(ctx, framework); err != nil {
				return err
			}
			for _, control := range controls {
				if err := repos.Controls.InsertSecurityControl(ctx, control); err != nil {
					return err
				}
			}
			var err error
			entry, err = repos.Audit.Append(ctx, newUnitOfWorkAuditEntry(framework.CreatedAt, actor.TenantID, "control_framework_template.installed", "control_framework", framework.ID, actorType(actor), actorID(actor), "", ""))
			return err
		}); err != nil {
			return domain.ControlFramework{}, err
		}
		l.frameworks[framework.ID] = framework
		for _, control := range controls {
			l.controls[control.ID] = control
		}
		l.publishCommittedAuditEntryLocked(entry)
		return framework, nil
	}
	l.frameworks[framework.ID] = framework
	for _, control := range controls {
		l.controls[control.ID] = control
	}
	_, _ = l.appendChainLocked(actor.TenantID, "control_framework_template.installed", "control_framework", framework.ID, actorType(actor), actorID(actor), "", "")
	if err := l.persistLocked(ctx); err != nil {
		return domain.ControlFramework{}, err
	}
	return framework, nil
}
