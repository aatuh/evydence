package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	riskapp "github.com/aatuh/evydence/internal/risk/app"
	riskdomain "github.com/aatuh/evydence/internal/risk/domain"
)

type controlNativeLinkReader interface {
	riskapp.ControlEvidenceReader
	riskapp.ControlEvidenceArtifactGrantReader
}
type controlNativeFixtureTransactions struct {
	catalogFixtureCommands
	readOnly bool
}
type controlNativeFixtureTransaction struct {
	creation   riskapp.ControlCreationReader
	template   riskapp.ControlTemplateReader
	links      controlNativeLinkReader
	repos      app.Repositories
	authorizer application.Authorizer
	readOnly   bool
}

func controlFixtureCoreError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return riskapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return riskapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return riskapp.ErrConflict
	default:
		return err
	}
}
func (f controlNativeFixtureTransactions) execute(ctx context.Context, kind string, run func(context.Context, controlNativeFixtureTransaction) error) error {
	if ctx == nil || run == nil {
		return riskapp.ErrValidation
	}
	return controlFixtureCoreError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Controls == nil || r.Audit == nil {
			return app.ErrValidation
		}
		tx := controlNativeFixtureTransaction{repos: r, readOnly: f.readOnly, authorizer: riskapp.NewControlAdminAuthorizer()}
		var ok bool
		switch kind {
		case "creation":
			tx.creation, ok = r.Controls.(riskapp.ControlCreationReader)
		case "template":
			tx.template, ok = r.Controls.(riskapp.ControlTemplateReader)
		case "link":
			tx.links, ok = r.Controls.(controlNativeLinkReader)
			if ok {
				var err error
				tx.authorizer, err = riskapp.NewControlEvidenceWriteAuthorizer(tx.links)
				if err != nil {
					return err
				}
			}
		default:
			return app.ErrValidation
		}
		if !ok {
			return app.ErrValidation
		}
		return run(ctx, tx)
	}))
}
func (f controlNativeFixtureTransactions) ExecuteControls(ctx context.Context, run func(context.Context, riskapp.ControlTransaction) error) error {
	return f.execute(ctx, "creation", func(ctx context.Context, tx controlNativeFixtureTransaction) error { return run(ctx, tx) })
}
func (f controlNativeFixtureTransactions) ExecuteControlTemplate(ctx context.Context, run func(context.Context, riskapp.ControlTemplateTransaction) error) error {
	return f.execute(ctx, "template", func(ctx context.Context, tx controlNativeFixtureTransaction) error { return run(ctx, tx) })
}
func (f controlNativeFixtureTransactions) ExecuteControlEvidence(ctx context.Context, run func(context.Context, riskapp.ControlEvidenceTransaction) error) error {
	return f.execute(ctx, "link", func(ctx context.Context, tx controlNativeFixtureTransaction) error { return run(ctx, tx) })
}
func (f controlNativeFixtureTransactions) ControlEvidenceArtifactVisible(ctx context.Context, req riskapp.ControlEvidenceArtifactGrantRequest) (bool, error) {
	var visible bool
	err := f.execute(ctx, "link", func(ctx context.Context, tx controlNativeFixtureTransaction) error {
		var err error
		visible, err = tx.links.ControlEvidenceArtifactVisible(ctx, req)
		return err
	})
	if err != nil {
		return false, err
	}
	return visible, nil
}
func (tx controlNativeFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return tx.authorizer.Authorize(ctx, a, r)
}
func (tx controlNativeFixtureTransaction) LockControlCreationTenant(ctx context.Context, tenant string) error {
	return controlFixtureCoreError(tx.creation.LockControlCreationTenant(ctx, tenant))
}
func (tx controlNativeFixtureTransaction) LockControlTemplateTenant(ctx context.Context, tenant string) error {
	return controlFixtureCoreError(tx.template.LockControlTemplateTenant(ctx, tenant))
}
func (tx controlNativeFixtureTransaction) FrameworkVersionExists(ctx context.Context, tenant, slug, version string) (bool, error) {
	if tx.readOnly {
		panic("control preflight read duplicate version metadata")
	}
	var reader riskapp.FrameworkVersionReader = tx.creation
	if tx.template != nil {
		reader = tx.template
	}
	v, err := reader.FrameworkVersionExists(ctx, tenant, slug, version)
	return v, controlFixtureCoreError(err)
}
func (tx controlNativeFixtureTransaction) ControlFrameworkExists(ctx context.Context, tenant, id string) (bool, error) {
	v, err := tx.creation.ControlFrameworkExists(ctx, tenant, id)
	return v, controlFixtureCoreError(err)
}
func (tx controlNativeFixtureTransaction) SecurityControlCodeExists(ctx context.Context, tenant, id, code string) (bool, error) {
	if tx.readOnly {
		panic("control preflight read duplicate code metadata")
	}
	v, err := tx.creation.SecurityControlCodeExists(ctx, tenant, id, code)
	return v, controlFixtureCoreError(err)
}
func (tx controlNativeFixtureTransaction) LockControlEvidenceTenant(ctx context.Context, tenant string) error {
	return controlFixtureCoreError(tx.links.LockControlEvidenceTenant(ctx, tenant))
}
func (tx controlNativeFixtureTransaction) ControlEvidenceControlExists(ctx context.Context, tenant, id string) (bool, error) {
	v, err := tx.links.ControlEvidenceControlExists(ctx, tenant, id)
	return v, controlFixtureCoreError(err)
}
func (tx controlNativeFixtureTransaction) ReadControlEvidenceSubject(ctx context.Context, tenant string, key riskapp.ControlEvidenceSubjectKey) (riskapp.ControlEvidenceSubjectCoordinates, error) {
	v, err := tx.links.ReadControlEvidenceSubject(ctx, tenant, key)
	return v, controlFixtureCoreError(err)
}
func (tx controlNativeFixtureTransaction) ReadControlEvidenceLink(ctx context.Context, tenant string, key riskapp.ControlEvidenceLinkKey) (riskdomain.ControlEvidence, bool, error) {
	if tx.readOnly {
		panic("link preflight read duplicate metadata")
	}
	v, found, err := tx.links.ReadControlEvidenceLink(ctx, tenant, key)
	return v, found, controlFixtureCoreError(err)
}
func (tx controlNativeFixtureTransaction) InsertControlFramework(ctx context.Context, v riskdomain.ControlFramework) error {
	if tx.readOnly || tx.links != nil {
		panic("control preflight or link command inserted framework")
	}
	return controlFixtureCoreError(tx.repos.Controls.InsertControlFramework(ctx, domain.ControlFramework(v)))
}
func (tx controlNativeFixtureTransaction) InsertSecurityControl(ctx context.Context, v riskdomain.SecurityControl) error {
	if tx.readOnly || tx.links != nil {
		panic("control preflight or link command inserted definition")
	}
	return controlFixtureCoreError(tx.repos.Controls.InsertSecurityControl(ctx, securityControlFromQuery(v)))
}
func (tx controlNativeFixtureTransaction) InsertControlEvidence(ctx context.Context, v riskdomain.ControlEvidence) error {
	if tx.readOnly || tx.links == nil {
		panic("control preflight or creation command inserted link")
	}
	return controlFixtureCoreError(tx.repos.Controls.InsertControlEvidence(ctx, domain.ControlEvidence(v)))
}
func (tx controlNativeFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	if tx.readOnly {
		panic("control preflight appended audit")
	}
	v, err := (governanceFixtureTransaction{audit: tx.repos.Audit}).AppendAudit(ctx, e)
	return v, controlFixtureCoreError(err)
}
func (f controlFixtureCommands) nativeClockIDs(readOnly bool) (application.Clock, application.IDGenerator) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly {
		clock = application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
		if f.clock != nil {
			clock = f.clock
		}
	}
	return clock, ids
}
func (f controlFixtureCommands) nativeControls(readOnly bool) (*riskapp.ControlCommands, error) {
	clock, ids := f.nativeClockIDs(readOnly)
	return riskapp.NewControlCommands(riskapp.ControlCommandConfig{Authorizer: riskapp.NewControlAdminAuthorizer(), Transactions: controlNativeFixtureTransactions{f.catalogFixtureCommands, readOnly}, Clock: clock, IDs: ids})
}
func (f controlFixtureCommands) nativeTemplate(readOnly bool) (*riskapp.ControlTemplateCommands, error) {
	clock, ids := f.nativeClockIDs(readOnly)
	return riskapp.NewControlTemplateCommands(riskapp.ControlTemplateCommandConfig{Authorizer: riskapp.NewControlAdminAuthorizer(), Transactions: controlNativeFixtureTransactions{f.catalogFixtureCommands, readOnly}, Clock: clock, IDs: ids})
}
func (f controlFixtureCommands) nativeLink(readOnly bool) (*riskapp.ControlEvidenceCommands, error) {
	clock, ids := f.nativeClockIDs(readOnly)
	tx := controlNativeFixtureTransactions{f.catalogFixtureCommands, readOnly}
	a, err := riskapp.NewControlEvidenceWriteAuthorizer(tx)
	if err != nil {
		return nil, err
	}
	return riskapp.NewControlEvidenceCommands(riskapp.ControlEvidenceCommandConfig{Authorizer: a, Transactions: tx, Clock: clock, IDs: ids})
}
