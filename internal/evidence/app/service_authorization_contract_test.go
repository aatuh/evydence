package app

import (
	"errors"
	"reflect"
	"testing"

	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/authz"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
)

func TestGenericEvidenceReadsUseTypedReadOnlyCoordinates(t *testing.T) {
	for _, operation := range []string{"get", "list", "lifecycle"} {
		t.Run(operation, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			item := f.mutableEvidence("evidence", "product", testDigest('a'))
			item.ProjectID, item.ReleaseID, item.BuildID, item.DeploymentID = "project", "release", "build", "deployment"
			f.reader.evidence[item.ID] = item
			action := authz.ActionEvidenceRead
			var err error
			switch operation {
			case "get":
				got, runErr := f.service.GetEvidence(t.Context(), f.actor, item.ID)
				err = runErr
				if got.ID != item.ID || got.BuildID != item.BuildID || got.DeploymentID != item.DeploymentID {
					t.Error("read lost evidence provenance")
				}
			case "list":
				got, runErr := f.service.ListEvidence(t.Context(), f.actor, "", "")
				err = runErr
				if len(got) != 1 || got[0].ID != item.ID || got[0].BuildID != item.BuildID || got[0].DeploymentID != item.DeploymentID {
					t.Error("list lost evidence provenance")
				}
			case "lifecycle":
				action = authz.ActionEvidenceLifecycleRead
				_, err = f.service.ListLifecycleEvents(t.Context(), f.actor, item.ID)
			}
			want := []application.AuthorizationRequest{{Action: action, ScopeOnly: true}, {Action: action, Resources: application.ResourceReferences{ProductID: item.ProductID, ProjectID: item.ProjectID, ReleaseID: item.ReleaseID}}}
			if err != nil || !reflect.DeepEqual(f.authorizer.requests, want) {
				t.Fatal("read selected scope strings or write-only coordinates", err, f.authorizer.requests)
			}
		})
	}
}

func TestGenericDiffRechecksItsOwnActionInsideTransactionBeforeEffects(t *testing.T) {
	for _, kind := range []string{"sbom", "contract"} {
		t.Run(kind, func(t *testing.T) {
			f := newEvidenceServiceFixture(t)
			f.actor.Scopes = []string{"evidence:read"}
			begun := 0
			f.transactions.beforeExecute = func() { begun++; f.actor.Scopes[0] = "revoked" }
			f.authorizer.authorize = func(r application.AuthorizationRequest) error {
				if r.Action != authz.ActionEvidenceDiffsCreate || r.Scope != "" {
					t.Error("diff borrowed a sibling scope/action", r)
					return ErrForbidden
				}
				mode := authz.ResolvedEvaluation
				if r.ScopeOnly {
					mode = authz.ScopeEvaluation
				}
				return authz.Authorize(t.Context(), f.actor, authz.Request{Action: r.Action, Resources: r.Resources, Evaluation: mode})
			}
			var err error
			if kind == "sbom" {
				for _, id := range []string{"base", "target"} {
					v := evidencedomain.SBOM{ID: id, TenantID: f.actor.TenantID, ArtifactID: "artifact-" + id}
					f.reader.sboms[id], f.transactions.state.sboms[id] = v, v
				}
				var got evidencedomain.SBOMDiff
				got, err = f.service.CreateSBOMDiff(t.Context(), f.actor, CreateSBOMDiffInput{BaseSBOMID: "base", TargetSBOMID: "target"})
				if got.ID != "" {
					t.Error("denied diff returned receipt")
				}
			} else {
				for _, id := range []string{"base", "target"} {
					v := evidencedomain.OpenAPIContract{ID: id, TenantID: f.actor.TenantID, ProductID: "product"}
					f.reader.contracts[id], f.transactions.state.contracts[id] = v, v
				}
				var got evidencedomain.ContractDiff
				got, err = f.service.CreateContractDiff(t.Context(), f.actor, CreateContractDiffInput{BaseContractID: "base", TargetContractID: "target"})
				if got.ID != "" {
					t.Error("denied diff returned receipt")
				}
			}
			if !errors.Is(err, ErrForbidden) || begun != 1 || f.transactions.commits != 0 || len(f.transactions.state.sbomDiffs)+len(f.transactions.state.contractDiffs)+len(f.transactions.state.audit) != 0 {
				t.Fatal("transaction admitted stale diff authority", err, begun, f.transactions.commits)
			}
		})
	}
}
