package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

func TestLegacyLedgerLeafFacadesAreAbsentFromProduction(t *testing.T) {
	retired := map[string]bool{
		"HasTenants": true, "MissingEvidenceReport": true, "RevokeSigningKey": true,
		"SearchEvidence": true, "UploadAPISecurityScan": true,
		"UploadGitHubSourceSnapshot": true, "UploadGitLabSourceSnapshot": true,
		"UploadSPDXSBOM": true, "UploadBuildAttestationPayload": true,
		"ensureApprovalSubjectLocked": true, "ensureWaiverScopeLocked": true,
		"uploadSourceSnapshot": true, "sourceSnapshot": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "sourceSnapshot" {
					t.Errorf("%s retains retired aggregate source snapshot schema", name)
				}
			case *ast.FuncDecl:
				if !retired[value.Name.Name] || value.Recv == nil || len(value.Recv.List) != 1 {
					break
				}
				if receiver, ok := value.Recv.List[0].Type.(*ast.StarExpr); ok {
					if identifier, ok := receiver.X.(*ast.Ident); ok && identifier.Name == "Ledger" {
						t.Errorf("%s retains retired Ledger method %s", name, value.Name.Name)
					}
				}
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no production application source inspected")
	}
}

// Native portal commands, queries and token access belong to Package services.
// Historical aggregate behavior may remain an oracle for package-local tests,
// but must not be compiled into the production application surface.
func TestLegacyPortalAggregateSurfaceIsAbsentFromProduction(t *testing.T) {
	retired := map[string]bool{
		"CreateCustomerPortalAccessInput": true, "CustomerPortalAcceptanceInput": true,
		"customerPortalFailedAccessLimit": true, "customerPortalAuditEffect": true,
		"CreateCustomerPortalAccess": true, "ListCustomerPortalAccess": true,
		"RevokeCustomerPortalAccess": true, "currentPortalPackageLocked": true,
		"AccessCustomerPortalPackage": true, "AccessCustomerPortalPackageWithAcceptance": true,
		"accessCustomerPortalPackage": true, "persistCustomerPortalAccessUpdateLocked": true,
		"ExportCustomerPortalPackageArchive": true, "ExportCustomerPortalPackageArchiveWithAcceptance": true,
		"prepareLocalPortalAccess": true, "authorizePortalWriteLocked": true,
		"AuthorizeCustomerPortalAccessCreate": true, "AuthorizeCustomerPortalAccessRevoke": true,
		"packageWithDistributionWatermark": true, "portalReviewerLabel": true, "packageDistributionWatermark": true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		inspected++
		ast.Inspect(file, func(node ast.Node) bool {
			var declared string
			switch value := node.(type) {
			case *ast.FuncDecl:
				declared = value.Name.Name
			case *ast.TypeSpec:
				declared = value.Name.Name
			case *ast.ValueSpec:
				for _, identifier := range value.Names {
					if retired[identifier.Name] {
						t.Errorf("%s declares retired portal aggregate value %s", name, identifier.Name)
					}
				}
			}
			if retired[declared] {
				t.Errorf("%s declares retired portal aggregate surface %s", name, declared)
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no production application source inspected")
	}
}

// The retired wrappers merely held *Ledger and forwarded back into the same
// aggregate. They must not return as substitutes for context-owned services.
func TestLegacyLedgerServiceShellsAreRetired(t *testing.T) {
	retired := map[string]bool{
		"identityService":        true,
		"releaseEvidenceService": true,
		"packageReportService":   true,
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.TypeSpec:
				if retired[n.Name.Name] {
					t.Errorf("%s declares retired Ledger service shell %s", name, n.Name.Name)
				}
			case *ast.FuncDecl:
				if retired[n.Name.Name] || n.Name.Name == "NewLedger" || n.Name.Name == "ReleaseLedgerMutationFromState" {
					t.Errorf("%s declares retired Ledger helper %s", name, n.Name.Name)
				}
			case *ast.SelectorExpr:
				if retired[n.Sel.Name] {
					t.Errorf("%s calls retired Ledger service factory %s", name, n.Sel.Name)
				}
			}
			return true
		})
	}
}
