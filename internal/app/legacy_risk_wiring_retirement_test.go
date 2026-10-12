package app

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// Risk commands use focused runtime services. Historical aggregate readers,
// mutable transactions and service construction must stay in test oracles.
func TestLegacyRiskAggregateWiringIsAbsentFromProduction(t *testing.T) {
	retired := map[string]bool{
		"configureRiskCommands": true, "legacyRiskCommands": true,
		"ledgerRiskProjectionRefresher": true, "ledgerRiskReader": true,
		"ledgerRiskTransactions": true, "ledgerRiskTransaction": true,
		"newLedgerRiskTransaction": true, "resolveRiskFindingLocked": true,
		"getRiskProductLocked": true, "getRiskReleaseLocked": true,
		"getRiskEvidenceLocked": true, "getRiskVEXLocked": true,
		"getRiskControlLocked": true, "validateRiskSupportingReferenceLocked": true,
		"resolveRiskGovernanceSubjectLocked": true,
		"listRiskDecisionsLocked":            true, "listRiskExceptionsLocked": true,
		"exceptionToRiskContext": true, "exceptionFromRiskContext": true,
		"waiverToRiskContext": true, "waiverFromRiskContext": true,
		"approvalFromRiskContext": true, "policyEvaluationFromRiskContext": true,
		"policyEvaluationToRiskContext": true, "cloneRiskWaiverMap": true,
		"cloneRiskApprovalMap": true, "cloneRiskPolicyEvaluationMap": true,
		"cloneRiskExceptionMap": true, "sameExceptionApproval": true,
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
			switch v := node.(type) {
			case *ast.TypeSpec:
				if retired[v.Name.Name] {
					t.Errorf("%s retains aggregate Risk type %s", name, v.Name.Name)
				}
			case *ast.FuncDecl:
				if retired[v.Name.Name] {
					t.Errorf("%s retains aggregate Risk function %s", name, v.Name.Name)
				}
			case *ast.Ident:
				if v.Name == "riskCommands" {
					t.Errorf("%s retains aggregate Risk service field or access", name)
				}
			}
			return true
		})
	}
	if inspected == 0 {
		t.Fatal("no production application source inspected")
	}
}
