package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestVerificationReadTransportRequiresFocusedPorts(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "router.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ handler, port string }{
		{"verifyAuditChain", "auditChainVerification"},
		{"verifyMerkleBatch", "merkleVerification"},
		{"verifyBackupManifest", "backupVerification"},
		{"signingCustodyReviewReport", "signingCustodyQuery"},
		{"listSigningKeys", "signingKeyQuery"},
		{"listAuditLog", "auditLogQuery"},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			found, focused := false, 0
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != tc.handler {
					continue
				}
				found = true
				ast.Inspect(function.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "verification", "writeCreatedAtPaginated", "writeCreatedAtPaginatedWithLegacyLimit":
						t.Errorf("%s retains broad verification read %s", tc.handler, selector.Sel.Name)
					case tc.port:
						focused++
					}
					return true
				})
			}
			if !found || focused != 1 {
				t.Errorf("%s found=%t focused references=%d, want true and one", tc.handler, found, focused)
			}
		})
	}
	file, err = parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		typeSpec, ok := node.(*ast.TypeSpec)
		if !ok || typeSpec.Name.Name != "verificationService" {
			return true
		}
		iface, ok := typeSpec.Type.(*ast.InterfaceType)
		if !ok {
			t.Fatal("broad Verification type is not an interface")
		}
		for _, field := range iface.Methods.List {
			for _, name := range field.Names {
				if name.Name == "VerifyMerkleBatch" || name.Name == "SigningCustodyReviewReport" || name.Name == "VerifyBackupManifest" || name.Name == "ListSigningKeys" {
					t.Errorf("broad Verification interface retains retired read %s", name.Name)
				}
			}
		}
		return false
	})
}

func TestLegacyAuditInventoryPaginationWrapperIsRetired(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "pagination.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "writeCreatedAtPaginatedWithLegacyLimit" {
			t.Fatal("obsolete legacy audit inventory pagination wrapper is retained")
		}
	}
}
