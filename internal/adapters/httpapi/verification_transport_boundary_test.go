package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestVerificationTransportHasNoBroadDependency(t *testing.T) {
	if _, exists := reflect.TypeFor[Server]().FieldByName("verification"); exists {
		t.Error("Server retains the retired broad Verification binding")
	}
	dependencies, err := parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(dependencies, func(node ast.Node) bool {
		if spec, ok := node.(*ast.TypeSpec); ok && spec.Name.Name == "verificationService" {
			t.Error("retired broad Verification interface still exists")
		}
		return true
	})
	for _, tc := range []struct {
		file, handler, port string
		focused, durable    int
	}{
		{"subject_verification.go", "verifySubject", "subjectVerification", 2, 1},
		{"release_bundle_verification.go", "verifyReleaseBundleResult", "releaseBundleVerification", 1, 0},
		{"dsse_verification.go", "verifyBuildAttestationSignature", "dsseVerification", 2, 1},
		{"cosign_verification.go", "verifyCosignSignature", "cosignVerification", 2, 1},
		{"backup_generation.go", "generateBackupManifest", "backupGenerationCommands", 2, 1},
		{"merkle_creation.go", "createMerkleBatch", "merkleCreationCommands", 2, 1},
		{"transparency_checkpoint_commands.go", "createTransparencyCheckpoint", "transparencyCheckpointCommands", 2, 1},
		{"retention_commands.go", "createObjectRetentionPolicy", "retentionCommands", 2, 1},
		{"retention_commands.go", "verifyObjectRetentionPolicy", "retentionCommands", 2, 1},
	} {
		t.Run(tc.handler, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tc.file, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			found, focused, durable := false, 0, 0
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
					case "ledger", "verification", "createWithActorFingerprint", "createWithActor", "create":
						t.Errorf("%s retains broad verification path %s", tc.handler, selector.Sel.Name)
					case tc.port:
						focused++
					case "createDurable":
						durable++
					}
					return true
				})
			}
			if !found || focused != tc.focused || durable != tc.durable {
				t.Errorf("%s found=%t focused=%d durable=%d, want true/%d/%d", tc.handler, found, focused, durable, tc.focused, tc.durable)
			}
		})
	}
}
