package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestSigningAdministrationTransportRequiresFocusedPorts(t *testing.T) {
	for _, tc := range []struct{ file, handler, port string }{
		{"signing_key_commands.go", "rotateSigningKey", "signingKeyCommands"},
		{"signing_key_commands.go", "revokeSigningKey", "signingKeyCommands"},
		{"trust_configuration_commands.go", "createSigningProvider", "trustConfigurationCommands"},
		{"trust_configuration_commands.go", "createDSSETrustRoot", "trustConfigurationCommands"},
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
						t.Errorf("%s retains broad signing administration path %s", tc.handler, selector.Sel.Name)
					case tc.port:
						focused++
					case "createDurable":
						durable++
					}
					return true
				})
			}
			if !found || focused != 2 || durable != 1 {
				t.Errorf("%s found=%t focused=%d durable=%d, want true/2/1", tc.handler, found, focused, durable)
			}
		})
	}
	file, err := parser.ParseFile(token.NewFileSet(), "context_dependencies.go", nil, parser.SkipObjectResolution)
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
				switch name.Name {
				case "RotateSigningKey", "AuthorizeSigningKeyRevocation", "RevokeSigningKeyWithPolicy", "CreateSigningProvider", "CreateDSSETrustRoot":
					t.Errorf("broad Verification interface retains retired administration method %s", name.Name)
				}
			}
		}
		return false
	})
}
