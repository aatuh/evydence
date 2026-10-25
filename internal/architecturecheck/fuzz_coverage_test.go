package architecturecheck

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// This floor protects the foundational input families, independently of a
// campaign runner's target discovery. Executed seeds and campaigns remain the
// behavioral evidence; a source declaration alone cannot establish a pass.
type fuzzCoverageTarget struct {
	file string
	name string
}

func TestFoundationalFuzzCoverage(t *testing.T) {
	assertSeededFuzzCoverage(t, []fuzzCoverageTarget{
		{"internal/application/normalized_json_fuzz_test.go", "FuzzNormalizedJSONHashStable"},
		{"internal/platform/jsonbounds/fuzz_test.go", "FuzzBoundedJSONRoundTrip"},
		{"internal/platform/jsonbounds/fuzz_test.go", "FuzzDuplicateJSONKeys"},
		{"internal/app/identity_fuzz_test.go", "FuzzObjectPayloadKeyRoundTrip"},
		{"internal/app/identity_fuzz_test.go", "FuzzParseObjectPayloadKey"},
		{"internal/app/identity_fuzz_test.go", "FuzzIdempotencyRecordKeyRoundTrip"},
		{"internal/app/identity_fuzz_test.go", "FuzzParseIdempotencyRecordKey"},
	})
}

func TestEvidenceParserFuzzCoverage(t *testing.T) {
	assertSeededFuzzCoverage(t, []fuzzCoverageTarget{
		{"internal/app/parsers/cyclonedx/parser_test.go", "FuzzCycloneDX"},
		{"internal/app/parsers/spdx/fuzz_test.go", "FuzzSPDX"},
		{"internal/app/parsers/vex/parser_test.go", "FuzzVEX"},
		{"internal/app/parsers/scanners/parser_test.go", "FuzzParseBounded"},
		{"internal/app/parsers/scanners/fuzz_test.go", "FuzzProbeReleaseID"},
		{"internal/app/openapi_fuzz_test.go", "FuzzOpenAPIContract"},
		{"cmd/evydence-worker/openapi_fuzz_test.go", "FuzzReplayedOpenAPIContract"},
	})
}

func TestVerificationFuzzCoverage(t *testing.T) {
	assertSeededFuzzCoverage(t, []fuzzCoverageTarget{
		{"internal/adapters/verification/dsse/fuzz_test.go", "FuzzDSSEEnvelope"},
		{"internal/adapters/verification/sigstore/fuzz_test.go", "FuzzSigstoreBundle"},
		{"internal/verification/app/integrity_fuzz_test.go", "FuzzMerkleBatchIntegrity"},
		{"internal/verification/app/integrity_fuzz_test.go", "FuzzReleaseBundleIntegrity"},
		{"internal/experimental/app/public_transparency_fuzz_test.go", "FuzzPublicTransparencyProof"},
		{"cmd/evydence/verification_fuzz_test.go", "FuzzCustomerPackageManifest"},
		{"cmd/evydence/verification_fuzz_test.go", "FuzzCustomerPackageArchive"},
		{"cmd/evydence/verification_fuzz_test.go", "FuzzReleaseManifest"},
	})
}

func assertSeededFuzzCoverage(t *testing.T, targets []fuzzCoverageTarget) {
	t.Helper()
	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			path := filepath.Join("..", "..", filepath.FromSlash(target.file))
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatalf("missing or invalid fuzz source %s: %v", target.file, err)
			}
			var function *ast.FuncDecl
			for _, declaration := range file.Decls {
				candidate, ok := declaration.(*ast.FuncDecl)
				if ok && candidate.Recv == nil && candidate.Name.Name == target.name {
					function = candidate
				}
			}
			if function == nil || function.Body == nil {
				t.Fatalf("missing fuzz target %s in %s", target.name, target.file)
			}
			seeded, fuzzed := false, false
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				receiver, ok := selector.X.(*ast.Ident)
				if !ok || receiver.Name != "f" {
					return true
				}
				seeded = seeded || selector.Sel.Name == "Add"
				fuzzed = fuzzed || selector.Sel.Name == "Fuzz"
				return true
			})
			if !seeded || !fuzzed {
				t.Fatalf("%s must register seeds and an executable fuzz callback", target.name)
			}
		})
	}
}
