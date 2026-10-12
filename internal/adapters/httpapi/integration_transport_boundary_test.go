package httpapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

func TestIntegrationTransportHasNoAggregateFallback(t *testing.T) {
	for path, handlers := range map[string][]string{
		"router.go":                     {"createCollector", "recordCollectorRelease", "createCommercialCollector", "listCollectors", "collectorHealthReport", "listCommercialCollectors", "listSourceRepositories"},
		"source_repository_commands.go": {"createSourceRepository"},
		"source_commit_commands.go":     {"recordSourceCommit"},
		"source_branch_commands.go":     {"upsertSourceBranch"},
		"pull_request_commands.go":      {"recordPullRequest"},
		"source_snapshot_commands.go":   {"recordSourceSnapshot"},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, handler := range handlers {
			found := false
			for _, declaration := range file.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if !ok {
					continue
				}
				switch fn.Name.Name {
				case "localSourceRepositoryInput", "localSourceCommitInput", "localSourceBranchInput", "localPullRequestInput":
					t.Errorf("obsolete aggregate mapper %s remains in %s", fn.Name.Name, path)
				}
				if fn.Name.Name != handler {
					continue
				}
				found = true
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					selector, ok := node.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					owner, ok := selector.X.(*ast.Ident)
					if !ok || owner.Name != "s" {
						return true
					}
					switch selector.Sel.Name {
					case "ledger", "create", "createWithActorFingerprint":
						t.Errorf("%s retains aggregate transport path %s", handler, selector.Sel.Name)
					}
					return true
				})
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					branch, ok := node.(*ast.IfStmt)
					if !ok {
						return true
					}
					ast.Inspect(branch.Cond, func(node ast.Node) bool {
						selector, ok := node.(*ast.SelectorExpr)
						if !ok {
							return true
						}
						switch selector.Sel.Name {
						case "collectorCommands", "collectorQuery", "collectorHealthQuery", "commercialCollectorQuery", "sourceRepositoryQuery", "sourceRepositoryCommands", "sourceCommitCommands", "sourceBranchCommands", "pullRequestCommands", "sourceSnapshotCommands":
							t.Errorf("%s retains optional dependency branch %s", handler, selector.Sel.Name)
						}
						return true
					})
					return true
				})
			}
			if !found {
				t.Errorf("handler %s missing from %s", handler, path)
			}
		}
	}
}
