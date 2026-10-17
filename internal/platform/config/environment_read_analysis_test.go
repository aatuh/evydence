package config

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
)

// This deliberately small source guard resolves finite names, not arbitrary Go.
// Unsupported expressions and escaping readers fail rather than imply coverage.
var errUnresolvedEnvironmentRead = errors.New("environment read needs explicit source review")

type environmentReadScope struct {
	file       *ast.File
	root       ast.Node
	function   *ast.FuncDecl
	parameters map[string]int
	readers    map[string]bool
	bindings   map[string][]ast.Expr
	calls      []*ast.CallExpr
}

type environmentReadAnalysis struct {
	imports   map[*ast.File]map[string]string
	parents   map[ast.Node]ast.Node
	globals   map[string][]ast.Expr
	mutable   map[string]bool
	functions map[string]*environmentReadScope
	scopes    []*environmentReadScope
	forwarded map[string]bool
}

func environmentReadNames(files map[string]string) ([]string, error) {
	a := environmentReadAnalysis{
		imports: map[*ast.File]map[string]string{}, parents: map[ast.Node]ast.Node{},
		globals: map[string][]ast.Expr{}, mutable: map[string]bool{}, functions: map[string]*environmentReadScope{},
		forwarded: map[string]bool{},
	}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		file, err := parser.ParseFile(token.NewFileSet(), name, files[name], 0)
		if err != nil {
			return nil, err
		}
		a.imports[file] = map[string]string{}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, err
			}
			name := path
			for i := len(path) - 1; i >= 0; i-- {
				if path[i] == '/' {
					name = path[i+1:]
					break
				}
			}
			if spec.Name != nil {
				name = spec.Name.Name
			}
			if name == "." && path == "os" {
				return nil, errUnresolvedEnvironmentRead
			}
			a.imports[file][name] = path
		}
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) != 0 {
				a.parents[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			return true
		})
		for _, decl := range file.Decls {
			s := &environmentReadScope{file: file, root: decl, parameters: map[string]int{}, readers: map[string]bool{}, bindings: map[string][]ast.Expr{}}
			if fn, ok := decl.(*ast.FuncDecl); ok {
				s.function = fn
				s.root = fn.Body
				if fn.Body == nil {
					continue
				}
				index := 0
				for _, field := range fn.Type.Params.List {
					for _, name := range field.Names {
						s.parameters[name.Name] = index
						s.readers[name.Name] = isEnvironmentReaderType(field.Type)
						index++
					}
				}
				if fn.Recv == nil {
					a.functions[fn.Name.Name] = s
				}
			}
			ast.Inspect(s.root, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CallExpr:
					s.calls = append(s.calls, n)
				case *ast.ValueSpec:
					for i, name := range n.Names {
						var value ast.Expr
						if len(n.Values) == len(n.Names) {
							value = n.Values[i]
						}
						s.bindings[name.Name] = append(s.bindings[name.Name], value)
					}
				case *ast.AssignStmt:
					for i, left := range n.Lhs {
						name, ok := left.(*ast.Ident)
						if !ok {
							continue
						}
						var value ast.Expr
						if len(n.Rhs) == len(n.Lhs) {
							value = n.Rhs[i]
						}
						s.bindings[name.Name] = append(s.bindings[name.Name], value)
					}
				case *ast.RangeStmt:
					if name, ok := n.Value.(*ast.Ident); ok {
						s.bindings[name.Name] = append(s.bindings[name.Name], n.X)
					}
				}
				return true
			})
			if s.function == nil {
				for name, values := range s.bindings {
					a.globals[name] = append(a.globals[name], values...)
					if decl, ok := decl.(*ast.GenDecl); ok && decl.Tok == token.VAR {
						a.mutable[name] = true
					}
				}
			}
			a.scopes = append(a.scopes, s)
		}
	}
	names := map[string]bool{}
	for _, s := range a.scopes {
		var scopeErr error
		ast.Inspect(s.root, func(n ast.Node) bool {
			if name, ok := n.(*ast.Ident); ok && s.readers[name.Name] && !a.readerUseIsBounded(s, name) {
				scopeErr = errUnresolvedEnvironmentRead
			}
			selector, ok := n.(*ast.SelectorExpr)
			if !ok || a.importPath(s, selector) != "os" || (selector.Sel.Name != "Getenv" && selector.Sel.Name != "LookupEnv" && selector.Sel.Name != "Environ") {
				return true
			}
			call, ok := a.parents[selector].(*ast.CallExpr)
			if !ok || (call.Fun != selector && !a.reviewedReaderForward(s, call, selector)) || (call.Fun == selector && selector.Sel.Name == "Environ") {
				scopeErr = errUnresolvedEnvironmentRead
			}
			return true
		})
		if scopeErr != nil {
			return nil, scopeErr
		}
		for _, call := range s.calls {
			reader := false
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
				reader = a.importPath(s, selector) == "os" && (selector.Sel.Name == "Getenv" || selector.Sel.Name == "LookupEnv")
			}
			if name, ok := call.Fun.(*ast.Ident); ok {
				reader = reader || s.readers[name.Name]
			}
			if !reader {
				continue
			}
			if len(call.Args) != 1 {
				return nil, errUnresolvedEnvironmentRead
			}
			values, err := a.resolve(s, call.Args[0], 0)
			if err != nil {
				return nil, err
			}
			for _, value := range values {
				names[value] = true
			}
		}
	}
	// A known direct call does not excuse an additional function-value escape.
	for node, parent := range a.parents {
		name, ok := node.(*ast.Ident)
		if !ok || !a.forwarded[name.Name] {
			continue
		}
		if decl, ok := parent.(*ast.FuncDecl); ok && decl.Name == name {
			continue
		}
		if call, ok := parent.(*ast.CallExpr); ok && call.Fun == name {
			continue
		}
		return nil, errUnresolvedEnvironmentRead
	}
	return slices.Sorted(maps.Keys(names)), nil
}

func (a *environmentReadAnalysis) readerUseIsBounded(s *environmentReadScope, name *ast.Ident) bool {
	if len(s.bindings[name.Name]) != 0 {
		return false
	}
	switch parent := a.parents[name].(type) {
	case *ast.CallExpr:
		if parent.Fun == name {
			return true
		}
		callee, ok := parent.Fun.(*ast.Ident)
		if !ok || a.functions[callee.Name] == nil || len(s.bindings[callee.Name]) != 0 {
			return false
		}
		target := a.functions[callee.Name]
		for parameter, index := range target.parameters {
			if target.readers[parameter] && index < len(parent.Args) && parent.Args[index] == name {
				return true
			}
		}
	case *ast.BinaryExpr:
		if parent.Op != token.EQL && parent.Op != token.NEQ {
			return false
		}
		other := parent.X
		if other == name {
			other = parent.Y
		}
		identifier, ok := other.(*ast.Ident)
		return ok && identifier.Name == "nil"
	}
	return false
}

func (a *environmentReadAnalysis) rangeListDoesNotEscape(name string) bool {
	for node, parent := range a.parents {
		identifier, ok := node.(*ast.Ident)
		if !ok || identifier.Name != name {
			continue
		}
		if declaration, ok := parent.(*ast.ValueSpec); ok && slices.Contains(declaration.Names, identifier) {
			continue
		}
		if loop, ok := parent.(*ast.RangeStmt); ok && loop.X == identifier {
			continue
		}
		return false
	}
	return true
}

func isEnvironmentReaderType(expr ast.Expr) bool {
	f, ok := expr.(*ast.FuncType)
	if !ok || len(f.Params.List) != 1 || len(f.Params.List[0].Names) > 1 || f.Results == nil || len(f.Results.List) != 1 {
		return false
	}
	arg, argOK := f.Params.List[0].Type.(*ast.Ident)
	result, resultOK := f.Results.List[0].Type.(*ast.Ident)
	return argOK && resultOK && arg.Name == "string" && result.Name == "string"
}

func (a *environmentReadAnalysis) importPath(s *environmentReadScope, selector *ast.SelectorExpr) string {
	if name, ok := selector.X.(*ast.Ident); ok {
		return a.imports[s.file][name.Name]
	}
	return ""
}

func (a *environmentReadAnalysis) reviewedReaderForward(s *environmentReadScope, call *ast.CallExpr, reader *ast.SelectorExpr) bool {
	callee, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	// Existing startup logging and configuration-freshness boundaries only.
	// EVY-1216 retires ambient reads; this guard does not authorize new shims.
	path := a.importPath(s, callee)
	if reader.Sel.Name == "Getenv" && path == "github.com/aatuh/evydence/internal/platform/logging" && callee.Sel.Name == "Run" {
		return len(call.Args) == 6 && call.Args[4] == reader
	}
	return reader.Sel.Name == "Environ" && path == "github.com/aatuh/evydence/internal/platform/confighealth" && callee.Sel.Name == "New" && len(call.Args) == 2 && call.Args[1] == reader
}

func (a *environmentReadAnalysis) resolve(s *environmentReadScope, expr ast.Expr, depth int) ([]string, error) {
	if depth > 32 || expr == nil {
		return nil, errUnresolvedEnvironmentRead
	}
	switch expr := expr.(type) {
	case *ast.BasicLit:
		if expr.Kind == token.STRING {
			value, err := strconv.Unquote(expr.Value)
			return []string{value}, err
		}
	case *ast.ParenExpr:
		return a.resolve(s, expr.X, depth+1)
	case *ast.BinaryExpr:
		if expr.Op != token.ADD {
			break
		}
		left, err := a.resolve(s, expr.X, depth+1)
		if err != nil {
			return nil, err
		}
		right, err := a.resolve(s, expr.Y, depth+1)
		if err != nil || len(left)*len(right) > 256 {
			return nil, errUnresolvedEnvironmentRead
		}
		var values []string
		for _, l := range left {
			for _, r := range right {
				if len(l)+len(r) > maxEnvironmentName {
					return nil, errUnresolvedEnvironmentRead
				}
				values = append(values, l+r)
			}
		}
		return values, nil
	case *ast.CompositeLit:
		var values []string
		for _, item := range expr.Elts {
			items, err := a.resolve(s, item, depth+1)
			if err != nil || len(values)+len(items) > 256 {
				return nil, errUnresolvedEnvironmentRead
			}
			values = append(values, items...)
		}
		return values, nil
	case *ast.Ident:
		if index, ok := s.parameters[expr.Name]; ok {
			if len(s.bindings[expr.Name]) != 0 || s.function == nil || s.function.Recv != nil {
				return nil, errUnresolvedEnvironmentRead
			}
			a.forwarded[s.function.Name.Name] = true
			var values []string
			for _, caller := range a.scopes {
				for _, call := range caller.calls {
					name, ok := call.Fun.(*ast.Ident)
					if !ok || name.Name != s.function.Name.Name {
						continue
					}
					if index >= len(call.Args) || len(caller.bindings[name.Name]) != 0 {
						return nil, errUnresolvedEnvironmentRead
					}
					items, err := a.resolve(caller, call.Args[index], depth+1)
					if err != nil || len(values)+len(items) > 256 {
						return nil, errUnresolvedEnvironmentRead
					}
					values = append(values, items...)
				}
			}
			if len(values) != 0 {
				return values, nil
			}
			break
		}
		bindings := s.bindings[expr.Name]
		if len(bindings) == 0 {
			bindings = a.globals[expr.Name]
			if a.mutable[expr.Name] && !a.rangeListDoesNotEscape(expr.Name) {
				return nil, errUnresolvedEnvironmentRead
			}
			// Global constant initializers have their declaration's lexical scope,
			// not the local bindings of whichever function uses the constant.
			s = &environmentReadScope{}
		}
		if len(bindings) == 1 {
			return a.resolve(s, bindings[0], depth+1)
		}
	}
	return nil, errUnresolvedEnvironmentRead
}
