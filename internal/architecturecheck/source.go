// Package architecturecheck inspects Go source without compiling or executing it.
package architecturecheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

const maxSourceBytes = 8 << 20

// SourceFile describes non-test source, including files excluded by build tags.
type SourceFile struct {
	Path       string            `json:"path"`
	Package    string            `json:"package"`
	Imports    []SourceImport    `json:"imports"`
	Interfaces []PublicInterface `json:"interfaces"`
	Generated  bool              `json:"generated"`
	Lines      int               `json:"lines"`
}

type SourceImport struct {
	Path  string `json:"path"`
	Alias string `json:"alias,omitempty"`
}

// PublicInterface measures declared methods and embeddings, not the expanded
// method set of embedded interfaces. The review policy must treat both counts.
type PublicInterface struct {
	Name       string `json:"name"`
	Methods    int    `json:"methods"`
	Embeddings int    `json:"embeddings"`
}

// ScanSources reads the repository's cmd, internal, pkg, sdk and examples trees.
// It skips tests, testdata, vendor and hidden directories. Child symlinks and
// non-regular source files are rejected; os.Root also confines file opens during
// concurrent path changes. A failed scan returns no partial inventory.
func ScanSources(ctx context.Context, rootPath, module string) ([]SourceFile, error) {
	if ctx == nil {
		return nil, errors.New("source inspection requires a context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if rootPath == "" || !validModulePath(module) {
		return nil, errors.New("source inspection requires a root and canonical module path")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, errors.New("cannot open source root")
	}
	defer root.Close()
	files := make([]SourceFile, 0)
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return fmt.Errorf("cannot inspect source path %s", name)
		}
		if name == "." {
			return nil
		}
		if !sourceTree(name) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("source symlink rejected: %s", name)
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") || entry.Name() == "testdata" || entry.Name() == "vendor" || entry.Name() == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular source rejected: %s", name)
		}
		body, err := readSource(ctx, root, name)
		if err != nil {
			return err
		}
		file, err := inspectSource(name, module, body)
		if err != nil {
			return err
		}
		files = append(files, file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func sourceTree(name string) bool {
	first, _, _ := strings.Cut(name, "/")
	switch first {
	case "cmd", "internal", "pkg", "sdk", "examples":
		return true
	default:
		return false
	}
}

func validModulePath(module string) bool {
	if module == "" || path.Clean(module) != module || strings.HasPrefix(module, "/") {
		return false
	}
	for _, part := range strings.Split(module, "/") {
		if part == "." || part == ".." || part == "" {
			return false
		}
		for _, char := range part {
			allowed := char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("-._~", char)
			if !allowed {
				return false
			}
		}
	}
	return true
}

func readSource(ctx context.Context, root *os.Root, name string) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("cannot read regular source: %s", name)
	}
	if info.Size() > maxSourceBytes {
		return nil, fmt.Errorf("source size limit exceeded: %s", name)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("cannot open source: %s", name)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("source changed while opening: %s", name)
	}
	body, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read source: %s", name)
	}
	if len(body) > maxSourceBytes {
		return nil, fmt.Errorf("source size limit exceeded: %s", name)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return body, nil
}

func inspectSource(name, module string, body []byte) (SourceFile, error) {
	syntax, err := parser.ParseFile(token.NewFileSet(), name, body, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		// Go parser errors may include source tokens: report only the file identity.
		return SourceFile{}, fmt.Errorf("invalid Go source: %s", name)
	}
	file := SourceFile{
		Path: name, Package: module + "/" + path.Dir(name),
		Generated: ast.IsGenerated(syntax), Lines: bytes.Count(body, []byte{'\n'}),
		Imports: make([]SourceImport, 0), Interfaces: make([]PublicInterface, 0),
	}
	if len(body) != 0 && body[len(body)-1] != '\n' {
		file.Lines++
	}
	for _, spec := range syntax.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return SourceFile{}, fmt.Errorf("invalid Go import: %s", name)
		}
		item := SourceImport{Path: importPath}
		if spec.Name != nil {
			item.Alias = spec.Name.Name
		}
		file.Imports = append(file.Imports, item)
	}
	for _, decl := range syntax.Decls {
		general, ok := decl.(*ast.GenDecl)
		if !ok || general.Tok != token.TYPE {
			continue
		}
		for _, spec := range general.Specs {
			typeSpec := spec.(*ast.TypeSpec)
			iface, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok || !ast.IsExported(typeSpec.Name.Name) {
				continue
			}
			item := PublicInterface{Name: typeSpec.Name.Name}
			for _, field := range iface.Methods.List {
				if len(field.Names) == 0 {
					item.Embeddings++
				} else {
					item.Methods += len(field.Names)
				}
			}
			file.Interfaces = append(file.Interfaces, item)
		}
	}
	sort.Slice(file.Imports, func(i, j int) bool { return file.Imports[i].Path < file.Imports[j].Path })
	sort.Slice(file.Interfaces, func(i, j int) bool { return file.Interfaces[i].Name < file.Interfaces[j].Name })
	return file, nil
}
