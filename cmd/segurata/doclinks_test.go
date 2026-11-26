package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/docref"
)

var (
	// repoPath is a repository path a user is pointed to without the URL that reaches it.
	repoPath = regexp.MustCompile(`(?:^|[\s("'])((?:docs|examples|plugins)/[\w/-]+\.md)`)
	linkPath = regexp.MustCompile(`^([\w/-]+\.md)(?:#([\w-]+))?`)
)

// TestDocLinksResolve fails on a string in the binary that points to a document by its path in the
// repository, which a go install user does not have, and on a docref link to a missing file or
// heading.
func TestDocLinksResolve(t *testing.T) {
	const root = "../.."
	links := 0
	check := func(at, rel string) {
		links++
		m := linkPath.FindStringSubmatch(rel)
		if m == nil {
			t.Errorf("%s: link %q names no Markdown file", at, rel)
			return
		}
		raw, err := os.ReadFile(filepath.Join(root, m[1]))
		if err != nil {
			t.Errorf("%s: link to %s, which does not exist", at, m[1])
			return
		}
		if m[2] != "" && !docref.Anchors(string(raw))[m[2]] {
			t.Errorf("%s: link to %s#%s: no such heading", at, m[1], m[2])
		}
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		linked := map[*ast.BasicLit]bool{} // the path after docref.Repo or docref.Docs
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BinaryExpr:
				ops := operands(n)
				for i := 1; i < len(ops); i++ {
					base, ok := docrefConst(ops[i-1])
					lit, isLit := ops[i].(*ast.BasicLit)
					if ok && isLit && !linked[lit] {
						linked[lit] = true
						s, _ := strconv.Unquote(lit.Value)
						check(fset.Position(lit.Pos()).String(), base+s)
					}
				}
			case *ast.BasicLit:
				if n.Kind != token.STRING || linked[n] {
					return true
				}
				if s, err := strconv.Unquote(n.Value); err == nil {
					if m := repoPath.FindStringSubmatch(s); m != nil {
						t.Errorf("%s: %s is a repository path: link it with docref", fset.Position(n.Pos()), m[1])
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if links < 15 {
		t.Fatalf("checked only %d docref links: the walk no longer finds them", links)
	}
}

// operands flattens a + chain, left to right.
func operands(e ast.Expr) []ast.Expr {
	if b, ok := e.(*ast.BinaryExpr); ok && b.Op == token.ADD {
		return append(operands(b.X), operands(b.Y)...)
	}
	if p, ok := e.(*ast.ParenExpr); ok {
		return operands(p.X)
	}
	return []ast.Expr{e}
}

// docrefConst is the repository folder docref.Repo or docref.Docs stands for.
func docrefConst(e ast.Expr) (string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "docref" {
		return "", false
	}
	switch sel.Sel.Name {
	case "Repo":
		return "", true
	case "Docs":
		return "docs/", true
	}
	return "", false
}
