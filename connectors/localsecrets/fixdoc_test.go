package localsecrets

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/segurata/segurata/internal/docref"
)

// TestFixAnchorsExist keeps every section fixFor links in docs/secrets.md, which is where fixDoc
// points on GitHub.
func TestFixAnchorsExist(t *testing.T) {
	if !strings.HasSuffix(fixDoc, "docs/secrets.md") || !strings.HasPrefix(fixDoc, docref.Docs) {
		t.Fatalf("fixDoc %q is not docs/secrets.md on GitHub", fixDoc)
	}
	raw, err := os.ReadFile("../../docs/secrets.md")
	if err != nil {
		t.Fatal(err)
	}
	anchors := docref.Anchors(string(raw))
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "localsecrets.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "fixFor" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
				return true
			}
			if id, ok := as.Lhs[0].(*ast.Ident); !ok || id.Name != "a" {
				return true
			}
			if lit, ok := as.Rhs[0].(*ast.BasicLit); ok {
				a, _ := strconv.Unquote(lit.Value)
				seen++
				if !anchors[a] {
					t.Errorf("%s: docs/secrets.md has no heading #%s", fset.Position(lit.Pos()), a)
				}
			}
			return true
		})
	}
	if seen < 10 {
		t.Fatalf("found only %d anchors in fixFor", seen)
	}
}
