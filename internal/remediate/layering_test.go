package remediate

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const self = "github.com/segurata/segurata/internal/remediate"

// What other packages share with the core lives in internal/connector, runfile and prompt.
func TestOnlyTheCommandImportsTheCore(t *testing.T) {
	root := filepath.Join("..", "..")
	importers := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != root {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == self {
				importers++
				if rel, _ := filepath.Rel(root, path); filepath.Dir(rel) != filepath.Join("cmd", "segurata") {
					t.Errorf("%s imports the remediation core; only cmd/segurata may", rel)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if importers == 0 {
		t.Fatal("nothing imports the remediation core: this test checks nothing")
	}
}
