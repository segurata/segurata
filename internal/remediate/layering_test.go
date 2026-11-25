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

// The remediation core serves the remediate verb alone. What other packages share with it lives
// elsewhere: the run files in internal/runfile, the confirmation prompt in internal/prompt, and the
// remediator contract (Plan, Allowlist, Executor, the generic actions) in internal/connector. So
// no connector, the tracker or any other package depends on the core; only cmd/segurata does.
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
