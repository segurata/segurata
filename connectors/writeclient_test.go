package connectors

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const writeClient = "github.com/segurata/segurata/connectors/internal/httpw"

// The write client is reachable only from remediation code: no connector file but remediate.go
// imports it, so no inventory code path can send anything but the GET httpx allows.
func TestWriteClientOnlyInRemediations(t *testing.T) {
	importers := 0
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if strings.HasPrefix(path, filepath.Join("internal", "httpw")) {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == writeClient {
				importers++
				if filepath.Base(path) != "remediate.go" {
					t.Errorf("%s imports the write client; only a connector's remediate.go may", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if importers == 0 {
		t.Fatal("no remediation imports the write client: this test checks nothing")
	}
}
