package signin

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// segurata attaches over CDP to the browser already running at cdp_url and never starts one: no
// `open`, no xdg-open, no browser binary, from the CDP client, signin or the command line. A
// sign-in tab opens with Target.createTarget in that browser; without it, signin prints the URLs.
func TestNoCodePathLaunchesABrowser(t *testing.T) {
	launchers := []string{"open", "/usr/bin/open", "xdg-open", "x-www-browser", "sensible-browser", "gio", "start"}
	browsers := []string{"google chrome", "google-chrome", "chromium", "brave browser", "brave-browser", "firefox", "safari", ".app/"}
	for _, dir := range []string{"../cdp", ".", "../../cmd/segurata"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: no Go files (%v)", dir, err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				// The CDP client and signin run no program at all; the command line runs some
				// (redact), checked by the strings below.
				if p, _ := strconv.Unquote(imp.Path.Value); dir != "../../cmd/segurata" && (p == "os/exec" || p == "syscall") {
					t.Errorf("%s imports %s", file, p)
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				low := strings.ToLower(strings.TrimSpace(s))
				if slices.Contains(launchers, low) || slices.ContainsFunc(browsers, func(b string) bool { return strings.Contains(low, b) }) {
					t.Errorf("%s: string %q names a browser or a launcher", file, s)
				}
				return true
			})
		}
	}
}
