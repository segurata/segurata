package secretrisk

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// PathRole is what a path inside a repository says about its files. Secrets (ImpactOf) and data
// dumps share it, so the two never disagree on what a fixture is.
type PathRole int

const (
	RoleNone      PathRole = iota
	RoleTest               // fixtures, recorded requests, specs
	RoleExample            // examples, samples, demos and *.example templates
	RoleDoc                // documentation folders, README and other prose files
	RoleVendor             // third-party code copied into the repository
	RoleGenerated          // checksum lists and lockfiles: hashes that look like tokens
)

var (
	testDirs    = set("test", "tests", "spec", "specs", "fixtures", "fixture", "testdata", "__tests__", "__fixtures__", "__mocks__", "cassettes")
	exampleDirs = set("example", "examples", "sample", "samples", "demo", "demos")
	docDirs     = set("doc", "docs", "documentation")
	vendorDirs  = set("vendor", "third_party", "third-party", "node_modules", "bower_components")

	checksumExts = []string{".md5", ".sha1", ".sha256", ".sha512", ".sum"}
	lockFiles    = set("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
		"gemfile.lock", "poetry.lock", "pipfile.lock", "uv.lock", "cargo.lock", "composer.lock", "mix.lock",
		"podfile.lock", "package.resolved", "pubspec.lock", "flake.lock", "go.sum", "gradle.lockfile", "packages.lock.json")
	testNames    = []string{"_test.", ".test.", ".spec.", "_spec."}
	exampleNames = set("example", "examples", "sample", "samples", "template", "templates", "dist")
	docExts      = []string{".md", ".markdown", ".rst", ".adoc"}
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// DirRoles reports whether the folders of a path ("/"-separated, any case), not its file name,
// are test or vendor folders.
func DirRoles(p string) (test, vendor bool) {
	r := dirRolesOf(strings.ToLower(p))
	return r.test, r.vendor
}

type dirRoles struct{ test, example, doc, vendor bool }

func dirRolesOf(lower string) dirRoles {
	var r dirRoles
	for _, d := range strings.Split(path.Dir(lower), "/") {
		r.test = r.test || testDirs[d]
		r.example = r.example || exampleDirs[d]
		r.doc = r.doc || docDirs[d]
		r.vendor = r.vendor || vendorDirs[d]
	}
	return r
}

// RoleOf classifies a path by its folders and file name; the most telling role wins: generated,
// vendor, test, example, documentation.
func RoleOf(p string) PathRole {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	if lockFiles[base] || hasSuffix(base, checksumExts) {
		return RoleGenerated
	}
	dirs := dirRolesOf(lower)
	switch {
	case dirs.vendor:
		return RoleVendor
	case dirs.test || contains(base, testNames) || strings.HasPrefix(base, "test_"):
		return RoleTest
	case dirs.example || slices.ContainsFunc(strings.Split(base, ".")[1:], func(ext string) bool { return exampleNames[ext] }):
		return RoleExample
	case dirs.doc || strings.HasPrefix(base, "readme") || hasSuffix(base, docExts):
		return RoleDoc
	}
	return RoleNone
}

func hasSuffix(s string, suffixes []string) bool {
	for _, x := range suffixes {
		if strings.HasSuffix(s, x) {
			return true
		}
	}
	return false
}

func contains(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// testName reads a folder or file name as a test's: "Test" or "Spec" in it, or "test" or "spec"
// starting a word ("test-123", "my_test", not "latest").
var testName = regexp.MustCompile(`Test|Spec|(?:^|[^A-Za-z])(?:test|spec)`)

// TestMaterial is why a copy is test material that no one uses as a secret, wherever it sits; ""
// when it is not:
//   - a file a test run generated under a tmp/ or .tmp/ folder: the folder after it has a test's
//     name, or git ignores the untracked file under its repository's tmp/ (IgnoredTmp);
//   - a test log: test.log, *.test.log, or test*.log in a log/ or logs/ folder;
//   - test data of a library vendored anywhere: a test folder below vendor/, third_party/,
//     node_modules/ and the like.
func TestMaterial(e Evidence) string {
	parts := strings.FieldsFunc(e.Path, func(r rune) bool { return r == '/' || r == '\\' })
	if len(parts) == 0 {
		return ""
	}
	base := strings.ToLower(parts[len(parts)-1])
	vendored := false
	for i, p := range parts[:len(parts)-1] {
		d := strings.ToLower(p)
		switch {
		case (d == "tmp" || d == ".tmp") && testName.MatchString(parts[i+1]):
			return "test key generated under tmp/ by a test run"
		case vendorDirs[d]:
			vendored = true
		case vendored && testDirs[d]:
			return "test data of a vendored third-party library"
		}
	}
	dir := ""
	if len(parts) > 1 {
		dir = strings.ToLower(parts[len(parts)-2])
	}
	switch {
	case e.IgnoredTmp:
		return "generated under the repository's git-ignored tmp/ folder"
	case base == "test.log", strings.HasSuffix(base, ".test.log"),
		(dir == "log" || dir == "logs") && strings.HasPrefix(base, "test") && strings.HasSuffix(base, ".log"):
		return "printed in a test log"
	}
	return ""
}
