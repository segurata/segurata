// Package gitlocal defines the restrictions for reads of local Git repositories.
package gitlocal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/proc"
)

// ReadEnv overrides repository config that could run a program or initiate a fetch during a read.
// Patch readers must also pass --no-ext-diff and --no-textconv.
func ReadEnv() []string {
	settings := [][2]string{
		{"core.fsmonitor", "false"},
		{"core.hooksPath", os.DevNull},
		{"log.showSignature", "false"},
		{"protocol.allow", "never"},
		{"core.pager", "cat"},
	}
	env := []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat",
		"GIT_OPTIONAL_LOCKS=0", fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(settings))}
	for i, kv := range settings {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	return env
}

// UnsafeRepositoryError is Git refusing a repository another account owns (safe.directory), as Git
// for Windows does for a folder created by an administrator or another user. segurata never
// overrides the check (-c safe.directory=* would hand that account's hooks and config our run).
type UnsafeRepositoryError struct {
	Repo string // empty when Git did not name it
	Err  error

	arg string // Repo quoted the way Git printed it in its hint
}

func (e *UnsafeRepositoryError) Error() string {
	repo, arg := e.Repo, e.arg
	if repo == "" {
		repo, arg = "<repository>", "<repository>"
	}
	return fmt.Sprintf("git refuses %s: it is owned by another account (dubious ownership). If you trust it, "+
		"run `git config --global --add safe.directory %s`; segurata never bypasses this check", repo, arg)
}

func (e *UnsafeRepositoryError) Unwrap() error { return e.Err }

// unsafeHint is the command Git suggests with its refusal. The sentence before it is translated;
// the command is not.
var unsafeHint = regexp.MustCompile(`git config --global --add safe\.directory ('[^'\n]*'|[^\n]*)`)

// Classify returns err as an *UnsafeRepositoryError when stderr, the failed git command's, says Git
// refused the repository for its owner, in any language, and err unchanged otherwise.
func Classify(err error, stderr string) error {
	if err == nil {
		return err
	}
	m := unsafeHint.FindStringSubmatch(stderr)
	if m == nil {
		if strings.Contains(stderr, "dubious ownership") {
			return &UnsafeRepositoryError{Err: err}
		}
		return err
	}
	arg := strings.TrimSpace(m[1])
	return &UnsafeRepositoryError{Repo: strings.Trim(arg, "'"), Err: err, arg: arg}
}

// WholeTree ends a `git ls-files` command line so it lists the whole index by repository-relative
// name even when the working directory lies inside the work tree.
func WholeTree() []string { return []string{"--full-name", "--", ":(top)"} }

// Tracked reports whether any repository enclosing an absolute path has it in its index. A failed
// index lookup is an error: tracking is then unknown, never false.
func Tracked(ctx context.Context, path string) (bool, error) {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		dot := filepath.Join(dir, ".git")
		if _, err := os.Lstat(dot); err == nil {
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return false, err
			}
			tracked, err := indexContains(ctx, dir, dot, filepath.ToSlash(rel))
			if err != nil || tracked {
				return tracked, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if filepath.Dir(dir) == dir {
			return false, nil
		}
	}
}

func indexContains(ctx context.Context, root, dot, path string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := proc.Command(ctx, "git", "--git-dir="+dot, "--work-tree="+root,
		"ls-files", "--cached", "-z", "--full-name", "--", ":(top,literal,icase)"+path)
	// A Git invocation that launched segurata must not supply its own index or config.
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "GIT_") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, ReadEnv()...)
	out, err := cmd.Output()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return false, Classify(err, string(ee.Stderr))
	}
	if err != nil {
		return false, err
	}
	for _, entry := range bytes.Split(out, []byte{0}) {
		if strings.EqualFold(string(entry), path) {
			return true, nil
		}
	}
	return false, nil
}
