// Package gitlocal defines the restrictions for reads of local Git repositories.
package gitlocal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// WholeTree ends a `git ls-files` command line so it lists the whole index by repository-relative
// name, wherever segurata runs: git otherwise reads pathspecs, and prints names, relative to the
// working directory when that lies inside the work tree.
func WholeTree() []string { return []string{"--full-name", "--", ":(top)"} }

// Tracked checks the on-disk indices of the repositories containing an absolute path, including
// enclosing repositories. A failed index lookup leaves tracking unknown.
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
	// In particular, a Git invocation that launched segurata must not supply its alternate index.
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "GIT_") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, ReadEnv()...)
	out, err := cmd.Output()
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
