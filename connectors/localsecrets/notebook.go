package localsecrets

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/segurata/segurata/internal/secretrisk"
)

// A Jupyter notebook stores what its cells printed next to their code: base64 images, tables,
// logs. Generic rules find token-shaped strings in those outputs (a "Square access token" inside a
// PNG), so in a .ipynb file only the cells' source counts. The check is by line: a match on a line
// that holds no source text is in an output, metadata or an attachment, and is dropped. Notebooks
// are pretty-printed JSON, one source line per JSON line; a notebook squeezed onto one line keeps
// its matches.

// notebooks remembers the source lines of each notebook version read in one run.
type notebooks struct {
	mu    sync.Mutex
	lines map[string]map[int]bool // repo, commit and path (or file path) -> source lines; nil when unreadable
}

func isNotebook(path string) bool { return strings.HasSuffix(strings.ToLower(path), ".ipynb") }

// inNotebookOutput reports whether a gitleaks match sits outside the source of a notebook's cells,
// reading the notebook as committed.
func (s *scan) inNotebookOutput(repo string, ev secretrisk.Evidence) bool {
	if !isNotebook(ev.Path) || ev.Line <= 0 || ev.Commit == "" {
		return false
	}
	rel := strings.TrimPrefix(ev.Path, ev.Repo+"/")
	lines := s.nb.get(repo+"\x00"+ev.Commit+"\x00"+rel, func() []byte {
		out, err := guardGit(s.c.Git).Run(s.ctx, gitDirArg(repo), "cat-file", "blob", ev.Commit+":"+filepath.ToSlash(rel))
		if err != nil {
			s.emit.Log("notebook " + ev.Path + "@" + ev.Commit + ": " + err.Error())
			return nil
		}
		return out
	})
	return lines != nil && !lines[ev.Line]
}

// fileNotebookOutput is inNotebookOutput for a match in a file on disk.
func (s *scan) fileNotebookOutput(path string, line int) bool {
	if !isNotebook(path) || line <= 0 {
		return false
	}
	lines := s.nb.get(path, func() []byte {
		raw, _ := readSmall(path)
		return raw
	})
	return lines != nil && !lines[line]
}

func (n *notebooks) get(key string, read func() []byte) map[int]bool {
	n.mu.Lock()
	if l, ok := n.lines[key]; ok {
		n.mu.Unlock()
		return l
	}
	n.mu.Unlock()
	l := notebookSourceLines(read())
	n.mu.Lock()
	if n.lines == nil {
		n.lines = map[string]map[int]bool{}
	}
	n.lines[key] = l
	n.mu.Unlock()
	return l
}

// notebookSourceLines returns the 1-based lines of a notebook's JSON that hold part of a cell's
// source ("source", or "input" in nbformat 3), or nil when the text is not readable JSON.
func notebookSourceLines(raw []byte) map[int]bool {
	if len(raw) == 0 {
		return nil
	}
	type frame struct {
		object, wantKey bool
		key             string
	}
	var stack []frame
	inSource := func() bool {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].object {
				return stack[i].key == "source" || stack[i].key == "input"
			}
		}
		return false
	}
	lines := map[int]bool{}
	line := 1
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '\n':
			line++
		case '{':
			stack = append(stack, frame{object: true, wantKey: true})
		case '[':
			stack = append(stack, frame{})
		case '}', ']':
			if len(stack) == 0 {
				return nil
			}
			stack = stack[:len(stack)-1]
		case ',':
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].wantKey = true
			}
		case '"':
			start, startLine := i+1, line
			for i++; i < len(raw) && raw[i] != '"'; i++ {
				switch raw[i] {
				case '\\':
					i++
				case '\n':
					line++
				}
			}
			if i >= len(raw) {
				return nil
			}
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].wantKey {
				stack[n-1].key, stack[n-1].wantKey = string(raw[start:i]), false
				continue
			}
			if inSource() {
				for l := startLine; l <= line; l++ {
					lines[l] = true
				}
			}
		}
	}
	if len(stack) != 0 {
		return nil
	}
	return lines
}
