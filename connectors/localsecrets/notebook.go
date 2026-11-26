package localsecrets

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/segurata/segurata/internal/secretrisk"
)

// A notebook's outputs (base64 images, tables) are full of token-shaped strings, so only matches
// on lines that hold cell source count. Notebooks are pretty-printed, one source line per line; a
// one-line notebook keeps its matches.

type notebooks struct {
	mu    sync.Mutex
	lines map[string]map[int]bool // nil when unreadable
}

func isNotebook(path string) bool { return strings.HasSuffix(strings.ToLower(path), ".ipynb") }

// inNotebookOutput judges a gitleaks match against the notebook as committed.
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

// notebookSourceLines are the lines holding cell source ("input" in nbformat 3); nil for bad JSON.
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
