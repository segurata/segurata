package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/segurata/segurata/internal/finding"
	"github.com/segurata/segurata/internal/statefile"
)

// Expected says a status other than ok is known and kept on purpose: an ephemeral key, an IAM
// user limited by design, accounts that belong to other people. A matching status gets state
// expected: it opens no setup item, and its scope still counts as not inspected. Empty fields
// match anything.
type Expected struct {
	State finding.State `json:"state,omitempty"`
	// Account is a glob (path.Match: * and ?, \ escapes).
	Account string `json:"account,omitempty"`
	// Detail is a substring of the status detail, or a regular expression between slashes.
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason"`
}

func (e Expected) detailRe() (*regexp.Regexp, bool, error) {
	if len(e.Detail) < 2 || !strings.HasPrefix(e.Detail, "/") || !strings.HasSuffix(e.Detail, "/") {
		return nil, false, nil
	}
	re, err := regexp.Compile(e.Detail[1 : len(e.Detail)-1])
	return re, true, err
}

// Matches reports whether the rule covers a status in its original state.
func (e Expected) Matches(st finding.Status, state finding.State) bool {
	if e.State != "" && e.State != state {
		return false
	}
	if e.Account != "" {
		if ok, err := path.Match(e.Account, st.Account); err != nil || !ok {
			return false
		}
	}
	if e.Detail == "" {
		return true
	}
	if re, isRe, err := e.detailRe(); isRe {
		return err == nil && re.MatchString(st.Detail)
	}
	return strings.Contains(st.Detail, e.Detail)
}

func (e Expected) validate() error {
	switch {
	case strings.TrimSpace(e.Reason) == "":
		return errors.New("an expected rule needs a reason")
	case e.State == finding.StateOK || e.State == finding.StateExpected:
		return fmt.Errorf("an expected rule cannot match state %q", e.State)
	}
	if _, err := path.Match(e.Account, ""); err != nil {
		return fmt.Errorf("expected account %q: %w", e.Account, err)
	}
	if _, _, err := e.detailRe(); err != nil {
		return fmt.Errorf("expected detail %s: %w", e.Detail, err)
	}
	return nil
}

// WriteSecretSuffix ends the name of every write credential a remediation uses
// (OPENAI_ADMIN_WRITE_KEY): such a name belongs under remediation_secrets.
const WriteSecretSuffix = "_WRITE_KEY"

func (c Config) validate() error {
	for key, cc := range c.Connectors {
		for name := range cc.Secrets {
			if strings.HasSuffix(name, WriteSecretSuffix) {
				return fmt.Errorf("connectors.%s: %s is a write credential: put it under remediation_secrets, which only remediate --apply resolves, not under secrets, which every inventory resolves", key, name)
			}
		}
		for _, e := range cc.Expected {
			if err := e.validate(); err != nil {
				return fmt.Errorf("connectors.%s: %w", key, err)
			}
		}
	}
	return nil
}

// Expect sets a status's state from the expected rules of its connector instance (the config key
// "name" or "name:label" that ran it): a status other than ok that a rule matches becomes
// expected, with the rule's reason and its original state in Was. It first undoes an earlier
// Expect, so a status read back from a run follows today's config.
func (c Config) Expect(st *finding.Status) {
	if st.State == finding.StateExpected && st.Was != "" {
		st.State, st.Was, st.Expected = st.Was, "", ""
	}
	if st.State == finding.StateOK || st.State == finding.StateExpected {
		return
	}
	key := st.Connector
	if st.Instance != "" {
		key += ":" + st.Instance
	}
	for _, e := range c.Connectors[key].Expected {
		if e.Matches(*st, st.State) {
			st.Was, st.State, st.Expected = st.State, finding.StateExpected, e.Reason
			return
		}
	}
}

// AddExpected appends a rule to connectors.<key>.expected in the config file at path, unless an
// equal rule is there already, and reports whether it changed the file. The file is rewritten as
// editFile says; the backup's name is returned.
func AddExpected(file, key string, rule Expected, now time.Time) (bool, string, error) {
	if err := rule.validate(); err != nil {
		return false, "", err
	}
	return editFile(file, now, func(raw []byte) ([]byte, bool, error) { return withExpected(raw, key, rule) })
}

// editFile rewrites the config file at path with what edit makes of its text (empty when the file
// does not exist), when edit reports a change and the result is a valid config: atomically, mode
// 0600, two-space indentation and the keys in their original order; the previous content is kept
// in a timestamped backup next to it, whose name it returns.
func editFile(file string, now time.Time, edit func(raw []byte) ([]byte, bool, error)) (bool, string, error) {
	raw, err := os.ReadFile(file)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		raw = nil
	case err != nil:
		return false, "", err
	}
	out, changed, err := edit(raw)
	if err != nil || !changed {
		return false, "", err
	}
	var check Config
	if err := json.Unmarshal(out, &check); err != nil {
		return false, "", err
	}
	if err := check.validate(); err != nil {
		return false, "", err
	}
	backup := ""
	if raw != nil {
		if backup, err = statefile.Backup(file, raw, now); err != nil {
			return false, "", err
		}
	}
	return true, backup, statefile.Write(file, out)
}

// withExpected is the config text with the rule added under connectors.<key>.expected.
func withExpected(raw []byte, key string, rule Expected) ([]byte, bool, error) {
	return editInstance(raw, key, func(inst *object) (bool, error) {
		var rules []json.RawMessage
		if v, ok := inst.get("expected"); ok {
			if err := json.Unmarshal(v, &rules); err != nil {
				return false, fmt.Errorf("connectors.%s.expected: %w", key, err)
			}
		}
		for _, r := range rules {
			var have Expected
			if json.Unmarshal(r, &have) == nil && have == rule {
				return false, nil
			}
		}
		add, err := json.Marshal(rule)
		if err != nil {
			return false, err
		}
		return true, inst.encode("expected", append(rules, add))
	})
}

// editInstance is the config text after edit changed the object under connectors.<key> (created
// when missing); raw comes back as it was when edit reports no change.
func editInstance(raw []byte, key string, edit func(inst *object) (bool, error)) ([]byte, bool, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	var root, conns, inst object
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, false, err
	}
	if err := root.decode("connectors", &conns); err != nil {
		return nil, false, err
	}
	if err := conns.decode(key, &inst); err != nil {
		return nil, false, err
	}
	changed, err := edit(&inst)
	if err != nil || !changed {
		return raw, false, err
	}
	if err := conns.encode(key, inst); err != nil {
		return nil, false, err
	}
	if err := root.encode("connectors", conns); err != nil {
		return nil, false, err
	}
	out, err := json.MarshalIndent(root, "", "  ")
	return append(out, '\n'), true, err
}

// object is a JSON object that keeps its keys in order, so rewriting the config moves nothing the
// owner did not ask to change.
type object []member

type member struct {
	Key   string
	Value json.RawMessage
}

func (o *object) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return errors.New("not a JSON object")
	}
	*o = nil
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return err
		}
		*o = append(*o, member{Key: t.(string), Value: v})
	}
	_, err := dec.Token()
	return err
}

func (o object) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m.Key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(m.Value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (o object) get(key string) (json.RawMessage, bool) {
	for _, m := range o {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// decode reads the object under key into v, leaving v empty when the key is absent.
func (o object) decode(key string, v *object) error {
	raw, ok := o.get(key)
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	return nil
}

// encode sets key to v, in place when present, at the end otherwise.
func (o *object) encode(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	for i := range *o {
		if (*o)[i].Key == key {
			(*o)[i].Value = raw
			return nil
		}
	}
	*o = append(*o, member{Key: key, Value: raw})
	return nil
}
