package localsecrets

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/sshkey"
	"github.com/segurata/segurata/internal/attribution"
	"github.com/segurata/segurata/internal/statefile"
)

// A private key is the owner's when its public half is one of theirs: a ~/.ssh/*.pub here, or a
// key of one of their GitHub users (gh's login and owned_owners), whose public lists are cached
// weekly. The public half is read from the key itself (connectors/internal/sshkey), so the private
// key never leaves memory. A key found nowhere is no evidence either way.

// sshOwnerKeys are the fingerprints of the owner's public keys.
type sshOwnerKeys struct {
	once   sync.Once
	files  map[string]string // fingerprint -> ~/.ssh/<name>.pub
	github map[string]string // fingerprint -> GitHub login
}

type githubKeysCache struct {
	Logins []string            `json:"logins"`
	Keys   map[string][]string `json:"keys"` // login -> fingerprints of its public keys
	At     time.Time           `json:"at"`
}

func ghUserKeysArgs(login string) []string {
	return []string{"api", "--paginate", "users/" + login + "/keys"}
}

// sshKeyClaim is where the owner holds the public half of a private key: "file:~/.ssh/<name>.pub",
// "github:<login>", "" for nowhere, or attribution.SSHKeyUnreadable.
func (s *scan) sshKeyClaim(value string) string {
	pub, _, err := sshkey.FromPrivate(value)
	if err != nil {
		return attribution.SSHKeyUnreadable
	}
	k := s.ownerKeys()
	fp := pub.Fingerprint()
	if f, ok := k.files[fp]; ok {
		return "file:" + f
	}
	if l, ok := k.github[fp]; ok {
		return "github:" + l
	}
	return ""
}

func (s *scan) ownerKeys() *sshOwnerKeys {
	k := &s.sshOwn
	k.once.Do(func() {
		k.files, k.github = map[string]string{}, map[string]string{}
		if s.home == "" {
			return
		}
		pubs, _ := filepath.Glob(filepath.Join(s.home, ".ssh", "*.pub"))
		for _, f := range pubs {
			eachPublicKey(f, func(fp string) { k.files[fp] = "~/.ssh/" + filepath.Base(f) })
		}
		for login, fps := range s.githubKeys() {
			for _, fp := range fps {
				k.github[fp] = login
			}
		}
	})
	return k
}

// eachPublicKey reads the public keys of a small file, one per line.
func eachPublicKey(path string, fn func(fingerprint string)) {
	raw, err := readSmall(path)
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		if pk, ok := sshkey.ParseAuthorized(sc.Text()); ok {
			fn(pk.Fingerprint())
		}
	}
}

// githubLogins are the owner's GitHub users: gh's login and owned_owners, less the organizations
// gh names (an organization has no keys).
func (s *scan) githubLogins() []string {
	var out []string
	add := func(l string) {
		if ghUserKeysPath.MatchString("users/"+l+"/keys") && !containsFold(out, l) {
			out = append(out, l)
		}
	}
	c, ok := s.githubOwners()
	if ok {
		add(c.Login)
	}
	for _, o := range s.cfg.ownedOwners {
		if !containsFold(c.Orgs, o) {
			add(o)
		}
	}
	slices.Sort(out)
	return out
}

func containsFold(list []string, v string) bool {
	return slices.ContainsFunc(list, func(x string) bool { return strings.EqualFold(x, v) })
}

// githubKeys are the fingerprints of each login's public SSH keys, from the cache when it is under
// a week old and for the same logins. An answer with a failed login is used but not cached.
func (s *scan) githubKeys() map[string][]string {
	if s.c == nil || s.c.GH == nil || s.c.CacheDir == nil {
		return nil
	}
	logins := s.githubLogins()
	if len(logins) == 0 {
		return nil
	}
	path := filepath.Join(filepath.Dir(s.c.CacheDir(s.home)), "github-ssh-keys.json")
	var c githubKeysCache
	found, err := statefile.ReadJSON(path, &c)
	if err != nil {
		s.emit.Log("github ssh keys cache: " + err.Error())
	}
	if found && err == nil && slices.Equal(c.Logins, logins) && s.now.Sub(c.At) < ownersTTL {
		return c.Keys
	}
	if _, err := s.c.LookPath("gh"); err != nil {
		return nil
	}
	c = githubKeysCache{Logins: logins, Keys: map[string][]string{}, At: s.now}
	complete := true
	for _, l := range logins {
		fps, err := s.githubUserKeys(l)
		if err != nil {
			complete = false
			s.emit.Log("gh api users/" + l + "/keys: private keys not compared with its public keys: " + err.Error())
			continue
		}
		c.Keys[l] = fps
	}
	if complete {
		if err := statefile.WriteJSON(path, c); err != nil {
			s.emit.Log("github ssh keys cache: " + err.Error())
		}
	}
	return c.Keys
}

// githubUserKeys reads one user's public keys; an account without them (an organization) has none.
func (s *scan) githubUserKeys(login string) ([]string, error) {
	out, err := guardGH(s.c.GH).Run(s.ctx, ghUserKeysArgs(login)...)
	if err != nil {
		if strings.Contains(cli.Stderr(err), "404") {
			return nil, nil
		}
		return nil, err
	}
	var fps []string
	dec := json.NewDecoder(bytes.NewReader(out)) // --paginate prints one array per page
	for {
		var page []struct{ Key string }
		if err := dec.Decode(&page); err == io.EOF {
			return fps, nil
		} else if err != nil {
			return nil, errors.New("unreadable answer")
		}
		for _, k := range page {
			if pk, ok := sshkey.ParseAuthorized(k.Key); ok {
				fps = append(fps, pk.Fingerprint())
			}
		}
	}
}
