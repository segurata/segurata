package liveness

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/segurata/segurata/connectors/internal/cli"
	"github.com/segurata/segurata/connectors/internal/sshkey"
	"github.com/segurata/segurata/internal/secretrisk"
)

// A private key is looked up by the fingerprint of its public half among the keys the owner
// registered: gh's GitHub SSH and signing keys, the deploy keys of the most recently pushed
// repositories, ~/.ssh/authorized_keys here and on config ssh_hosts.
//
//   - Registered anywhere: live.
//   - Only a ~/.ssh/*.pub here: unknown, the owner's key registered somewhere unseen.
//   - Not an OpenSSH key, found nowhere: unknown; a PEM key may sign TLS certificates or JWTs.
//   - Found nowhere with GitHub's lists read: unregistered, which lowers priority and is not dead.
//   - Encrypted with no clear public half, or cut short: unknown.

const (
	maxDeployKeyRepos = 30 // one call each
	maxSSHHosts       = 20
)

const ghKeysEndpoint = "GET api.github.com/user/keys"

// ghPaths are the only paths gh is asked for, each a GET: no method flag, no field.
var ghPaths = regexp.MustCompile(`^(user|user/keys|user/ssh_signing_keys|user/repos\?affiliation=owner&sort=pushed&per_page=` +
	fmt.Sprint(maxDeployKeyRepos) + `|repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/keys)$`)

var ghReadOnly = cli.CheckFunc(func(args []string) error {
	if len(args) >= 2 && args[0] == "api" {
		rest := args[1:]
		if rest[0] == "--paginate" {
			rest = rest[1:]
		}
		if len(rest) == 1 && ghPaths.MatchString(rest[0]) {
			return nil
		}
	}
	return fmt.Errorf("%w: gh %s", cli.ErrRefused, strings.Join(args, " "))
})

// sshHost is a host name or alias of ~/.ssh/config, optionally user@: never an option.
var sshHost = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]*$`)

// sshArgs read a host's authorized_keys: no prompt, only a known host key, a bounded connection,
// no terminal, one read-only command.
func sshArgs(host string) []string {
	return []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-T", "--", host, "cat", ".ssh/authorized_keys"}
}

var sshReadOnly = cli.CheckFunc(func(args []string) error {
	if n := len(args); n >= 3 && sshHost.MatchString(args[n-3]) && slices.Equal(args, sshArgs(args[n-3])) {
		return nil
	}
	return fmt.Errorf("%w: ssh", cli.ErrRefused)
})

type sshPlace struct {
	where, endpoint, account string
}

type sshRegistry struct {
	registered         map[string][]sshPlace // by fingerprint
	localPub           map[string]string     // fingerprint -> ~/.ssh/<name>.pub
	githubRead         bool                  // both GitHub lists were read
	deployRepos, hosts int                   // repositories and hosts read
}

func (l *lookups) sshRegistry(ctx context.Context) *sshRegistry {
	l.sshOnce.Do(func() { l.ssh = l.readSSH(ctx) })
	return l.ssh
}

func (l *lookups) readSSH(ctx context.Context) *sshRegistry {
	r := &sshRegistry{registered: map[string][]sshPlace{}, localPub: map[string]string{}}
	add := func(line string, p sshPlace) {
		if k, ok := sshkey.ParseAuthorized(line); ok {
			fp := k.Fingerprint()
			r.registered[fp] = append(r.registered[fp], p)
		}
	}
	l.readGitHubKeys(ctx, r, add)
	if l.owner.Home != "" {
		dir := filepath.Join(l.owner.Home, ".ssh")
		eachLine(filepath.Join(dir, "authorized_keys"), func(line string) {
			add(line, sshPlace{where: "authorized on this machine (~/.ssh/authorized_keys)", endpoint: "~/.ssh/authorized_keys"})
		})
		pubs, _ := filepath.Glob(filepath.Join(dir, "*.pub"))
		for _, f := range pubs {
			eachLine(f, func(line string) {
				if k, ok := sshkey.ParseAuthorized(line); ok {
					r.localPub[k.Fingerprint()] = "~/.ssh/" + filepath.Base(f)
				}
			})
		}
	}
	hosts := l.cfg.SSHHosts
	if len(hosts) > 0 && l.owner.SSH == nil {
		l.hint("ssh: not available: liveness.ssh_hosts not read")
		hosts = nil
	}
	for _, h := range hosts {
		out, err := cli.Guard(sshReadOnly, l.owner.SSH).Run(ctx, sshArgs(h)...)
		if err != nil {
			l.hint(fmt.Sprintf("ssh: %s: authorized_keys not read (%s): ssh -o BatchMode=yes %s must sign in without a prompt", h, cliError(err), h))
			continue
		}
		r.hosts++
		for _, line := range strings.Split(string(out), "\n") {
			add(line, sshPlace{where: "authorized on host " + h, endpoint: "ssh " + h + " cat .ssh/authorized_keys"})
		}
	}
	return r
}

type ghKey struct {
	Key, Title string
}

func (l *lookups) readGitHubKeys(ctx context.Context, r *sshRegistry, add func(string, sshPlace)) {
	if l.owner.GH == nil {
		l.hint("gh: not available: private keys are not looked up among your GitHub keys")
		return
	}
	var user struct{ Login string }
	if err := l.gh(ctx, &user, "user"); err != nil || user.Login == "" {
		l.hint("gh: not signed in (" + cliErrorOr(err, "no login") + "): private keys are not looked up among your GitHub keys; run gh auth login")
		return
	}
	account := "github:" + user.Login
	lists := []struct{ path, scope, what string }{
		{"user/keys", "read:public_key", "GitHub SSH key"},
		{"user/ssh_signing_keys", "read:ssh_signing_key", "GitHub signing key"},
	}
	read := 0
	for _, ls := range lists {
		var keys []ghKey
		if err := l.gh(ctx, &keys, "--paginate", ls.path); err != nil {
			l.hint(fmt.Sprintf("gh: %s not listed (%s): run gh auth refresh -h github.com -s %s", ls.path, cliError(err), ls.scope))
			continue
		}
		read++
		for _, k := range keys {
			add(k.Key, sshPlace{where: fmt.Sprintf("%s %q", ls.what, k.Title), endpoint: "GET api.github.com/" + ls.path, account: account})
		}
	}
	r.githubRead = read == len(lists)
	var repos []struct {
		FullName string `json:"full_name"`
		Owner    struct{ Login string }
	}
	if err := l.gh(ctx, &repos, fmt.Sprintf("user/repos?affiliation=owner&sort=pushed&per_page=%d", maxDeployKeyRepos)); err != nil {
		l.hint("gh: your repositories not listed (" + cliError(err) + "): deploy keys not read")
		return
	}
	for _, repo := range repos[:min(len(repos), maxDeployKeyRepos)] {
		var keys []ghKey
		path := "repos/" + repo.FullName + "/keys"
		if err := l.gh(ctx, &keys, path); err != nil {
			continue // a repository whose deploy keys gh may not read
		}
		r.deployRepos++
		for _, k := range keys {
			add(k.Key, sshPlace{where: fmt.Sprintf("deploy key %q of %s", k.Title, repo.FullName), endpoint: "GET api.github.com/" + path, account: "github:" + repo.Owner.Login})
		}
	}
}

// gh decodes `gh api`'s output; --paginate prints one JSON array per page.
func (l *lookups) gh(ctx context.Context, out any, args ...string) error {
	raw, err := cli.Guard(ghReadOnly, l.owner.GH).Run(ctx, append([]string{"api"}, args...)...)
	if err != nil {
		return err
	}
	list, isList := out.(*[]ghKey)
	if !isList {
		if err := json.Unmarshal(raw, out); err != nil {
			return errors.New("unreadable answer")
		}
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var page []ghKey
		if err := dec.Decode(&page); err == io.EOF {
			return nil
		} else if err != nil {
			return errors.New("unreadable answer")
		}
		*list = append(*list, page...)
	}
}

// eachLine reads a small regular file; a missing or unreadable one has no lines.
func eachLine(path string, fn func(string)) {
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	for sc.Scan() {
		fn(sc.Text())
	}
}

func lookupSSHKey(ctx context.Context, l *lookups, p Probe) secretrisk.Liveness {
	pub, openssh, err := sshkey.FromPrivate(p.Value)
	switch {
	case errors.Is(err, sshkey.ErrEncrypted):
		return unknown("", "encrypted, and no passphrase is at hand")
	case err != nil:
		return unknown("", "not a whole private key segurata can read")
	}
	reg := l.sshRegistry(ctx)
	fp := pub.Fingerprint()
	if places := reg.registered[fp]; len(places) > 0 {
		first := places[0]
		where := first.where
		if len(places) > 1 {
			where += fmt.Sprintf(" and %d more", len(places)-1)
		}
		return secretrisk.Liveness{State: secretrisk.Live, Endpoint: first.endpoint, Reason: where, Account: first.account}
	}
	if pubFile, ok := reg.localPub[fp]; ok {
		return unknown(pubFile, "the public half of "+pubFile+" on this machine, registered nowhere segurata can see")
	}
	if !openssh && p.Type != "ssh-key" {
		return unknown("", "not registered as an SSH key where segurata looked; a PEM key may instead sign TLS certificates or JWTs, which it cannot look up")
	}
	if !reg.githubRead {
		return unknown(ghKeysEndpoint, "your GitHub keys could not be listed")
	}
	return secretrisk.Liveness{State: secretrisk.Unregistered, Endpoint: ghKeysEndpoint,
		Reason: fmt.Sprintf("registered nowhere segurata can see: your GitHub SSH and signing keys, the deploy keys of %d repositories, authorized_keys here and on %d hosts", reg.deployRepos, reg.hosts)}
}
