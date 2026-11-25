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

// A private key is looked up by the fingerprint of its public half, derived in memory
// (connectors/internal/sshkey), among the keys the owner registered where segurata can read them:
// GitHub's SSH authentication and signing keys of gh's login, the deploy keys of the owner's
// maxDeployKeyRepos most recently pushed repositories, ~/.ssh/authorized_keys here and, opt-in,
// on the hosts of config ssh_hosts. The private key is never sent anywhere.
//
//   - Registered anywhere: live, with where.
//   - Only the public half of a key in ~/.ssh on this machine (its .pub): unknown. It is the
//     owner's key, used from here, registered somewhere segurata does not see.
//   - Not an OpenSSH key and found nowhere: unknown "not an OpenSSH key". A PKCS#1, PKCS#8 or SEC 1
//     key may sign TLS certificates or JWTs, which no registry here holds. Keys from ~/.ssh count
//     as SSH keys whatever their container.
//   - Found nowhere, and GitHub's lists were read: unregistered (lower priority, not dead). When gh
//     cannot list them, unknown, with a hint.
//   - An encrypted key whose public half is not stored in clear, or a key cut short: unknown.

// maxDeployKeyRepos bounds the repositories whose deploy keys are read: one call each.
const maxDeployKeyRepos = 30

// maxSSHHosts bounds config ssh_hosts.
const maxSSHHosts = 20

const ghKeysEndpoint = "GET api.github.com/user/keys"

// ghPaths are the only GitHub API paths gh is asked for, each a GET (no method flag, no field).
var ghPaths = regexp.MustCompile(`^(user|user/keys|user/ssh_signing_keys|user/repos\?affiliation=owner&sort=pushed&per_page=` +
	fmt.Sprint(maxDeployKeyRepos) + `|repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/keys)$`)

// ghReadOnly allows `gh api [--paginate] <path>` for those paths only.
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

// sshArgs are ssh's arguments to read a host's authorized_keys: no prompt (BatchMode), only a known
// host key, a bounded connection, no terminal, and one read-only command.
func sshArgs(host string) []string {
	return []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", "-T", "--", host, "cat", ".ssh/authorized_keys"}
}

var sshReadOnly = cli.CheckFunc(func(args []string) error {
	if n := len(args); n >= 3 && sshHost.MatchString(args[n-3]) && slices.Equal(args, sshArgs(args[n-3])) {
		return nil
	}
	return fmt.Errorf("%w: ssh", cli.ErrRefused)
})

// sshPlace is where a public key is registered.
type sshPlace struct {
	where, endpoint, account string
}

type sshRegistry struct {
	registered         map[string][]sshPlace // by fingerprint
	localPub           map[string]string     // fingerprint -> ~/.ssh/<name>.pub
	githubRead         bool                  // the authentication and signing keys were both listed
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

// ghKey is an entry of GitHub's key listings; Title is the owner's name for it.
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

// gh runs `gh api` and decodes its output; with --paginate gh prints one JSON array per page,
// which are joined.
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

// eachLine calls fn with each line of a small regular file; a missing or unreadable one is none.
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

// lookupSSHKey classifies a private key by its public half.
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
		return unknown("", "not an OpenSSH key: it may sign TLS certificates or JWTs, which segurata cannot look up")
	}
	if !reg.githubRead {
		return unknown(ghKeysEndpoint, "your GitHub keys could not be listed")
	}
	return secretrisk.Liveness{State: secretrisk.Unregistered, Endpoint: ghKeysEndpoint,
		Reason: fmt.Sprintf("registered nowhere segurata can see: your GitHub SSH and signing keys, the deploy keys of %d repositories, authorized_keys here and on %d hosts", reg.deployRepos, reg.hosts)}
}
