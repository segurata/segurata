# Releasing

Releases are cut only from `github.com/segurata/segurata`, where the cosign identity, the cask and
`go install` below expect them. A `v*` tag pushed there runs [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which runs the tests and then [GoReleaser](../.goreleaser.yaml):

| Output | Detail |
|---|---|
| Binaries | darwin, linux and windows on amd64 and arm64; `CGO_ENABLED=0`, `-trimpath`, version, commit and commit date stamped into `segurata version` |
| Archives | `segurata_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) with `LICENSE`, `README.md` and `SECURITY.md` |
| SBOM | `<archive>.sbom.json`, SPDX, one per archive (syft) |
| Checksums | `checksums.txt`, SHA-256 of every archive and SBOM |
| Signature | `checksums.txt.sigstore.json`, a Sigstore bundle: keyless cosign signature with the workflow's GitHub OIDC identity, logged in the Rekor transparency log |
| Homebrew cask | `Casks/segurata.rb` pushed to the `segurata/homebrew-tap` repository, when the tap token is configured |

A second job downloads `checksums.txt` and its bundle from the published release and verifies
them as below, so a release with a broken signature fails visibly.

Signing is keyless cosign rather than minisign: there is no long-lived private key to store as a
secret, rotate or lose, and a leaked key could sign a forged release that verifies. The signature
names the workflow, the repository and the tag that produced it, and the Rekor transparency log
records every signature made with that identity, so a forged release would leave a public trace.
The cost is on the verifier's side: cosign, and trust in Sigstore's public instance.

## Cutting a release

1. On `main`, with CI green: `git pull`, then `go vet ./... && go test ./...`.
2. Pick the version ([semver](https://semver.org/)): `v0.x.y` until the CLI and the connector
   protocol are stable. A suffix (`v1.2.0-rc.1`) makes a GitHub pre-release and skips the tap.
3. Tag and push the tag:

   ```bash
   git tag -a v0.1.0 -m "segurata v0.1.0"
   git push origin v0.1.0
   ```

4. Watch the `release` workflow; check that `verify` passed and the release page lists the
   archives, SBOMs, `checksums.txt` and `checksums.txt.sigstore.json`.

To check the GoReleaser config locally: `goreleaser check`, and `goreleaser release --snapshot
--clean --skip=sign,sbom` for a dry build into `dist/` (nothing is published).

### Repository settings

| Setting | Where | Needed for |
|---|---|---|
| `HOMEBREW_TAP_GITHUB_TOKEN` | Actions secret | Pushing the cask. A fine-grained token with the `segurata` organization as resource owner, access to the `homebrew-tap` repository only, and Contents read and write. Without it the release still publishes, with the tap step skipped |
| `HOMEBREW_TAP_OWNER` | Actions variable | Optional. Owner of the `homebrew-tap` repository; `segurata` when unset |
| `homebrew-tap` repository | GitHub | Must exist (public, with a default branch) before the first release with the token set |

The workflow uses no other secret. The default `GITHUB_TOKEN` creates the release; `id-token:
write` exists only in the release job, for the signature.

### Pinned tools

Actions are pinned by commit SHA and tools by exact version, each a release published at least 4
days before it was pinned. Dependabot proposes action updates
([`.github/dependabot.yml`](../.github/dependabot.yml)); reviewers hold them until the release is 4
days old. The tool versions inside `release.yml` (`cosign-release`, `syft-version`, the goreleaser
`version`) are bumped by hand under the same rule, and so are the tool versions inside `ci.yml`
(staticcheck, govulncheck, gitleaks and its SHA-256). The Go toolchain that tests and builds a
release is the `toolchain` line of `go.mod`: bump it to each Go patch release once it is 4 days old,
since govulncheck fails CI on standard library vulnerabilities the older patch still has.

## Verifying a release

Download the archive for your platform, `checksums.txt` and `checksums.txt.sigstore.json` from the
release page, then verify the signature with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
v3 or later:

```bash
TAG=v0.1.0
cosign verify-blob \
  --certificate-identity "https://github.com/segurata/segurata/.github/workflows/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json \
  checksums.txt
```

`Verified OK` means `checksums.txt` was signed by this repository's release workflow running for
that tag. Then check the archive against it:

```bash
sha256sum --ignore-missing -c checksums.txt          # Linux
shasum -a 256 --ignore-missing -c checksums.txt      # macOS
```

## Installing

### Homebrew

```bash
brew install --cask segurata/tap/segurata
segurata version
```

The tap holds a cask: current GoReleaser deprecated Homebrew formulas for prebuilt binaries. The
binary is not notarized by Apple; if macOS refuses to run it, verify the release as above and
remove the quarantine attribute (`xattr -d com.apple.quarantine "$(brew --prefix)/bin/segurata"`),
as the cask's caveat says.

### go install

```bash
go install github.com/segurata/segurata/cmd/segurata@latest   # or @v0.1.0
```

Builds from source with your Go toolchain (the version in `go.mod` or newer). `segurata version`
then shows the module version without a commit or date.

This works only once the code is public at `https://github.com/segurata/segurata`, because the
module path is `github.com/segurata/segurata`. The go command maps a `github.com/<owner>/<repo>`
path straight to `https://github.com/<owner>/<repo>` with no lookup that could point elsewhere
(`vcsPaths` in the Go source, `src/cmd/go/internal/vcs/vcs.go`), the module proxy fetches it the
same way, and a `go.mod` whose module path differs from the path asked for is rejected. A
repository living anywhere else cannot serve this module path;
a vanity path (`segurata.dev/segurata`) could, but would change the module path. Until then, clone
the repository and run `go build ./cmd/segurata`.

### Release binaries

Download, verify (above), extract and put `segurata` on your `PATH`:

```bash
tar -xzf segurata_0.1.0_darwin_arm64.tar.gz segurata
install -m 0755 segurata ~/.local/bin/
```

While the repository is private, release downloads (and so the cask) need a GitHub token with read
access to it, for example `gh release download v0.1.0 --repo segurata/segurata`.

## Going public

The code goes public as a new history in `github.com/segurata/segurata`, a repository that exists
today, private and empty. The private `example-org/segurata` repository is only read from: its
history is never rewritten in place and never force-pushed. Its clones cannot pull from the public
repository afterwards (every commit id changes), so open branches move over by `git format-patch`
and `git am` or by cherry-pick.

### 1. Clean the tip

List the private identifiers in `~/.config/segurata/public-gate.txt`, outside any repository:
client and employer names, internal hosts and domains, cloud project and account ids, people's
names and emails, private repository names. Format: [`scripts/identifiers.py`](../scripts/identifiers.py).
Then, on `main`:

```bash
scripts/check-public.sh --require-identifiers --history
grep -rn 'TODO (owner)[:]' --exclude-dir=.git .   # the contacts still to fill in
```

Every hit in the tracked files is fixed on `main` by an ordinary commit, and so is every
`TODO (owner)` (the security and conduct contacts). Hits in the history are what the next step
rewrites.

### 2. Build the public history

```bash
scripts/prepare-public-history.sh --workdir ~/segurata-public --drop-path-glob '*.pyc'
```

It clones `main` and its tags from `origin` into `~/segurata-public/public.git`, replaces every
identifier in file contents and commit and tag messages, and writes `~/segurata-public/report.txt`.
Its gates: no identifier left anywhere in the new history (paths, binary files and authors
included, which the replacement does not touch: `--drop-path-glob` removes such files, `--mailmap`
rewrites authors), gitleaks clean, the tip's files identical to `main`'s, and no ref but `main` and
tags. `--drop-path-glob '*.pyc'` drops the Python bytecode an early commit added, which holds local
paths. Run it again with a new `--workdir` until the report ends in `ALL GATES PASSED`, then read
the result once by eye: `git -C ~/segurata-public/public.git log --stat`.

### 3. Publish

```bash
cd ~/segurata-public/public.git
git push git@github.com:segurata/segurata.git 'refs/heads/main:refs/heads/main' 'refs/tags/*:refs/tags/*'
```

An ordinary push into an empty repository: nothing is overwritten. Then, with the repository still
private:

1. Wait for CI on `main` to pass. GitHub-hosted runners are free for public repositories; while
   private, the `segurata` organization's plan pays for them.
2. Contacts: the address that replaced `TODO (owner)` in `SECURITY.md` and `CODE_OF_CONDUCT.md`
   must receive mail.
3. Tap: `gh repo create segurata/homebrew-tap --public --add-readme`, then a fine-grained token as
   in [Repository settings](#repository-settings), stored with
   `gh secret set HOMEBREW_TAP_GITHUB_TOKEN --repo segurata/segurata`.
4. Go public, then turn on private vulnerability reporting:

   ```bash
   gh repo edit segurata/segurata --visibility public --accept-visibility-change-consequences
   gh api -X PUT repos/segurata/segurata/private-vulnerability-reporting
   ```

5. Check `go install github.com/segurata/segurata/cmd/segurata@main` from a machine without a
   clone, then cut `v0.1.0` as in [Cutting a release](#cutting-a-release).
6. Archive the private repository (`gh repo archive example-org/segurata`) once nothing is left
   to move over.
