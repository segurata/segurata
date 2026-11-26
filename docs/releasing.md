# Releasing

Releases are cut from the public `github.com/segurata/segurata`. On a `v*` tag,
[`.github/workflows/release.yml`](../.github/workflows/release.yml) requires the history leak
scan and the Go tests before [GoReleaser](../.goreleaser.yaml) can upload assets.

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

Use the public `segurata/segurata` repository for development and releases.

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
| `release` environment | Settings > Environments | Deployment rule: tags matching `v*` only, so no branch workflow can read its secret |
| `HOMEBREW_TAP_DEPLOY_KEY` | Secret of the `release` environment | Pushing the cask: the private half of an ed25519 deploy key with write access, added to `segurata/homebrew-tap` only (the organization must allow deploy keys). Without it the release still publishes, with the tap step skipped |
| `homebrew-tap` repository | GitHub | Public, default branch `main` |

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

On Windows, in PowerShell, the same signature check and a hash comparison that prints `True`:

```powershell
$TAG = "v0.1.0"
cosign verify-blob `
  --certificate-identity "https://github.com/segurata/segurata/.github/workflows/release.yml@refs/tags/$TAG" `
  --certificate-oidc-issuer https://token.actions.githubusercontent.com `
  --bundle checksums.txt.sigstore.json `
  checksums.txt
$zip = "segurata_0.1.0_windows_amd64.zip"
$line = Get-Content checksums.txt | Where-Object { $_.EndsWith("  $zip") }
(Get-FileHash -Algorithm SHA256 $zip).Hash -eq $line.Split(" ")[0]
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

From a clone, `go build ./cmd/segurata` builds the same binary in the current folder.

### Release binaries

Download, verify (above), extract and put `segurata` on your `PATH`:

```bash
tar -xzf segurata_0.1.0_darwin_arm64.tar.gz segurata
install -m 0755 segurata ~/.local/bin/
```

On Windows, after verifying, clear the downloaded-file mark, extract into a folder that will stay
(a scheduled task runs that exact path) and add it to your user `PATH`:

```powershell
Unblock-File $zip
$dir = "$env:LOCALAPPDATA\Programs\segurata"
Expand-Archive $zip -DestinationPath $dir
$path = [Environment]::GetEnvironmentVariable("Path", "User")
[Environment]::SetEnvironmentVariable("Path", "$path;$dir", "User")
```

A new terminal then finds `segurata`. The binary has no Authenticode signature, so SmartScreen may
warn the first time it runs; the cosign signature over `checksums.txt` is what proves its origin.
There is no winget or Scoop manifest.

## Project website

The GitHub Pages source is the root of the public repository's `gh-pages` branch. To update it,
copy the contents of `site/` from a reviewed public commit, including `.nojekyll`, into a checkout
of that branch. Commit the changed files, push the branch, and check the Pages deployment.

## Going public

Publish a sanitized copy into an empty private destination at `github.com/segurata/segurata`.
The rewrite changes commit IDs in the copy. Move any remaining private branches to the new
history by cherry-pick or with `git format-patch` and `git am`.

### 1. Clean the tip

List the private identifiers in `~/.config/segurata/public-gate.txt`, outside any repository:
client and employer names, internal hosts and domains, cloud project and account ids, people's
names and emails, private repository names. Format: [`scripts/identifiers.py`](../scripts/identifiers.py).
Then, on `main`:

```bash
scripts/check-public.sh --require-identifiers
grep -n 'TODO (owner)[:]' CODE_OF_CONDUCT.md
```

Fix hits in tracked files and set the conduct contact in the tree that will be published.
The next step rewrites identifiers in the history.

### 2. Build the public history

```bash
scripts/prepare-public-history.sh --source "$PWD" --workdir ~/segurata-public \
  --drop-path-glob '*.pyc' --mailmap /path/to/public-author-mailmap
```

The command copies the committed local `main` and its reachable tags. Run it from the same commit
that passed tests. It rewrites file contents and Git messages, then checks that `main` still has
the same tree and the clone has only `main` and tags. `--drop-path-glob '*.pyc'` removes old Python
bytecode containing local paths.

To omit private documents, remove them in the tested source commit first and pass a
`--drop-path-glob` for their history. If the public identity overlaps the private identifiers list,
pass `--allow-author 'Name <email>'` for that exact identity. The exception applies to Git identity
headers. File content, paths, ref names and messages still get checked.

The gate scans for the configured identifiers in reachable objects and ref names. Gitleaks scans
Git patches, including merges, and commit and annotated tag metadata. Review historical binary
files and archives separately. A clean scan still depends on which identifier variants you list
and which credential formats Gitleaks recognizes.

Review `~/segurata-public/report.txt` privately. It masks listed identifiers and includes the
post-rewrite author, committer and tagger names and emails. Use `--keep-authors` in place of
`--mailmap` only after approving those identities for public release. Read the candidate history
before pushing and rerun in a fresh work directory after any change.

### 3. Publish

```bash
cd ~/segurata-public/public.git
git push --no-follow-tags git@github.com:segurata/segurata.git 'refs/heads/main:refs/heads/main'
```

An ordinary push into an empty repository: nothing is overwritten. Then, with the repository still
private:

1. Wait for CI on `main` to pass. Before changing visibility, review existing Actions logs and
   artifacts in the destination repository. Its Actions history and logs become public too.
2. Confirm that the conduct address in `CODE_OF_CONDUCT.md` is monitored. Enable GitHub's
   private reporting as soon as the repository is public.
3. Tap: `gh repo create segurata/homebrew-tap --public --add-readme`, then a deploy key as in
   [Repository settings](#repository-settings): `ssh-keygen -t ed25519 -N "" -f tap`,
   `gh repo deploy-key add tap.pub --repo segurata/homebrew-tap --allow-write`,
   `gh secret set HOMEBREW_TAP_DEPLOY_KEY --repo segurata/segurata --env release < tap`, then
   delete both files.
4. Go public, then turn on private vulnerability reporting:

   ```bash
   gh repo edit segurata/segurata --visibility public --accept-visibility-change-consequences
   gh api -X PUT repos/segurata/segurata/private-vulnerability-reporting
   ```

5. Check `go install github.com/segurata/segurata/cmd/segurata@main` from a machine without a
   clone, then cut `v0.1.0` as in [Cutting a release](#cutting-a-release).
6. In the clone you work in from now on, install the push gate without `--skip-authors`
   (`scripts/install-hooks.sh`): the private remote's pushes skip the author lines, the public
   one's must check them. Pass `--allow-author` if the approved identity needs the same exception.
7. Archive the private repository (`gh repo archive <owner>/<repository>`) once nothing is left to
   move over.
