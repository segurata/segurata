# Releasing

A `v*` tag pushed to GitHub runs [`.github/workflows/release.yml`](../.github/workflows/release.yml),
which runs the tests and then [GoReleaser](../.goreleaser.yaml):

| Output | Detail |
|---|---|
| Binaries | darwin, linux and windows on amd64 and arm64; `CGO_ENABLED=0`, `-trimpath`, version, commit and commit date stamped into `segurata version` |
| Archives | `segurata_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) with `LICENSE`, `README.md` and `SECURITY.md` |
| SBOM | `<archive>.sbom.json`, SPDX, one per archive (syft) |
| Checksums | `checksums.txt`, SHA-256 of every archive and SBOM |
| Signature | `checksums.txt.sigstore.json`, a Sigstore bundle: keyless cosign signature with the workflow's GitHub OIDC identity, logged in the Rekor transparency log |
| Homebrew cask | `Casks/segurata.rb` pushed to the tap, when the tap token is configured |

A second job downloads `checksums.txt` and its bundle from the published release and verifies
them as below, so a release with a broken signature fails visibly.

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
| `HOMEBREW_TAP_GITHUB_TOKEN` | Actions secret | Pushing the cask. A fine-grained token with Contents read and write on the tap repository only. Without it the release still publishes, with the tap step skipped |
| `HOMEBREW_TAP_OWNER` | Actions variable | Optional. Owner of the `homebrew-tap` repository; `example-org` when unset |
| `homebrew-tap` repository | GitHub | Must exist (public, with a default branch) before the first release with the token set |

The workflow uses no other secret. The default `GITHUB_TOKEN` creates the release; `id-token:
write` exists only in the release job, for the signature.

### Pinned tools

Actions are pinned by commit SHA and tools by exact version, each a release published at least 4
days before it was pinned. Dependabot proposes action updates
([`.github/dependabot.yml`](../.github/dependabot.yml)); reviewers hold them until the release is 4
days old. The tool versions inside `release.yml` (`cosign-release`, `syft-version`, the goreleaser
`version`) are bumped by hand under the same rule.

## Verifying a release

Download the archive for your platform, `checksums.txt` and `checksums.txt.sigstore.json` from the
release page, then verify the signature with [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
v3 or later:

```bash
TAG=v0.1.0
cosign verify-blob \
  --certificate-identity "https://github.com/example-org/segurata/.github/workflows/release.yml@refs/tags/$TAG" \
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

When the repository moves to `segurata/segurata`, the identity becomes
`https://github.com/segurata/segurata/.github/workflows/release.yml@refs/tags/$TAG`. Releases made
before the move keep verifying only with the `example-org/segurata` identity.

## Installing

### Homebrew

```bash
brew install --cask example-org/tap/segurata
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
then shows the module version without a commit or date. This works once the module is published at
`github.com/segurata/segurata`; until then, clone the repository and run `go build ./cmd/segurata`.

### Release binaries

Download, verify (above), extract and put `segurata` on your `PATH`:

```bash
tar -xzf segurata_0.1.0_darwin_arm64.tar.gz segurata
install -m 0755 segurata ~/.local/bin/
```

While the repository is private, release downloads (and so the cask) need a GitHub token with read
access to it, for example `gh release download v0.1.0 --repo example-org/segurata`.

## Moving to segurata/segurata

When the repository moves, change in one go:

- `docs/releasing.md` and `README.md`: the cosign identity, the tap owner and the download
  examples.
- `.goreleaser.yaml`: `homepage`.
- The `HOMEBREW_TAP_OWNER` variable, if the tap moves too.
- `SECURITY.md`: enable private vulnerability reporting and set the security contact.
