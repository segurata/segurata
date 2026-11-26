# Contributing

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md). Vulnerabilities go
through [SECURITY.md](SECURITY.md), never a public issue.

## Build and test

```bash
go build -o segurata ./cmd/segurata
gofmt -l .                 # must print nothing
go vet ./...
go test ./...
(cd examples/hibp && python3 -m unittest)   # the example external connector
(cd plugins/prowler && python3 -m unittest) # the Prowler wrapper
(cd scripts && python3 -m unittest)         # the leak gate
scripts/check-public.sh                     # gitleaks and private identifiers over tracked files
GOOS=windows GOARCH=amd64 go vet ./...      # and GOARCH=arm64
for p in $(go list ./...); do GOOS=windows go test -c -o /dev/null "$p" || exit 1; done
```

On Windows, `go vet ./...` and `go test ./...` run natively; the tests that fake a CLI with a shell
script need Git for Windows' `sh`. The leak gate and the hooks are bash scripts: run them from WSL
or Git Bash.

`scripts/check-public.sh` needs [gitleaks](https://github.com/gitleaks/gitleaks); its options
(`--history`, `--unpushed`, `--pre-push`) are in its usage block. Maintainers keep a list of private
identifiers (client names, internal hosts, project ids) outside the repository, at
`~/.config/segurata/public-gate.txt` or `$SEGURATA_PUBLIC_GATE` (format in
[`scripts/identifiers.py`](scripts/identifiers.py)), and gate every push with a pre-push hook that
scans exactly the commits the remote lacks, so a secret or identifier added in one commit and
deleted in the next is still caught. Install it, keeping the hooks you already have, with:

```bash
scripts/install-hooks.sh
```

While the remote is the private one, install it with `--skip-authors`: the commits' author lines
carry the owner's name until `scripts/prepare-public-history.sh` decides the public history's
authors; messages and content are still scanned.

## Rules

- **Go standard library only.** No third-party modules in `go.mod`. A connector that needs a
  provider SDK calls the provider's official CLI instead, or becomes an external connector.
- **Inventory is read-only.** A connector lists and reads; it never changes anything. Changes go
  through `segurata remediate`: one finding, an exact plan shown first, explicit confirmation,
  and for built-ins only commands on a hand-written allowlist.
- **No secret values anywhere**: not in findings, statuses, logs, test fixtures, docs or commit
  messages. Tests use obviously fake values and assert they never reach the output.
- **No personal data in the repository**: inventories (`out/`) are gitignored; fixtures use
  `example.com` addresses and made-up names.
- **English** for code, comments, finding text, docs and commit messages.
- **Platform code in build-tagged files.** Windows code lives in `_windows.go` files and calls
  Win32 only through `internal/winsys`. Every decision about who can reach a file goes through
  `internal/fileacl`, never through mode bits or uids read by hand, and tests assert a private
  file with `fileacltest.AssertPrivate`. A test that fakes a CLI uses `proctest`, so it runs on
  Windows too.
- Every behaviour change comes with a test. External services are faked in tests, never called.

How to write a connector, the finding model and the external protocol:
[docs/connectors.md](docs/connectors.md). Design: [docs/architecture.md](docs/architecture.md).
Releases and their signatures: [docs/releasing.md](docs/releasing.md).
