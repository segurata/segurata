# Secrets out of plaintext files

What to do with each finding of the `local-secrets` connector (`segurata inventory
local-secrets`). The `evidence.fix` field of every finding points to the section that applies.

Order of work: first **rotate** whatever has left the machine (git, agent transcripts), then move
the rest to an encrypted store, and only then delete the plaintext copies. Deleting without
rotating does nothing: the value is still valid wherever it was copied. `segurata rotations
sync` and `segurata rotations list --priority P0,P1` keep that order for you: one item per
secret, its locations, the files where the new value goes and the provider page where it is
rotated; `segurata rotations done <id>` once it is rotated. `segurata rotations next` walks
that list one item at a time with the provider's rotation steps, and `segurata rotations
replace <id>` puts the new value in every file that held the old one, or in the Keychain
([README](../README.md#rotation-ledger), [architecture](architecture.md#guided-rotation-next-and-replace)).

Tools on this machine (2026-11-23): macOS Keychain (`security`), 1Password CLI (`op` 2.41, signed
in), `age`, `gitleaks`, `git-credential-osxkeychain` already configured, `gh` with its token in the
Keychain. Not installed: `direnv`, `sops`, `aws-vault`. To install them, respect the 4-day
quarantine: `~/.claude/scripts/safe-update.sh`, or check the release date before `brew install`.

| Finding | Section |
|---|---|
| Any secret in a tracked file or in history (gitleaks) | [In git: always rotate](#in-git-always-rotate) |
| A database dump in a repository or its history (`data_dump`) | [Data dumps in git](#data-dumps-in-git) |
| `.env*` under `~/src` | [.env files](#env-files) |
| `export X=...` in `~/.zshrc` and friends | [Shell variables from the Keychain](#shell-variables-from-the-keychain) |
| MCP `env` blocks in `~/.claude.json`, `~/.mcp`, `~/.codex`, `~/.cursor` | [MCP servers and agents](#mcp-servers-and-agents) |
| `~/.aws/credentials`, `AKIA…` | [AWS](#aws) |
| `~/.config/gcloud`, service account JSON, `refresh_token`, `AIza…` | [Google Cloud and OAuth](#google-cloud-and-oauth) |
| `ghp_…`, `~/.netrc`, `~/.config/gh` | [GitHub and git](#github-and-git) |
| `~/.npmrc`, `~/.docker/config.json`, PyPI, RubyGems | [Package registries and Docker](#package-registries-and-docker) |
| `config/master.key`, `*.secret.exs`, `*.pem`, keystores | [Files that must live in the repo](#files-that-must-live-in-the-repo) |
| Keys in `~/.ssh` without a passphrase | [SSH keys](#ssh-keys) |
| `~/.zsh_history`, `~/.zsh_sessions` | [Shell history](#shell-history) |
| `~/.claude/projects`, `~/.codex/sessions`, `~/.cursor/projects` | [Agent transcripts](#agent-transcripts) |
| `*.log`, `~/Library/Logs` | [Logs](#logs) |

## In git: always rotate

A secret that reached a commit is leaked: it is in every clone, in forks, in GitHub's caches and in
backups.

1. Revoke it and issue a new one in the provider's console. This is the only step that cannot be
   skipped.
2. Store the new value as in [.env files](#env-files) or
   [Files that must live in the repo](#files-that-must-live-in-the-repo).
3. Optional, for private repos with no other clones: rewrite history with
   `git filter-repo --replace-text` and ask GitHub to purge cached views. It does not replace step 1.
4. So it does not happen again: a pre-commit hook running `gitleaks git --pre-commit --staged`, and
   GitHub push protection in every organisation.

segurata already discounts what is not yours or not live: copies in third-party repositories and
in history a fork inherited from its upstream, test-data values in fixture paths, checksum files
and lockfiles, notebook outputs, expired STS keys and credentials for localhost or `example.com`
([what counts against the owner](architecture.md#what-counts-against-the-owner)). If a
third-party repository is in fact yours (an organization you left, a client's), add its owner to
`owned_owners` in the connector config.

If the finding is a false positive (test fixture, sample key), add the gitleaks `Fingerprint`
(`commit:file:rule:line`, printed by `gitleaks git` in that repo) to `.gitleaksignore`, and mark the
item with `segurata rotations ignore <id> --reason …`.

## Data dumps in git

A `data_dump` finding is a database dump, database file or data export committed to a repository:
`production_latest_backup.sql`, `latest.dump`, `app.sqlite3`. Everyone who could clone the
repository has every row in it: customers' personal data, password hashes, session and API tokens.
Deleting the file in a new commit changes nothing; the blob stays in the history and in every
clone.

1. Treat the data as exposed. Who could clone it: collaborators past and present, CI systems,
   forks, and anyone at all if `visibility` is `PUBLIC`. `on_remote_branch: false` with
   `remote: true` means the commit has not been seen on a remote branch: if it really never left
   this machine, do not push it and continue at step 3.
2. Rotate every credential the dump holds: application secrets stored in tables, API keys of
   integrations, admin passwords. Force a password reset if user password hashes are in it and the
   hashing is weak (MD5, SHA-1, unsalted). The gitleaks matches inside the dump are marked
   `in_data_dump` and kept out of `segurata rotations` as noise, except AWS, Stripe live, GitHub
   and GitLab keys and private keys, which stay in the ledger.
3. Remove the file from history, in a fresh clone:
   `git filter-repo --path <path> --invert-paths` (from
   [git-filter-repo](https://github.com/newren/git-filter-repo)), then force-push every branch and
   tag. Every collaborator must re-clone: an old clone pushed again brings the file back. On
   GitHub, cached views and pull request refs keep it until
   [GitHub Support purges them](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository).
   segurata never rewrites history or pushes; this step is yours.
4. Personal data of customers or staff in the dump may be a personal data breach under the GDPR:
   the controller has 72 hours from becoming aware of it to notify the supervisory authority,
   unless it is unlikely to result in a risk to people. Spain:
   [AEPD, brechas de datos personales](https://www.aepd.es/es/derechos-y-deberes/cumple-tus-deberes/medidas-de-cumplimiento/brechas-de-datos-personales);
   EU: [EDPB Guidelines 9/2022 on personal data breach notification](https://www.edpb.europa.eu/documents/guideline/guidelines-92022-on-personal-data-breach-notification-under-gdpr_en).
   Document the incident even when no notification is due.
5. So it does not happen again: `*.sql`, `*.dump`, `*.sqlite3` and `*.db` in `.gitignore`, dumps
   kept outside repositories (encrypted, with an expiry), and anonymised or generated data for
   development.

A false positive (a public sample database, a fixture with generated rows):
`segurata accept <finding-id> --reason …`.

## After a rotation

Once the old value is revoked, the copies left in git history, agent transcripts, logs and shell
history are dead: nobody can use them. `segurata rotations sync` leaves such an item `rotated`
and notes once "old value still in history/transcripts". It reopens the item only when a working
file (config, `.env`, rc file, repo working tree) still holds the old value, because a program
still reads it from there. Purging the dead copies is optional housekeeping:
[git](#in-git-always-rotate) (step 3), [shell history](#shell-history),
[agent transcripts](#agent-transcripts), [logs](#logs). `segurata redact` does it for
transcripts, shell histories and logs in one pass, rotated or not: each secret becomes
`[REDACTED:<type>:<fingerprint8>]`, so the trail keeps its link to the rotation item
([architecture](architecture.md#redaction)):

```bash
segurata redact --trails                 # dry run: files, matches per file and per type
segurata redact --item <id> --apply      # one secret, everywhere it appears in trails
segurata redact --trails --apply         # everything non-noise, after confirmation
```

It leaves alone files modified in the last two hours (`--min-age`) and files a running `claude`
or `codex` holds open, keeps JSONL lines valid, mode and modification time unchanged, and makes
no backup unless `--backup`.

## .env files

Goal: keep a *reference* to the secret on disk, not the value.

**With 1Password** (installed). The env file holds `op://` references and can be committed:

```bash
# .env.op
OPENAI_API_KEY=op://Development/OpenAI my-project/credential
DATABASE_URL=op://Development/Postgres my-project/url
```

```bash
op run --env-file=.env.op -- mix phx.server
op run --env-file=.env.op -- npm run dev
op read "op://Development/OpenAI my-project/credential"   # a single value
```

`op run` injects the variables into that process only and masks the values if they show up in its
output. Avoid `op inject -o file`, which writes the secret back to disk in plaintext.

**With the macOS Keychain and direnv** (no external account):

```bash
security add-generic-password -a "$USER" -s my-project/OPENAI_API_KEY -w   # prompts for the value, stays out of history
```

```bash
# .envrc, no secrets, can be committed
export OPENAI_API_KEY="$(security find-generic-password -a "$USER" -s my-project/OPENAI_API_KEY -w)"
```

Run `direnv allow` once per repo. Without direnv, put the same `export` in a `bin/dev` script that
then starts the server.

**In the meantime**, for every `.env` left: `chmod 600 .env` and `git check-ignore -v .env` (no
output means the file is not ignored). Keep a `.env.example` with names and no values.

## Shell variables from the Keychain

An `export ANTHROPIC_API_KEY=sk-ant-…` in `~/.zshrc` is readable by every process and ends up in
backups, dotfiles repos and transcripts. Store each key once:

```bash
security add-generic-password -a "$USER" -s ANTHROPIC_API_KEY -w
```

and in `~/.zshrc`:

```bash
kc() { security find-generic-password -a "$USER" -s "$1" -w 2>/dev/null; }
export ANTHROPIC_API_KEY="$(kc ANTHROPIC_API_KEY)"
```

After rotating a key, `segurata rotations replace <id> --apply --to-keychain ANTHROPIC_API_KEY`
does both steps for an rc line: it stores the new value (through `security -i` on stdin, so it
never shows in a process listing) and rewrites the line to
`export ANTHROPIC_API_KEY="$(security find-generic-password -a "$USER" -s ANTHROPIC_API_KEY -w)"`,
the same lookup as `kc` written out, so the line works without the function.

Better still, do not export it to every shell; fetch it where it is used:
`ANTHROPIC_API_KEY="$(kc ANTHROPIC_API_KEY)" command`. With 1Password, the same with
`op read op://…` or `op run`. The first read from a new binary asks for Keychain permission.

After moving the keys, delete the `export` lines, `chmod 600 ~/.zshrc`, and check whether the file
lives in a dotfiles repo: if it was committed with keys, [rotate](#in-git-always-rotate).

## MCP servers and agents

The `env` blocks in `~/.claude.json`, `.mcp.json`, `~/.mcp/*.json`, `~/.codex/config.toml` and
`~/.cursor/mcp.json` often hold plaintext keys, and these files get copied, synced and pasted into
conversations.

- Claude Code expands `${VAR}` in `.mcp.json`: write `"env": {"GROK_API_KEY": "${GROK_API_KEY}"}`
  and export the variable from the Keychain as in the previous section.
- For any MCP client, wrap the command so it reads the secret at start-up:

  ```json
  "command": "op",
  "args": ["run", "--env-file", "/Users/me/.config/mcp/grok.env.op", "--", "node", "server.js"]
  ```

  or without 1Password:

  ```json
  "command": "sh",
  "args": ["-c", "GROK_API_KEY=\"$(security find-generic-password -a \"$USER\" -s GROK_API_KEY -w)\" exec node server.js"]
  ```

- `*.bak*` copies of these files carry the same keys: delete them once the clean version works.

## AWS

Long-lived access keys in `~/.aws/credentials` are what gets exploited first from a stolen laptop or
a malicious package.

- Preferred: IAM Identity Center (SSO). `aws configure sso`, then `aws sso login --profile x`;
  credentials expire on their own.
- Without SSO and without installing anything: `credential_process` reading from the Keychain.

  ```bash
  security add-generic-password -a "$USER" -s aws/my-profile -w   # paste {"Version":1,"AccessKeyId":"…","SecretAccessKey":"…"}
  ```

  ```ini
  # ~/.aws/config
  [profile my-profile]
  credential_process = /usr/bin/security find-generic-password -a "$USER" -s aws/my-profile -w
  ```

  and delete that profile's section from `~/.aws/credentials`.
- `aws-vault` does the same with rotation and temporary sessions (`aws-vault add`,
  `aws-vault exec`), but it is not installed.
- In the meantime: `chmod 600 ~/.aws/credentials` and rotate keys older than 90 days
  (`aws iam list-access-keys`).

## Google Cloud and OAuth

- `gcloud auth login` and `gcloud auth application-default login` store user *refresh tokens* in
  `~/.config/gcloud` (`credentials.db`, `application_default_credentials.json`). That is how gcloud
  works; FileVault protects them, and you revoke the ones you no longer need: `gcloud auth list`,
  `gcloud auth revoke ACCOUNT`, `gcloud auth application-default revoke`.
- Service account JSON keys never expire. Replace them with impersonation:
  `gcloud auth application-default login --impersonate-service-account=sa@project.iam.gserviceaccount.com`.
  Then delete the keys: `gcloud iam service-accounts keys list --iam-account=…` and
  `gcloud iam service-accounts keys delete ID --iam-account=…`.
- Tool OAuth token files (`google-drive-token.json`, Gemini's `oauth_creds.json`,
  `gcp-oauth.keys.json`): `chmod 600`, and revoke unused ones at
  <https://myaccount.google.com/connections>.
- Firebase `AIza…` keys in `google-services.json` are client keys, restricted per app in the
  console. `AIza…` keys for Gemini, Maps or YouTube are secrets: restrict them by API and IP, or
  rotate them.

## GitHub and git

- `gh` already keeps its token in the Keychain (`gh auth status` says `keyring`). For scripts use
  `GITHUB_TOKEN="$(gh auth token)"` instead of a PAT pasted into a file.
- `git config --global credential.helper` is already `osxkeychain`. `~/.netrc` is read in plaintext
  by curl, git and other tools: move those credentials to the Keychain or `op` and delete the file.
- Any PAT you still need: *fine-grained*, one repo, with an expiry date.

## Package registries and Docker

- npm: in `~/.npmrc` keep `//registry.npmjs.org/:_authToken=${NPM_TOKEN}` and export `NPM_TOKEN`
  from the Keychain. Use *granular* tokens with an expiry.
- Docker: in `~/.docker/config.json`, `"credsStore": "osxkeychain"` (or `"desktop"` with Docker
  Desktop), then `docker logout && docker login` so the `"auth"` entries go away.
- PyPI and RubyGems: per-project tokens; `chmod 600` on `~/.gem/credentials` and `~/.pypirc`, or
  `keyring` for PyPI.

## Files that must live in the repo

For encrypted config that is versioned, `sops` with `age` (`age` installed, `sops` not):

```bash
age-keygen -o ~/.config/sops/age/keys.txt          # keep a copy of this key in 1Password
cat > .sops.yaml <<'EOF'
creation_rules:
  - path_regex: \.env\.enc$
    age: age1…                                       # the public key printed by age-keygen
EOF
sops -e --input-type dotenv --output-type dotenv .env > .env.enc
sops exec-env .env.enc 'mix phx.server'
```

- Rails: `config/master.key` never in git (it must be in `.gitignore`); its value in 1Password and
  in CI as `RAILS_MASTER_KEY`.
- Elixir: replace `config/*.secret.exs` with `config/runtime.exs` reading `System.fetch_env!/1`,
  with values served by one of the options in [.env files](#env-files).
- `*.pem`, `*.p8`, `*.p12`, Android keystores: in 1Password as documents and outside the repo tree;
  in CI, as pipeline secrets.

## SSH keys

```bash
ssh-keygen -p -f ~/.ssh/id_rsa                        # add a passphrase to an existing key
ssh-add --apple-use-keychain ~/.ssh/id_rsa            # the passphrase is kept in the Keychain
```

`~/.ssh/config` already has `AddKeysToAgent yes` and `UseKeychain yes`. Better than keeping old
RSA keys:

- A new `ssh-keygen -t ed25519` key with a passphrase, or a key in the 1Password SSH agent
  (`IdentityAgent "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"`), which never
  leaves the private key on disk.
- With a hardware key: `ssh-keygen -t ed25519-sk -O resident -O verify-required`. Apple's `ssh` has
  no FIDO support; it needs Homebrew's `openssh`.
- When switching keys, remove the old one from GitHub (`gh ssh-key list`, `gh ssh-key delete`) and
  from `authorized_keys` on every server.

## Shell history

`segurata redact --path ~/.zsh_history --apply` replaces each secret in place and keeps the
`: <ts>:<d>;cmd` format. A shell still open holds the old lines in memory and may write them back
when it exits: close the other terminals first and run `fc -R` in the one left afterwards. To
delete whole lines instead, from a single terminal:

```bash
fc -W                                                                        # flush in-memory history
LC_ALL=C sed -i '' -E '/sk-ant-|sk-proj-|sk-or-|xai-|ghp_|github_pat_|AKIA|_TOKEN=|_KEY=/d' ~/.zsh_history
fc -R ~/.zsh_history
rm -rf ~/.zsh_sessions                                                        # Terminal.app per-tab history
```

To stop saving them, in `~/.zshrc`:

```bash
setopt HIST_IGNORE_SPACE            # a command starting with a space is not saved
HISTORY_IGNORE="(*_KEY=*|*TOKEN=*|*SECRET=*|*PASSWORD=*|*sk-*|*ghp_*)"
```

Whatever was typed with the key already went through the shell: if it was also pasted into an agent
or uploaded somewhere, [rotate](#in-git-always-rotate).

## Agent transcripts

A secret found in `~/.claude/projects`, `~/.codex/sessions` or `~/.cursor/projects` was sent to the
model provider. Treat it as leaked: **rotate**.

Then remove the local copies: `segurata redact --trails` (dry run, then `--apply`) replaces each
secret inside the transcripts and keeps them readable. Or delete the transcripts that contain it
(the list comes from the jsonl, without values):

```bash
jq -r 'select(.evidence.kind=="transcript") | .evidence.path' out/*/local-secrets.jsonl | sort -u
```

or, for one secret, `segurata rotations show <id>` lists every transcript that holds it.

To keep them from piling up:

- Claude Code: `"cleanupPeriodDays": 14` in `~/.claude/settings.json` deletes older sessions.
- Codex: `[history] persistence = "none"` in `~/.codex/config.toml` stops writing
  `history.jsonl`; sessions in `~/.codex/sessions` must be pruned by hand.
- Do not paste keys into a chat. Ask the agent to use `op run`/`op read` or the `kc` Keychain
  function, so it sees the reference and not the value.

## Logs

- Truncate or delete logs with secrets (`: > log/development.log`), or replace just the secrets:
  `segurata redact --path ~/src/app/log/development.log --apply` (the logs `local-secrets` scans:
  `*.log` under `repos_root`, `~/Library/Logs`, `~/.local/log`).
- Filter parameters: Rails `config.filter_parameters += [:token, :api_key, :password, :secret]`;
  Phoenix `config :phoenix, :filter_parameters, ["password", "token", "api_key", "secret"]`.
- If the log was uploaded somewhere (Sentry, CI, an issue), [rotate](#in-git-always-rotate).
