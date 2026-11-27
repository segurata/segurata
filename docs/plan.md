# Securing a digital life: the plan

Legend: **P0** today, **P1** this week, **P2** this month. **[S]** a script can audit it, method in brackets. Minutes are estimates.

## 1. Google accounts and Workspace administration

| P | Action | Threat | Min | Where | [S] |
|---|---|---|---|---|---|
| P0 | Run Security Checkup on every account: sessions, devices, recovery phone and email | Recovery pointing at an old number or address; stolen sessions | 5 per account | https://myaccount.google.com/security-checkup | CDP, per account |
| P0 | Revoke third-party apps with Gmail or Drive access you no longer use | An OAuth grant survives a password change and 2FA | 10 per account | https://myaccount.google.com/connections | **CDP** (personal accounts have no API) |
| P0 | Passkey or FIDO2 key on every account; remove SMS as a second factor | Proxy phishing (AiTM) and SIM swap | 5 per account | https://myaccount.google.com/signinoptions/passkeys | CDP |
| P1 | Advanced Protection on the personal Gmail and the admin accounts | Phishing aimed at an executive; restricts OAuth and downloads | 15 | https://landing.google.com/advancedprotection/ | No |
| P0 | Workspace: enforce 2SV with a security key, at least for admins | Takeover of an admin account, which controls the whole domain | 15 per tenant | Admin › Security › 2-step verification | **API**: Directory `users.list` (`isEnrolledIn2Sv`, `isEnforcedIn2Sv`) |
| P0 | Superadmin on a separate account not used day to day | Keep daily use apart from the most privileged role | 20 | admin.google.com | Directory API (`isAdmin`) |
| P1 | API controls: block unconfigured apps, trust only the ones needed | Malicious OAuth consent by employees | 30 per tenant | Admin › Security › API controls (`admin.google.com/ac/owl`) | **API**: Directory `tokens.list` per user and Reports `applicationName=token` |
| P1 | Go through the official checklist: alerts, DMARC, external forwarding, Drive sharing | Silent exfiltration | 60 | https://support.google.com/a/answer/9184226 | Partial API (Reports, Gmail settings) |
| P2 | Inactive Account Manager | Recovery if something happens to you | 5 | https://myaccount.google.com/inactive | No |

## 2. Password manager, passkeys and hardware keys

- **P0** Two FIDO2 keys (YubiKey or similar), one kept in a safe. Register both on Google, GitHub, Cloudflare, AWS root, Stripe, the password manager and the exchanges. Without a backup key, losing the main one locks you out of everything. 30 min.
- **P0** Protect the password manager with a long master password plus a hardware key, and review its reused or breached password report (1Password Watchtower, Bitwarden Reports). The manager is the single point of failure. 20 min. [S] Export the report via CLI (`op`, `bw`) without dumping secrets.
- **P1** Move to passkeys where available and drop SMS codes. 30 min.
- **P1** Print recovery codes and keep them on paper, outside the manager and off the Mac. 20 min.

## 3. Email and phone: SIM swap

- **P0** Ask your carrier for a PIN or password on number ports and SIM replacements, if they offer one. A duplicate SIM gives access to SMS, account recovery and banking. 15 min. Source: INCIBE.
- **P0** Remove the phone number as a recovery method on Google, GitHub and the exchanges, or keep it only as a last resort behind a key. 15 min. [S] CDP.
- **P1** Use a secondary, non-public number or eSIM for banking 2FA. 30 min.
- Warning sign: losing signal where you always have it. Call the carrier and the bank right away. INCIBE's helpline in Spain is **017**.

## 4. OAuth grants and connected apps outside Google

| Service | URL | [S] |
|---|---|---|
| GitHub (OAuth apps, GitHub Apps, sessions) | https://github.com/settings/applications, `/settings/installations`, `/settings/sessions` | CDP (no user API for OAuth grants); `gh api /user/installations` |
| Microsoft | https://account.live.com/consent/Manage | CDP |
| Dropbox | https://www.dropbox.com/account/connected_apps | CDP |
| X | https://x.com/settings/connected_apps | CDP |
| Apple (Sign in with Apple, devices) | https://account.apple.com/account/manage | CDP |
| Slack | `<workspace>.slack.com/apps/manage` | `admin.apps.approved.list` API on Enterprise; otherwise CDP |
| Notion | Settings › Connections, inside the app | CDP |

**P0** for GitHub, Google and Microsoft (10 min each). **P1** for the rest. The threat is the same everywhere: a long-lived token held by an abandoned or compromised app.

## 5. macOS and Brave

- **P0** Check that FileVault is on, macOS is up to date and the firewall is enabled. An unencrypted stolen laptop exposes everything. 10 min. [S] **CLI**: `fdesetup status`, `softwareupdate -l`, `socketfilterfw --getglobalstate`, `spctl --status`, `csrutil status`.
- **P0** On a Windows PC: BitLocker or Device encryption on, Windows up to date, Microsoft Defender Firewall and real-time protection on, User Account Control on. 10 min. [S] `segurata inventory windows`.
- **P0** Review Brave extensions at `brave://extensions` and remove the ones you don't use. Extensions bought by third parties steal session cookies. 10 min. [S] **Local file**: `~/Library/Application Support/BraveSoftware/Brave-Browser/*/Preferences` (IDs and permissions).
- **P1** Review login items and background services. 10 min. [S] `sfltool dumpbtm`.
- **P1** On the iPhone: Stolen Device Protection and Advanced Data Protection for iCloud. 10 min.
- **P2** Lockdown Mode only if your risk profile calls for it.

## 6. Developer secrets

- **P0** Scan every repo under `~/src`, git history included, with gitleaks or trufflehog. A token that has sat in history for years is still valid. 30 min. [S] **Local scan**.
- **P0** Inventory plaintext secrets on disk: `.env*`, `~/.aws/credentials`, `~/.config/gcloud`, `~/.npmrc`, `~/.netrc`, `~/.docker/config.json`, shell history (patterns `sk-`, `ghp_`, `AKIA`). 20 min. [S] Local scan, reporting path and type, never the value.
- **P0** Check whether SSH keys have a passphrase; move keys to the 1Password SSH agent or a FIDO key (`ed25519-sk`). Review the keys registered on GitHub. 20 min. [S] `ssh-keygen -y -P "" -f key`: if it succeeds, the key has no passphrase. `gh api /user/keys /user/ssh_signing_keys /user/gpg_keys`.
- **P0** AWS: hardware-key MFA on root, no access keys on root, rotate keys older than 90 days. 20 min. [S] `aws iam get-account-summary` and `aws iam generate-credential-report`.
- **P1** GCP: delete service-account JSON keys; prefer Workload Identity. [S] `gcloud iam service-accounts keys list`.
- **P1** Cloudflare: replace the Global API Key with least-privilege tokens with TTL and IP restrictions; enforce 2FA on every account; Full (strict) SSL, TLS 1.2 minimum and DNSSEC on every zone. [S] **cloudflare** connector: `GET /user/tokens`, account settings and members, zone settings and DNSSEC; the Global API Key stays a manual check.
- **P1** Stripe: use restricted keys and remove unused secret keys. [S] CDP inventory of the dashboard.
- **P1** AI service keys: one per project, with a spend limit; revoke unused ones. [S] Local scan plus each provider's console or admin API.
- **P1** Enable secret scanning and push protection on GitHub organizations. [S] **github** connector: `security_and_analysis` per repository and the organization's default code security configurations.

## 7. Finance and crypto

- **P0** Binance and Bybit: hardware key or passkey, no SMS, withdrawal address whitelist with a 24 h lock, anti-phishing code in emails. Without a whitelist, whoever gets in empties the account in minutes. 20 min per exchange.
- **P0** Exchange API keys: no withdrawal permission, restricted to an IP; delete unused ones. 10 min.
- **P1** Wise and banks: app-based 2FA, alerts on every transaction, low transfer limits. 15 min.
- [S] Manual or CDP inventory only. Never automate anything that can write to these accounts.

## 8. Breaches and data brokers

- **P0** Check every email address on Have I Been Pwned and verify company domains in Domain Search. 15 min. [S] **API v3** (paid for per-account search; Pwned Passwords is free and uses k-anonymity).
- **P2** Sign up for Spain's Lista Robinson (https://www.listarobinson.es/) and exercise the GDPR right to erasure with specific brokers.

## 9. Backups and recovery

- **P1** 3-2-1 rule: encrypted Time Machine plus an encrypted offsite copy. Protects against ransomware and theft. 30 min. [S] `tmutil latestbackup`, `tmutil destinationinfo`.
- **P1** Paper emergency kit: recovery codes, the password manager's emergency kit, location of the backup key.
- **P2** Periodic Google Takeout of critical accounts.

## How the repo covers this

Connectors and their scope: [architecture.md](architecture.md).

## Sources (all checked on 2026-11-23)

1. Google Advanced Protection: https://support.google.com/accounts/answer/7539956
2. Google Workspace security checklists: https://support.google.com/a/answer/9184226
3. Workspace, controlling app access: https://support.google.com/a/answer/7281227
4. OAuth token audit events (Admin SDK): https://developers.google.com/admin-sdk/reports/v1/appendix/activity/token
5. CISA, phishing-resistant MFA: https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf
6. NCSC UK, Top tips for staying secure online: https://www.ncsc.gov.uk/collection/top-tips-for-staying-secure-online
7. INCIBE, SIM duplication: https://www.incibe.es/ciudadania/blog/por-que-un-ciberdelincuente-le-interesa-duplicar-tu-tarjeta-sim
8. EFF Surveillance Self-Defense: https://ssd.eff.org/
9. Personal Security Checklist (Lissy93): https://github.com/Lissy93/personal-security-checklist
10. GitHub, reviewing authorized integrations: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/reviewing-your-authorized-integrations
11. AWS, root user best practices: https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
12. Apple, iCloud data security (ADP) and Stolen Device Protection: https://support.apple.com/en-us/102651 and https://support.apple.com/en-us/120340

Also checked: HIBP API v3 (https://haveibeenpwned.com/API/v3), gitleaks (https://github.com/gitleaks/gitleaks), GCP service-account key best practices (https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys), Stripe keys (https://docs.stripe.com/keys), Cloudflare tokens (https://developers.cloudflare.com/fundamentals/api/get-started/create-token/).

Not verifiable without a session: `slack.com/apps/manage` (403 for signed-out clients), exchange dashboards and `admin.google.com/ac/owl`.
