# securizame

Scripts y listas para revisar y limpiar la seguridad de mis cuentas.

Regla de la casa: cada script **inventaría primero y en solo lectura**. Quitar accesos es otro paso,
a mano o con un script aparte, después de revisar la lista.

## Google: aplicaciones vinculadas

```bash
node google/linked-apps-inventory.mjs
```

Recorre todas las cuentas de Google con sesión abierta en el navegador y, para cada una, saca las
apps con acceso a datos (`access`, con sus permisos) y las que solo usan «Iniciar sesión con Google»
(`signin`). Las cuentas en las que Google pide volver a entrar salen como `reauth`.

- Requisito: Brave o Chrome arrancado con `--remote-debugging-port=9222` (otro puerto con
  `SECURIZAME_CDP`). Las páginas se abren en segundo plano y se cierran solas, sin tocar tus pestañas.
- Salida: `out/google-linked-apps-<fecha>.jsonl`. `out/` está en `.gitignore`, porque contiene
  correos y la lista de servicios de cada cuenta.
- Para quitar un acceso: <https://myaccount.google.com/connections> en la cuenta que toque, o el
  campo `href` de cada fila, que lleva directo a la ficha de la app.

## Connected apps outside Google

```bash
node connected-apps/inventory.mjs              # every service
node connected-apps/inventory.mjs github x     # only those
```

Using the sessions the browser already has open, lists the apps with access to each account,
their permissions, and the authorization or last-used date when the service shows it. `href`
points to the page where access is revoked.

| Service | What it lists |
|---|---|
| GitHub | OAuth apps (scopes and organizations with access), authorized and installed GitHub Apps, web sessions; SSH, signing and GPG keys via `gh api` (title, type, dates, never the key) |
| X | Connected apps with scopes and authorization date |
| Slack | Installed apps and their scope count, in every workspace the browser is signed in to |
| Notion | Developer connections of the active workspace, with capabilities, owner and date |
| Microsoft, Dropbox | Detects whether there is a session; when signed in it saves the page text under `out/` for review, because the reader has not been checked against the real page |

`status` of each row: `ok`; `signedout`; `reauth` when the service wants identity confirmed
(GitHub requires sudo mode for authorized GitHub Apps: open the page, confirm, run again);
`noscope` when `gh` lacks a scope (the message carries the exact `gh auth refresh`);
`ratelimited`; `unverified`; `error`.

- Requires the same browser setup as the Google script, plus a signed-in `gh` for GitHub keys.
- Output: `out/connected-apps-<date>.jsonl` and a summary with counts, apps with broad
  permissions (write, full control, delete, or more than 15 Slack scopes) and services without data.
- X rate-limits its connected-apps API hard. The script loads the list page once and reads the
  app list from that page's own API response (the grant tokens in it are dropped, never stored);
  opening each app's page exhausts the limit. If X answers "Rate limit exceeded", wait 15 minutes.
- Notion has no URL for Settings > Connections (it is a modal): review those by hand.

## Google Workspace: admin audit

```bash
node workspace/audit.mjs example.com example.org [--inactive-days 90] [--quota-project ID]
node --test workspace/        # tests with a mocked fetch, no network
```

Per tenant, read-only through the Admin SDK: accounts without 2SV enrolled or enforced (admins
first), admins, accounts suspended or without a login in over 90 days, and third-party apps with
OAuth grants ranked by number of users, with their scopes (`tokens.list` per user). If the token
allows it, adds OAuth authorizations and revocations over the last 30 days (Reports API,
`applicationName=token`).

Credentials, once per tenant. The script never signs in and never creates service accounts:

1. In a Google Cloud project of the tenant, enable "Admin SDK API" and create an OAuth client ID
   of type "Desktop app". gcloud's default client does not allow scopes outside Google Cloud.
2. Sign in with an admin account of the tenant in a separate gcloud config, so the usual ADC is
   left alone:

   ```bash
   CLOUDSDK_CONFIG="$HOME/.config/securizame/gcloud-example.com" \
     gcloud auth application-default login \
     --client-id-file=$HOME/Downloads/client_secret.json \
     --scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.reports.audit.readonly
   ```

   gcloud requires `cloud-platform` on that login. The token the script then requests carries only
   the three read-only Admin SDK scopes, and the script checks the account belongs to the audited
   domain.

- Without credentials the script stops and prints that same command with the tenant's path.
- `WORKSPACE_ACCESS_TOKEN` replaces gcloud when the token comes from elsewhere.
- If the Admin SDK API is not enabled in the quota project, pass `--quota-project <ID>`.
- Output: `out/workspace-<domain>-<date>.jsonl`, with `user`, `grant`, `app` and
  `token-activity` lines, plus the summary on screen.

## Plan

Acciones por área y prioridad, con fuentes comprobadas y qué se puede auditar por script: [docs/plan.md](docs/plan.md).
