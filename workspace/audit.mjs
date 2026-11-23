// Read-only audit of a Google Workspace tenant with the Admin SDK: 2SV, admins,
// suspended or inactive accounts and third-party apps holding OAuth grants.
// Only GET requests with read-only scopes: nothing in the tenant is changed.
//
//   node workspace/audit.mjs example.com [example.org ...] [--inactive-days 90] [--quota-project ID]
//
// Output per tenant: out/workspace-<domain>-<date>.jsonl + summary. Line types:
//   user  {email, name, isAdmin, isDelegatedAdmin, enrolled2sv, enforced2sv, lastLoginTime, suspended, archived, inactiveDays}
//   grant {user, app, clientId, scopes, nativeApp, anonymous}          one per user and app (tokens.list)
//   app   {app, clientId, users, scopes}                               aggregated from the grants
//   token-activity {app, clientId, authorize, revoke, lastEvent}       Reports API, last 30 days
//
// Credentials: a separate gcloud config per tenant, so the usual ADC is left alone.
// The first sign-in is done by hand (the script never does it); see loginHelp().
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const SCOPES = [
  "https://www.googleapis.com/auth/admin.directory.user.readonly",
  "https://www.googleapis.com/auth/admin.directory.user.security",
  "https://www.googleapis.com/auth/admin.reports.audit.readonly",
];
const REPORTS_SCOPE = SCOPES[2];
const API = "https://admin.googleapis.com/admin";
const CONC = 5;
const DAY = 86400000;
const USAGE = "Usage: node workspace/audit.mjs <domain> [<domain> ...] [--inactive-days 90] [--quota-project ID]";

export const configDir = (domain) => join(homedir(), ".config", "securizame", `gcloud-${domain}`);

// gcloud requires cloud-platform on the ADC login; the token this script requests carries only
// the read-only SCOPES. An own OAuth client is needed because gcloud's default client does not
// allow scopes outside Google Cloud.
export function loginHelp(domain) {
  return [
    `No admin credentials for ${domain} with the read-only Admin SDK scopes.`,
    "One-time steps per tenant:",
    "  1. In a Google Cloud project of the tenant: enable \"Admin SDK API\" and create an OAuth client ID",
    "     of type \"Desktop app\". Download its JSON (for example ~/Downloads/client_secret.json).",
    "  2. Sign in with an admin account of the tenant, in a separate gcloud config:",
    `     CLOUDSDK_CONFIG="${configDir(domain)}" gcloud auth application-default login \\`,
    "       --client-id-file=$HOME/Downloads/client_secret.json \\",
    `       --scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform,${SCOPES.join(",")}`,
    "Then run this script again. To authenticate some other way, export WORKSPACE_ACCESS_TOKEN.",
  ].join("\n");
}

export class AuditError extends Error {}

export function parseArgs(argv) {
  const opts = { domains: [], inactiveDays: 90, quotaProject: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--inactive-days") {
      opts.inactiveDays = Number(argv[++i]);
      if (!Number.isInteger(opts.inactiveDays) || opts.inactiveDays <= 0) throw new AuditError("--inactive-days needs a whole number of days.");
    } else if (a === "--quota-project") {
      opts.quotaProject = argv[++i];
      if (!opts.quotaProject) throw new AuditError("--quota-project needs a Google Cloud project ID.");
    } else if (a === "-h" || a === "--help") {
      opts.help = true;
    } else if (a.startsWith("-")) {
      throw new AuditError(`Unknown option: ${a}`);
    } else if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(a)) {
      opts.domains.push(a.toLowerCase());
    } else {
      throw new AuditError(`"${a}" does not look like a domain.`);
    }
  }
  if (!opts.help && !opts.domains.length) throw new AuditError("Give at least one domain: node workspace/audit.mjs example.com");
  return opts;
}

// Access token for a tenant: WORKSPACE_ACCESS_TOKEN if set; otherwise the ADC stored in that
// tenant's gcloud config, requesting only the read-only scopes.
export function accessToken(domain, { env = process.env, exec = execFileSync } = {}) {
  if (env.WORKSPACE_ACCESS_TOKEN) return env.WORKSPACE_ACCESS_TOKEN;
  const dir = configDir(domain);
  if (!existsSync(join(dir, "application_default_credentials.json"))) throw new AuditError(loginHelp(domain));
  try {
    return exec("gcloud", ["auth", "application-default", "print-access-token", `--scopes=${SCOPES.join(",")}`],
      { encoding: "utf8", env: { ...env, CLOUDSDK_CONFIG: dir }, stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (e) {
    if (e.code === "ENOENT") throw new AuditError("`gcloud` not found. Install the Google Cloud SDK or export WORKSPACE_ACCESS_TOKEN.");
    throw new AuditError(`gcloud could not issue a token for ${domain} (${String(e.stderr || e.message).trim().split("\n").pop()}).\n\n${loginHelp(domain)}`);
  }
}

// Checks with tokeninfo which scopes and account the token carries, before calling the API.
export async function checkToken(domain, token, fetchFn = fetch) {
  const r = await fetchFn("https://oauth2.googleapis.com/tokeninfo", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: `access_token=${encodeURIComponent(token)}` });
  const info = await r.json();
  if (!r.ok) throw new AuditError(`The token is not valid (${info.error_description || r.status}).\n\n${loginHelp(domain)}`);
  const granted = new Set((info.scope || "").split(" "));
  const missing = SCOPES.slice(0, 2).filter((s) => !granted.has(s));
  if (missing.length) throw new AuditError(`The token lacks scopes: ${missing.join(", ")}.\n\n${loginHelp(domain)}`);
  if (info.email && !info.email.toLowerCase().endsWith(`@${domain}`)) {
    throw new AuditError(`The credentials for ${domain} belong to ${info.email}, outside that domain. Sign in again with an admin account of ${domain}.`);
  }
  return { email: info.email || null, reports: granted.has(REPORTS_SCOPE) };
}

// Paginated GET (nextPageToken). Turns the usual Admin SDK errors into actionable messages.
function client(domain, token, { fetchFn = fetch, quotaProject = null } = {}) {
  const headers = { authorization: `Bearer ${token}`, ...(quotaProject ? { "x-goog-user-project": quotaProject } : {}) };
  async function get(url) {
    const r = await fetchFn(url, { headers });
    const body = await r.json().catch(() => ({}));
    if (r.ok) return body;
    const msg = body.error?.message || r.statusText;
    const reason = body.error?.errors?.[0]?.reason || body.error?.status || "";
    if (/SERVICE_DISABLED|accessNotConfigured|has not been used in project|API has not been used/i.test(msg + reason)) {
      throw new AuditError(`The Admin SDK API is not enabled in the quota project (${msg}). Enable it there or pass --quota-project <ID> for a project where it is.`);
    }
    if (r.status === 401) throw new AuditError(`Token rejected (401: ${msg}).\n\n${loginHelp(domain)}`);
    if (r.status === 403) throw new AuditError(`Forbidden (403: ${msg}). The account must be an admin of ${domain} with read privileges on users and security.`);
    throw new AuditError(`Error ${r.status} on ${new URL(url).pathname}: ${msg}`);
  }
  async function all(url, key) {
    const out = [];
    let page = null;
    do {
      const u = new URL(url);
      if (page) u.searchParams.set("pageToken", page);
      const body = await get(u.toString());
      out.push(...(body[key] || []));
      page = body.nextPageToken;
    } while (page);
    return out;
  }
  return { get, all };
}

const isLive = (u) => !u.suspended && !u.archived;
const daysSince = (iso, now) => (iso ? Math.floor((now - Date.parse(iso)) / DAY) : null);
const NEVER = "1970-01-01T00:00:00.000Z";

export async function audit(domain, token, { fetchFn = fetch, quotaProject = null, inactiveDays = 90, now = Date.now(), reports = true } = {}) {
  const api = client(domain, token, { fetchFn, quotaProject });
  const fields = "nextPageToken,users(primaryEmail,name/fullName,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,lastLoginTime,creationTime,suspended,archived)";
  const raw = await api.all(`${API}/directory/v1/users?customer=my_customer&maxResults=500&orderBy=email&fields=${encodeURIComponent(fields)}`, "users");
  const users = raw.map((u) => {
    const never = !u.lastLoginTime || u.lastLoginTime === NEVER;
    return { type: "user", email: u.primaryEmail, name: u.name?.fullName || null,
      isAdmin: !!u.isAdmin, isDelegatedAdmin: !!u.isDelegatedAdmin,
      enrolled2sv: !!u.isEnrolledIn2Sv, enforced2sv: !!u.isEnforcedIn2Sv,
      lastLoginTime: never ? null : u.lastLoginTime, suspended: !!u.suspended, archived: !!u.archived,
      // With no login at all, inactivity counts from account creation.
      inactiveDays: daysSince(never ? u.creationTime : u.lastLoginTime, now) };
  });

  // Third-party OAuth grants, user by user (suspended accounts cannot use them).
  const grants = [];
  const active = users.filter(isLive);
  for (let i = 0; i < active.length; i += CONC) {
    const batch = await Promise.all(active.slice(i, i + CONC).map((u) =>
      api.get(`${API}/directory/v1/users/${encodeURIComponent(u.email)}/tokens`).then((b) => [u, b.items || []])));
    for (const [u, items] of batch) for (const t of items) {
      grants.push({ type: "grant", user: u.email, app: t.displayText || t.clientId, clientId: t.clientId, scopes: t.scopes || [], nativeApp: !!t.nativeApp, anonymous: !!t.anonymous });
    }
  }
  const byApp = new Map();
  for (const g of grants) {
    const a = byApp.get(g.clientId) || { type: "app", app: g.app, clientId: g.clientId, users: 0, scopes: new Set(), userList: [] };
    a.users++; a.userList.push(g.user); g.scopes.forEach((s) => a.scopes.add(s));
    byApp.set(g.clientId, a);
  }
  const apps = [...byApp.values()].map((a) => ({ ...a, scopes: [...a.scopes].sort() })).sort((x, y) => y.users - x.users || x.app.localeCompare(y.app));

  // Reports API: authorizations and revocations over the last 30 days, if the token allows it.
  let activity = [];
  if (reports) {
    const start = new Date(now - 30 * DAY).toISOString();
    const items = await api.all(`${API}/reports/v1/activity/users/all/applications/token?maxResults=1000&startTime=${start}`, "items");
    const acc = new Map();
    for (const it of items) for (const ev of it.events || []) {
      const p = Object.fromEntries((ev.parameters || []).map((x) => [x.name, x.value ?? x.multiValue]));
      const key = p.client_id || p.app_name;
      if (!key) continue;
      const a = acc.get(key) || { type: "token-activity", app: p.app_name || key, clientId: p.client_id || null, authorize: 0, revoke: 0, lastEvent: null };
      if (ev.name === "authorize") a.authorize++;
      if (ev.name === "revoke") a.revoke++;
      if (!a.lastEvent || it.id?.time > a.lastEvent) a.lastEvent = it.id?.time || a.lastEvent;
      acc.set(key, a);
    }
    activity = [...acc.values()].sort((x, y) => y.authorize - x.authorize);
  }

  return { users, grants, apps, activity, inactiveDays };
}

const adminFirst = (a, b) => (b.isAdmin - a.isAdmin) || (b.isDelegatedAdmin - a.isDelegatedAdmin) || a.email.localeCompare(b.email);

export function summarize(domain, { users, apps, activity, inactiveDays }) {
  const out = [];
  const role = (u) => (u.isAdmin ? "superadmin" : u.isDelegatedAdmin ? "delegated admin" : "user");
  const live = users.filter(isLive);
  const no2sv = live.filter((u) => !u.enforced2sv || !u.enrolled2sv).sort(adminFirst);
  out.push(`== ${domain}: ${users.length} accounts, ${live.length} active`);
  out.push(`\n2SV not enforced or not enrolled (${no2sv.length}):`);
  for (const u of no2sv) out.push(`  [${role(u)}] ${u.email}: enrolled=${u.enrolled2sv ? "yes" : "no"}, enforced=${u.enforced2sv ? "yes" : "no"}`);
  const admins = users.filter((u) => u.isAdmin || u.isDelegatedAdmin).sort(adminFirst);
  out.push(`\nAdmins (${admins.length}):`);
  for (const u of admins) out.push(`  [${role(u)}] ${u.email}${u.suspended ? " (suspended)" : ""}, last login ${u.lastLoginTime?.slice(0, 10) || "never"}`);
  const stale = users.filter((u) => u.suspended || u.archived || u.inactiveDays > inactiveDays).sort((a, b) => (b.inactiveDays ?? 0) - (a.inactiveDays ?? 0));
  out.push(`\nSuspended, archived or no login in over ${inactiveDays} days (${stale.length}):`);
  for (const u of stale) out.push(`  ${u.email}: ${u.suspended ? "suspended" : u.archived ? "archived" : `${u.inactiveDays} days`}${u.lastLoginTime ? "" : " (never logged in)"}${u.isAdmin || u.isDelegatedAdmin ? ` [${role(u)}]` : ""}`);
  out.push(`\nThird-party apps by number of users (${apps.length}, top 20):`);
  for (const a of apps.slice(0, 20)) out.push(`  ${a.users} · ${a.app}: ${a.scopes.join(" ")}`);
  if (activity.length) {
    out.push("\nOAuth activity over 30 days (authorizations / revocations):");
    for (const a of activity.slice(0, 15)) out.push(`  ${a.authorize}/${a.revoke} · ${a.app}`);
  }
  return out.join("\n");
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) { console.log(USAGE); return 0; }
  mkdirSync("out", { recursive: true });
  const date = new Date().toISOString().slice(0, 10);
  let failed = 0;
  for (const domain of opts.domains) {
    try {
      const token = accessToken(domain);
      const info = await checkToken(domain, token);
      if (!info.reports) console.error(`${domain}: the token lacks ${REPORTS_SCOPE}; skipping OAuth activity.`);
      const res = await audit(domain, token, { quotaProject: opts.quotaProject, inactiveDays: opts.inactiveDays, reports: info.reports });
      const file = `out/workspace-${domain}-${date}.jsonl`;
      writeFileSync(file, [...res.users, ...res.grants, ...res.apps, ...res.activity].map((r) => JSON.stringify(r)).join("\n") + "\n");
      console.log(summarize(domain, res));
      console.log(`\nFull list: ${file}\n`);
    } catch (e) {
      if (!(e instanceof AuditError)) throw e;
      failed++;
      console.error(`\n[${domain}] ${e.message}\n`);
    }
  }
  return failed ? 1 : 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().then((code) => process.exit(code), (e) => {
    console.error(e instanceof AuditError ? e.message : e);
    process.exit(e instanceof AuditError ? 2 : 1);
  });
}
