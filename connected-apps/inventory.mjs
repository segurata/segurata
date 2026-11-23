// Read-only inventory of connected apps outside Google: GitHub, Microsoft, Dropbox, X, Slack
// and Notion, using the sessions the browser already has open.
// Never clicks revoke and never submits forms: it only reads pages in background tabs.
//
//   node connected-apps/inventory.mjs                 -> every service
//   node connected-apps/inventory.mjs github x        -> only those
//
// Output: out/connected-apps-<date>.jsonl + summary. Each line:
//   {service, account, status, kind, app, publisher, scopes, lastUsed, authorized, href, note}
//   status: ok | signedout | reauth (the service wants identity confirmed) | noscope (the CLI
//           lacks a permission) | ratelimited | unverified (signed in, but the reader has not
//           been checked against the real page) | error
import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { connect } from "../lib/cdp.mjs";

const CONC = 6;
const today = new Date().toISOString().slice(0, 10);

// Helpers injected into the page. rowOf climbs from a link to the largest container that links
// only to that target (one target can have an icon link and a name link), or to the first
// row-like element (ROW), so a one-item list does not climb up to <body>. uniq drops those
// repeated links and empty ones. No CSS classes beyond GitHub's stable .Box-row.
const PAGE_HELPERS = `
  const lines = (el) => (el?.innerText || "").split("\\n").map((s) => s.trim()).filter(Boolean);
  const hrefs = (el, sel) => new Set([...el.querySelectorAll(sel)].map((x) => x.href)).size;
  const ROW = "li, tr, [role=row], [role=listitem], .Box-row";
  const rowOf = (a, sel) => { let r = a; while (!r.matches(ROW) && r.parentElement && hrefs(r.parentElement, sel) === 1) r = r.parentElement; return r; };
  const uniq = (sel) => { const m = new Map(); for (const a of document.querySelectorAll(sel)) if (a.innerText.trim() && !m.has(a.href)) m.set(a.href, a); return [...m.values()]; };
  const page = () => ({ url: location.href, title: document.title, text: document.body?.innerText || "" });
`;
const inPage = (body) => `(() => { ${PAGE_HELPERS} ${body} })()`;
const parse = (s) => (s ? JSON.parse(s) : null);

// Permission lines between two text markers of a detail page.
function between(text, startRe, endRe, skipRe = /^$/) {
  const ls = text.split("\n").map((s) => s.trim()).filter(Boolean);
  const i = ls.findIndex((l) => startRe.test(l));
  if (i < 0) return [];
  const out = [];
  for (const l of ls.slice(i + 1)) {
    if (endRe.test(l)) break;
    if (!skipRe.test(l)) out.push(l);
  }
  return out;
}

const row = (service, account, fields) => ({ service, account, status: "ok", scopes: [], ...fields });
const statusRow = (service, account, status, href, note) => ({ service, account, status, href, ...(note ? { note } : {}) });

async function inBatches(items, fn) {
  const out = [];
  for (let i = 0; i < items.length; i += CONC) out.push(...await Promise.all(items.slice(i, i + CONC).map(fn)));
  return out;
}

// ---------- GitHub ----------
const GH = "https://github.com/settings";
const ghSudo = (p) => /Confirm access|sudo mode/.test(p.title + p.text);
const ghSignedOut = (p) => /\/login|\/session/.test(new URL(p.url).pathname);
const ghLogin = `document.querySelector('meta[name="user-login"]')?.content || null`;

async function github({ evalAt }) {
  const S = "github", rows = [];
  // OAuth apps, paginated: follow the "Next" link while there is one.
  let url = `${GH}/applications`, account = null;
  const oauth = [];
  while (url) {
    const p = parse(await evalAt(url, inPage(`
      const apps = uniq('a[href*="/settings/connections/applications/"]').map((a) => {
        const ls = lines(rowOf(a, 'a[href*="/settings/connections/applications/"]'));
        const meta = ls.find((l) => /Never used|Last used|Owned by/.test(l)) || "";
        return { app: a.innerText.trim(), href: a.href,
          lastUsed: (meta.match(/^(Never used|Last used[^·]*)/) || [])[1]?.trim() || null,
          publisher: (meta.match(/Owned by (.+)$/) || [])[1]?.trim() || null };
      });
      const next = [...document.querySelectorAll('a[rel="next"], a.next_page'), ...[...document.querySelectorAll("a")].filter((a) => a.innerText.trim() === "Next")].map((a) => a.href)[0] || null;
      return JSON.stringify({ ...page(), login: ${ghLogin}, apps, next });`),
      (s) => { const j = JSON.parse(s); return j.apps.length || /granted|not granted any|No authorized|Confirm access/i.test(j.text) || /login/.test(j.url); }, 40));
    if (!p || ghSignedOut(p)) return [statusRow(S, null, "signedout", `${GH}/applications`)];
    account ||= p.login;
    oauth.push(...p.apps);
    url = p.next && p.next !== url ? p.next : null;
  }
  const details = await inBatches(oauth, (a) => evalAt(a.href, inPage(`return JSON.stringify(page());`),
    (s) => /Organization access|Permissions/.test(JSON.parse(s).text), 30));
  oauth.forEach((a, k) => {
    const text = parse(details[k])?.text || "";
    const scopes = between(text, /^Permissions$/, /^Applications act on your behalf/, /^Revoke access$/);
    const orgLines = between(text, /^Organization access$/, /^Footer$/);
    // An organization not followed by a "Request"/"Grant" button is one the app has access to.
    const orgs = orgLines.filter((l, i) => !/^(Loading|Request|Grant|Requested)$/.test(l) && !/^(Loading|Request|Grant)$/.test(orgLines[i + 1] || ""));
    rows.push(row(S, account, { kind: "oauth", app: a.app, publisher: a.publisher, scopes, lastUsed: a.lastUsed, href: a.href, orgs }));
  });

  // Authorized GitHub Apps: GitHub requires sudo mode; if it asks, report it and move on.
  const auth = parse(await evalAt(`${GH}/apps/authorizations`, inPage(`
    const sel = 'a[href*="/settings/connections/applications/"], a[href*="/settings/apps/authorizations/"]';
    const apps = uniq(sel).map((a) => ({ app: a.innerText.trim(), href: a.href, ls: lines(rowOf(a, sel)) }));
    return JSON.stringify({ ...page(), apps });`),
    (s) => { const j = JSON.parse(s); return j.apps.length || /Confirm access|No authorized|haven.t authorized/i.test(j.title + j.text); }, 30));
  if (auth && ghSudo(auth)) rows.push(statusRow(S, account, "reauth", `${GH}/apps/authorizations`, "Authorized GitHub Apps: GitHub wants identity confirmed (sudo mode). Open the page, confirm, and run again."));
  else for (const a of auth?.apps || []) {
    const meta = a.ls.find((l) => /Never used|Last used|Owned by/.test(l)) || "";
    rows.push(row(S, account, { kind: "github-app-authorized", app: a.app, href: a.href,
      lastUsed: (meta.match(/^(Never used|Last used[^·]*)/) || [])[1]?.trim() || null,
      publisher: (meta.match(/Owned by (.+)$/) || [])[1]?.trim() || null }));
  }

  // GitHub Apps installed on the personal account.
  const inst = parse(await evalAt(`${GH}/installations`, inPage(`
    const sel = 'a[href*="/settings/installations/"]:not([href*="/permissions/"])';
    const apps = [...document.querySelectorAll(sel)].map((a) => ({ href: a.href, ls: lines(rowOf(a, sel)) }));
    return JSON.stringify({ ...page(), apps });`),
    (s) => { const j = JSON.parse(s); return j.apps.length || /no installed|haven.t installed|Confirm access/i.test(j.text); }, 30));
  for (const a of inst?.apps || []) {
    const [app, ...rest] = a.ls.filter((l) => !/^Configure$/.test(l));
    rows.push(row(S, account, { kind: "github-app-installed", app, href: a.href, note: rest.join(" ") || undefined }));
  }

  // Open web sessions.
  const ses = parse(await evalAt(`${GH}/sessions`, inPage(`
    const sel = 'a[href*="/settings/sessions/"]';
    const s = [...document.querySelectorAll(sel)].map((a) => ({ href: a.href, ls: lines(rowOf(a, sel)).filter((l) => !/^(Details|Revoke)$/.test(l)) }));
    return JSON.stringify({ ...page(), s });`),
    (s) => JSON.parse(s).s.length > 0, 30));
  for (const s of ses?.s || []) {
    rows.push(row(S, account, { kind: "session", app: s.ls[0], lastUsed: s.ls.find((l) => /Seen|Last accessed|active/i.test(l)) || null, href: s.href, note: s.ls.slice(1).join(" · ") }));
  }

  rows.push(...githubKeys(account));
  return rows;
}

// SSH, signing and GPG keys through `gh api`. The key material is never stored.
function githubKeys(account) {
  const S = "github", out = [];
  const ENDPOINTS = [
    ["ssh-key", "/user/keys", "admin:public_key"],
    ["ssh-signing-key", "/user/ssh_signing_keys", "admin:ssh_signing_key"],
    ["gpg-key", "/user/gpg_keys", "admin:gpg_key"],
  ];
  const href = `${GH}/keys`;
  for (const [kind, path, scope] of ENDPOINTS) {
    let keys;
    try {
      keys = JSON.parse(execFileSync("gh", ["api", "--paginate", path], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
    } catch (e) {
      const err = `${e.stderr || ""}${e.stdout || ""}${e.message}`;
      if (/ENOENT/.test(err)) return [statusRow(S, account, "signedout", href, "The `gh` CLI is not installed: keys not listed.")];
      if (/not logged in|auth login/i.test(err)) return [statusRow(S, account, "signedout", href, "`gh` is not signed in: run `gh auth login` to list keys.")];
      if (/needs the .* scope|Not Found/.test(err)) { out.push({ ...statusRow(S, account, "noscope", href, `gh lacks the ${scope} scope: gh auth refresh -h github.com -s ${scope}`), kind }); continue; }
      throw e;
    }
    for (const k of keys) {
      out.push(row(S, account, { kind, app: k.title || k.name || (k.emails || []).map((m) => m.email).join(", ") || String(k.key_id || k.id),
        note: (k.key || "").split(" ")[0] || (k.key_id ? `gpg ${k.key_id}` : undefined),
        authorized: k.created_at || null, lastUsed: k.last_used || null, href }));
    }
  }
  return out;
}

// ---------- X ----------
// The connected-apps page loads every grant from one call (oauth/list.json), which X rate-limits
// hard: opening each app's page burns through the limit within a few dozen apps. So the script
// loads the list page once and reads that response. It carries each grant's token, which is
// never stored: only the fields below are kept.
async function x({ withPage }) {
  const S = "x", URL_ = "https://x.com/settings/connected_apps";
  const seen = [];
  const res = await withPage(URL_, async (p) => {
    const dom = parse(await p.waitFor(inPage(`
      const handle = (document.querySelector('a[data-testid="AppTabBar_Profile_Link"]')?.getAttribute("href") || "").replace("/", "@") || null;
      return JSON.stringify({ ...page(), handle, links: document.querySelectorAll('a[href*="/settings/connected_apps/"]').length });`),
      (s) => { const j = JSON.parse(s); return j.links || /\/(login|i\/flow)/.test(j.url) || /went wrong|Algo salió mal/.test(j.text); }, 50));
    const hit = seen.findLast((r) => /\/oauth\/list\.json/.test(r.url));
    const body = hit ? (await p.send("Network.getResponseBody", { requestId: hit.requestId })).result?.body : null;
    return { dom, status: hit?.status, body: parse(body) };
  }, async (p) => {
    await p.send("Network.enable");
    p.on("Network.responseReceived", (e) => seen.push({ url: e.response.url, status: e.response.status, requestId: e.requestId }));
  });
  if (!res.dom || /\/(login|i\/flow)/.test(res.dom.url)) return [statusRow(S, null, "signedout", URL_)];
  if (!res.body?.applications) {
    const why = res.body?.errors?.[0]?.message || res.body?.message || `HTTP ${res.status ?? "?"}`;
    return [statusRow(S, res.dom.handle, /rate limit/i.test(why) ? "ratelimited" : "error", URL_, `X did not return the app list (${why}). Wait 15 minutes and run again.`)];
  }
  // The same app can hold several grants (one per token): one row per app.
  const byApp = new Map();
  for (const a of res.body.applications) {
    const prev = byApp.get(a.app_id);
    const scopes = a.scopes ? a.scopes.map((sc) => sc.name)
      : [a.can_read && "read", a.can_write && "write", a.can_read_dms && "dm.read", a.has_ads_read_access && "ads.read", a.has_ads_read_write_access && "ads.write"].filter(Boolean);
    if (a.email_access && !scopes.includes("users.email")) scopes.push("users.email");
    const r = prev || row(S, res.dom.handle, { kind: a.token_type || "oauth", app: a.name, publisher: a.organization || null,
      href: `${URL_}/${a.app_id}`, grants: 0, scopes: [] });
    r.grants++;
    r.scopes = [...new Set([...r.scopes, ...scopes])];
    const approved = a.approved ? new Date(a.approved).toISOString() : null;
    if (approved && (!r.authorized || approved > r.authorized)) r.authorized = approved;
    if (a.expires_at) r.note = `expires ${new Date(a.expires_at).toISOString().slice(0, 10)}`;
    byApp.set(a.app_id, r);
  }
  return [...byApp.values()];
}

// ---------- Slack ----------
async function slack({ evalAt }) {
  const S = "slack";
  // slack.com/signin lists the workspaces this browser is signed in to.
  const si = parse(await evalAt("https://slack.com/signin", inPage(`
    const ws = [...new Set([...document.querySelectorAll('a[href*=".slack.com/"]')].map((a) => new URL(a.href).hostname).filter((h) => !/^(app|api|www)\\./.test(h)))];
    return JSON.stringify({ ...page(), ws });`),
    (s) => JSON.parse(s).ws.length > 0, 30));
  if (!si?.ws.length) return [statusRow(S, null, "signedout", "https://slack.com/signin")];
  const sel = 'a[href*="/integrations/profile/"]';
  const rows = [];
  for (const host of si.ws) {
    const href = `https://${host}/apps/manage`;
    const p = parse(await evalAt(href, inPage(`
      const apps = uniq('${sel}').map((a) => {
        const ls = lines(rowOf(a, '${sel}'));
        return { app: a.innerText.trim(), href: a.href, scopes: ls.find((l) => /^\\d+ (ámbitos?|scopes?)$/.test(l)) || null,
          note: ls.filter((l) => /^(Aprobado|Aprobación necesaria|Approved|Approval required|Restringido|Restricted)/.test(l)).join(" ") || null };
      });
      return JSON.stringify({ ...page(), apps });`),
      (s) => { const j = JSON.parse(s); return j.apps.length || /workspace-signin|signin/.test(j.url) || /no hay aplicaciones|no apps/i.test(j.text); }, 40));
    if (!p || /signin/.test(p.url)) { rows.push(statusRow(S, host, "signedout", href)); continue; }
    // The list shows only how many scopes each app has; the app page shows the developer's
    // defaults, not what this workspace granted, so it is not read.
    for (const a of p.apps) rows.push(row(S, host, { kind: "workspace-app", app: a.app, scopeCount: parseInt(a.scopes) || null, href: a.href, note: a.note || undefined }));
  }
  return rows;
}

// ---------- Notion ----------
// Notion has no URL for Settings > Connections (it is a modal); the page with a URL is the active
// workspace's developer connections: internal integrations and their capabilities.
async function notion({ evalAt }) {
  const S = "notion", href = "https://www.notion.so/profile/integrations";
  const p = parse(await evalAt(href, inPage(`
    const rows = [...document.querySelectorAll("tr")].map((r) => [...r.querySelectorAll("td")].map(lines)).filter((c) => c.length >= 4 && c[0].length);
    return JSON.stringify({ ...page(), rows });`),
    (s) => { const j = JSON.parse(s); return j.rows.length || /\/login|notion\.com\/?$/.test(j.url) || /No connections|Sin conexiones/i.test(j.text); }, 50));
  if (!p || /\/login/.test(p.url) || /^https:\/\/www\.notion\.com\/?$/.test(p.url)) return [statusRow(S, null, "signedout", href)];
  return p.rows.map(([conn, auth, owner, created]) => {
    const c = conn[0].length === 1 && conn.length > 2 ? conn.slice(1) : conn; // the first line can be the avatar's initial
    return row(S, auth[1]?.replace(/^(Internal to|Interna de) /, "") || null, { kind: "integration", note: auth[0], app: c[0],
      scopes: c[1] ? [c[1]] : [], publisher: owner.join(" "), authorized: created[0] || null, href });
  });
}

// ---------- Microsoft and Dropbox ----------
// Signed out when this script was written: it detects the signed-out state; when signed in, it
// saves the page text for review and marks the service unverified.
const pageOnly = (S, href, signedOutRe) => async ({ evalAt }) => {
  const p = parse(await evalAt(href, inPage(`return JSON.stringify(page());`), (s) => JSON.parse(s).text.length > 200, 40));
  if (!p || signedOutRe.test(p.url)) return [statusRow(S, null, "signedout", href)];
  const file = `out/connected-apps-${S}-${today}.txt`;
  writeFileSync(file, p.text);
  return [statusRow(S, null, "unverified", href, `Signed in, but the reader for this page is unverified. Page text saved to ${file}.`)];
};
const microsoft = pageOnly("microsoft", "https://account.live.com/consent/Manage", /login\.(live|microsoftonline)\.com/);
const dropbox = pageOnly("dropbox", "https://www.dropbox.com/account/connected_apps", /dropbox\.com\/login/);

// ---------- main ----------
const SERVICES = { github, microsoft, dropbox, x, slack, notion };
const wanted = process.argv.slice(2);
const unknown = wanted.filter((s) => !SERVICES[s]);
if (unknown.length) {
  console.error(`Unknown service: ${unknown.join(", ")}. Available: ${Object.keys(SERVICES).join(", ")}`);
  process.exit(2);
}
mkdirSync("out", { recursive: true });
const cdp = await connect();
const rows = [];
for (const name of wanted.length ? wanted : Object.keys(SERVICES)) {
  try {
    const r = await SERVICES[name](cdp);
    rows.push(...r);
    const failed = r.filter((x) => x.status !== "ok").map((x) => x.status);
    console.error(`${name}: ${r.length - failed.length} rows${failed.length ? `, ${failed.join(", ")}` : ""}`);
  } catch (e) {
    rows.push(statusRow(name, null, "error", null, e.message));
    console.error(`${name}: error ${e.message}`);
  }
}
cdp.close();

const file = `out/connected-apps-${today}.jsonl`;
writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

// Summary: counts per service and kind, broad permissions, and services without data.
const BROAD = /full control|delete repositor|write|insert|^dm\.|admin/i;
const broad = (r) => r.status === "ok" && !/key|session/.test(r.kind) && (r.scopeCount >= 15 || r.scopes.some((s) => BROAD.test(s)));
const counts = {};
for (const { service, kind } of rows.filter((r) => r.status === "ok")) counts[`${service}/${kind}`] = (counts[`${service}/${kind}`] ?? 0) + 1;
console.log("Counts:");
for (const [k, n] of Object.entries(counts)) console.log(`  ${k}: ${n}`);
console.log("\nBroad permissions:");
for (const r of rows.filter(broad)) console.log(`  [${r.service}] ${r.app}${r.lastUsed ? ` (${r.lastUsed})` : ""}: ${r.scopeCount ? `${r.scopeCount} scopes` : r.scopes.filter((s) => BROAD.test(s)).join(" | ")}`);
const other = rows.filter((r) => r.status !== "ok");
if (other.length) {
  console.log("\nNo data:");
  for (const r of other) console.log(`  [${r.service}${r.account ? ` ${r.account}` : ""}] ${r.status}${r.note ? `: ${r.note}` : ""}`);
}
console.log(`\nFull list: ${file}`);
process.exit(0);
