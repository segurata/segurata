// Read-only inventory of Google "linked apps" (third-party OAuth grants and
// Sign in with Google) for every Google account signed in to the browser.
// Never clicks anything: removal is done by hand, or by a separate script after review.
//
//   node google/linked-apps-inventory.mjs            -> out/google-linked-apps-<date>.jsonl + summary
//
// Each line: {u, account, status, app, kind, scopes, href}
//   status: ok | reauth (Google wants a fresh sign-in before showing the page)
//   kind:   access (holds data scopes) | signin (only Sign in with Google)
import { mkdirSync, writeFileSync } from "node:fs";
import { connect } from "../lib/cdp.mjs";

const MAX_ACCOUNTS = 20, CONC = 6;
const ICONS = new Set(["pentagon", "account_circle", "Delete all", "Eliminar todas", "See details", "Ver detalles"]);

const listJS = `JSON.stringify({
  mail: ((document.documentElement.innerHTML.match(/"([\\w.+-]+@[\\w-]+\\.[\\w.-]+)"/) || [])[1]) || null,
  reauth: /Verify (it.s|that it.s) you|Demuestra que eres t/.test(document.body.innerText),
  apps: [...document.querySelectorAll('a[href*="linkedapps/overview/"]')].map(a => ({app: a.innerText.trim(), href: a.href}))
})`;
const detailJS = `(document.querySelector('main') || document.body).innerText`;

// Turns an overview page's text into the list of data scopes, empty for sign-in only.
function scopesOf(text) {
  const m = text.match(/(has some access|tiene acceso parcial)[^\n]*\n([\s\S]*)/);
  if (!m) return [];
  return m[2].split("\n").map((s) => s.trim())
    .filter((s) => s && !ICONS.has(s) && !/^(Quita|Remove|¿Ves|See something|Para usar|To use|Privacidad|Privacy)/.test(s));
}

const { evalAt, close } = await connect();
const rows = [], seen = new Set();
for (let u = 0; u < MAX_ACCOUNTS; u++) {
  const raw = await evalAt(`https://myaccount.google.com/u/${u}/connections`, listJS,
    (s) => { const j = JSON.parse(s); return j.reauth || j.apps.length > 0; }, 24);
  const page = JSON.parse(raw || '{"apps":[]}');
  // Past the last account Google falls back to the default one: stop there.
  if (!page.mail || seen.has(page.mail)) break;
  seen.add(page.mail);
  if (page.reauth) {
    rows.push({ u, account: page.mail, status: "reauth" });
    console.error(`u${u} ${page.mail}: needs a fresh sign-in`);
    continue;
  }
  for (let i = 0; i < page.apps.length; i += CONC) {
    const batch = page.apps.slice(i, i + CONC);
    const texts = await Promise.all(batch.map((a) =>
      evalAt(a.href, detailJS, (t) => /(acceso|access|Iniciar sesión|Sign in)/i.test(t) && t.length > 200)));
    batch.forEach((a, k) => {
      const scopes = scopesOf(texts[k] || "");
      rows.push({ u, account: page.mail, status: "ok", app: a.app, kind: scopes.length ? "access" : "signin", scopes, href: a.href });
    });
  }
  console.error(`u${u} ${page.mail}: ${page.apps.length} apps`);
}
close();

mkdirSync("out", { recursive: true });
const file = `out/google-linked-apps-${new Date().toISOString().slice(0, 10)}.jsonl`;
writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");

for (const r of rows.filter((r) => r.kind === "access")) {
  console.log(`[access] ${r.account} · ${r.app}: ${r.scopes.join(" | ")}`);
}
const signin = rows.filter((r) => r.kind === "signin");
console.log(`\n${signin.length} sign-in-only apps, ${rows.filter((r) => r.status === "reauth").length} accounts need a fresh sign-in. Full list: ${file}`);
process.exit(0);
