// Read-only inventory of plaintext secrets on disk: .env and credential files, shell and agent
// config, shell histories, logs, agent transcripts, git history (gitleaks) and SSH keys without a
// passphrase. Changes nothing.
//
//   node secrets/local-secrets-scan.mjs     -> out/local-secrets-<date>.jsonl + summary
//
// Never writes a secret value: at most its known prefix and length (`sk-ant-…(108)`) and, when it
// is 20+ chars long, a fingerprint `fp` (12 hex of its SHA-256) to see where the same secret
// repeats. Every row is checked not to contain the value before it is written.
//
// Each line: {bucket, kind, path, line, count, type, redacted, fp, mode, tracked, fix, ...}
//   bucket: 0-git (in git) | 1-readable (group/other can read) | 2-trail (transcripts, logs,
//           histories) | 3-local (untracked, closed permissions)
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";

const HOME = homedir(), SRC = join(HOME, "src");
const ROOT = resolve(dirname(new URL(import.meta.url).pathname), "..");
const GITLEAKS = spawnSync("which", ["gitleaks"]).status === 0;
const DOC = "docs/secrets.md";
const h = (p) => join(HOME, p);
const tilde = (p) => (p.startsWith(HOME) ? "~" + p.slice(HOME.length) : p);
const globs = (list) => list.flatMap((g) => ["-g", g]);
const SKIP_GLOBS = globs(["node_modules", "deps", "_build", "vendor", ".git", ".elixir_ls", ".venv", "venv", "__pycache__", ".next", "dist"].map((d) => `!${d}`));

// Specific patterns (A), applied everywhere including transcripts. `group` holds the secret
// (0 = whole match), `prefix` is the only part that may be shown. They must work both in
// ripgrep (Rust regex) and JavaScript.
const A = [
  ["anthropic", "sk-ant-[A-Za-z0-9_-]{32,}", "sk-ant-"],
  ["openrouter", "sk-or-[A-Za-z0-9_-]{32,}", "sk-or-"],
  ["openai-project", "sk-proj-[A-Za-z0-9_-]{40,}", "sk-proj-"],
  ["openai-service", "sk-(?:svcacct|admin)-[A-Za-z0-9_-]{40,}", "sk-"],
  ["openai-legacy", "\\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\\b", "sk-"],
  ["sk-generic", "\\bsk-[A-Za-z0-9]{32,64}\\b", "sk-"],
  ["xai", "\\bxai-[A-Za-z0-9]{40,}", "xai-"],
  ["groq", "\\bgsk_[A-Za-z0-9]{48,}", "gsk_"],
  ["huggingface", "\\bhf_[A-Za-z0-9]{34,}", "hf_"],
  ["replicate", "\\br8_[A-Za-z0-9]{37}\\b", "r8_"],
  ["perplexity", "\\bpplx-[A-Za-z0-9]{40,}", "pplx-"],
  ["tavily", "\\btvly-[A-Za-z0-9-]{30,}", "tvly-"],
  ["elevenlabs", "\\bsk_[a-f0-9]{48}\\b", "sk_"],
  ["github", "\\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}", "gh"],
  ["github-pat", "\\bgithub_pat_[A-Za-z0-9_]{60,}", "github_pat_"],
  ["gitlab", "\\bglpat-[A-Za-z0-9_-]{20,}", "glpat-"],
  ["aws-secret-key", "(?i)aws_?secret_?access_?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40})\\b", "", 1],
  ["aws-access-key-id", "\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b", "AKIA"],
  ["google-api-key", "\\bAIza[0-9A-Za-z_-]{35}", "AIza"],
  ["google-oauth-client-secret", "\\bGOCSPX-[A-Za-z0-9_-]{28}", "GOCSPX-"],
  ["google-refresh-token", "\\b1//0[A-Za-z0-9_-]{40,}", "1//0"],
  ["oauth-refresh-token", "\"refresh_token\"\\s*:\\s*\"([^\"\\\\]{20,})\"", "", 1],
  ["oauth-client-secret", "\"client_secret\"\\s*:\\s*\"([^\"\\\\]{10,})\"", "", 1],
  ["gcp-service-account", "\"type\"\\s*:\\s*\"service_account\"", ""],
  ["private-key", "-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\\\n([A-Za-z0-9+/=]{40,}))?", ""],
  ["age-secret-key", "\\bAGE-SECRET-KEY-1[0-9A-Z]{58}\\b", "AGE-SECRET-KEY-1"],
  ["stripe-live", "\\b(?:sk|rk)_live_[A-Za-z0-9]{20,}", "sk_live_"],
  ["stripe-test", "\\b(?:sk|rk)_test_[A-Za-z0-9]{20,}", "sk_test_"],
  ["stripe-webhook", "\\bwhsec_[A-Za-z0-9+/=]{24,}", "whsec_"],
  ["slack-token", "\\bxox[abposr]-[A-Za-z0-9-]{10,}", "xox"],
  ["slack-webhook", "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}", "https://hooks.slack.com/"],
  ["cloudflare-token", "(?i)\\b(?:cloudflare|cf)_?(?:api_?)?(?:token|key)\\w*[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_-]{37,40})\\b", "", 1],
  ["notion", "\\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\\b", ""],
  ["sentry-token", "\\bsntry[su]_[A-Za-z0-9+/=_-]{50,}", "sntry"],
  ["sentry-dsn", "https://[a-f0-9]{32}@[a-z0-9.-]+\\.sentry\\.io/\\d+", "https://"],
  ["linear", "\\blin_api_[A-Za-z0-9]{40}\\b", "lin_api_"],
  ["sendgrid", "\\bSG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}\\b", "SG."],
  ["shopify", "\\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\\b", "shp"],
  ["digitalocean", "\\bdo[por]_v1_[a-f0-9]{64}\\b", "do"],
  ["supabase", "\\b(?:sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,})", "sb"],
  ["onepassword-service", "\\bops_[A-Za-z0-9_-]{50,}", "ops_"],
  ["npm-token", "\\bnpm_[A-Za-z0-9]{36}\\b", "npm_"],
  ["npm-authtoken", "_authToken\\s*=\\s*([^\\s\"']{16,})", "", 1],
  ["pypi-token", "\\bpypi-[A-Za-z0-9_-]{50,}", "pypi-"],
  ["rubygems", "\\brubygems_[a-f0-9]{48}\\b", "rubygems_"],
  ["telegram-bot", "\\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\\b", ""],
  ["docker-auth", "\"auth\"\\s*:\\s*\"([A-Za-z0-9+/=]{16,})\"", "", 1],
  ["kube-client-key", "client-key-data:\\s*([A-Za-z0-9+/=]{40,})", "", 1],
  ["netrc-password", "\\bpassword\\s+(\\S{6,})", "", 1, /\.netrc$/],
  ["url-credentials", "\\b[a-z][a-z0-9+.-]{1,20}://[^\\s:/@\"'<>]+:([^\\s@/\"'<>]{3,})@[A-Za-z0-9.-]+", "", 1],
  ["url-token-param", "(?i)[?&](?:access_token|token|api_key|apikey|key|secret|password)=([A-Za-z0-9._~%-]{16,})", "", 1],
  ["jwt", "\\beyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", "eyJ"],
].map(([type, src, prefix, group = 0, files]) => ({ type, src, prefix, group, files }));

// Generic assignment (B): `NAME_TOKEN=value`, `password: "..."`. Only in config files, .env files
// and shell histories, where the noise is tolerable.
const B = [{
  type: "assignment", group: 2, prefix: "",
  src: "(?i)\\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|credentials?)[A-Za-z0-9_.-]*)[\"']?\\s*(?::|=>|=)\\s*[\"']?([^\\s\"'`,;#]{8,})",
}];
const AB = [...A, ...B];
for (const p of AB) {
  const ci = p.src.startsWith("(?i)");
  p.re = new RegExp(`^(?:${ci ? p.src.slice(4) : p.src})$`, ci ? "i" : "");
}

// Types that are not secrets on their own (identifiers or keys meant for clients).
const PUBLIC = new Set(["aws-access-key-id", "sentry-dsn", "gcp-service-account", "stripe-test"]);
const PLACEHOLDER = /x{5,}|X{5,}|0{8,}|\.{3}|…|\*{3,}|example|your[_-]|placeholder|dummy|redacted|changeme|replace|<[^>]*>|\$\{|\$\(|%s|\{\{/i;

const entropy = (s) => {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  return Object.values(f).reduce((e, n) => e - (n / s.length) * Math.log2(n / s.length), 0);
};

// Decides whether a match is a plausible secret. Returns {secret, note} or null.
function judge(p, m, kind) {
  const secret = (p.group ? m[p.group] : m[0]) || "";
  if (p.type === "gcp-service-account") return { secret: "", note: "service account JSON" };
  if (p.type === "private-key") {
    if (!secret && (kind === "transcript" || kind === "log")) return null; // header only: documentation
    const label = m[0].match(/BEGIN ([A-Z ]*)PRIVATE KEY/)[1].trim() || "PKCS8";
    return { secret, note: /ENCRYPTED/.test(label) ? "encrypted" : label };
  }
  const body = secret.slice(p.prefix.length);
  if (PLACEHOLDER.test(secret) || entropy(body) < (p.type === "assignment" ? 3.0 : 3.2)) return null;
  if (p.type === "assignment") {
    if (/[(${<%]/.test(secret) || /^[a-z_]+$/i.test(secret) || /^(true|false|null|none|nil)$/i.test(secret)) return null;
    if (/^(https?:|\/|\.\/|~)/.test(secret) || /^\d+$/.test(secret)) return null;
    // Names that hold counts, paths or URLs rather than secrets.
    if (/tokens$|_(url|uri|path|file|dir|ttl|type|count|length|expires(_at|_in)?)$/i.test(m[1])) return null;
    return { secret, note: m[1] };
  }
  if (p.type === "url-credentials") {
    if (/^(pass(word)?|postgres|secret|root|admin|test|user|changeme|mysql|redis|guest)$/i.test(secret)) return null;
    return { secret, note: m[0].replace(/:\/\/.*@/, "://…@") };
  }
  if (p.type === "jwt") {
    let claims = {};
    try { claims = JSON.parse(Buffer.from(secret.split(".")[1], "base64url").toString()); } catch { return null; }
    const role = claims.role || claims.typ || "";
    const expired = claims.exp && claims.exp * 1000 < Date.now();
    return { secret, note: [role && `role=${role}`, expired && "expired"].filter(Boolean).join(" "), public: role === "anon" || expired };
  }
  return { secret };
}

function redact(p, secret) {
  if (!secret) return "";
  const shown = p.prefix && secret.startsWith(p.prefix) ? p.prefix : p.type.startsWith("github") ? secret.slice(0, 4) : "";
  return `${shown}…(${secret.length})`;
}

// Source kind by path.
const TRANSCRIPTS = [".claude/projects", ".claude/history.jsonl", ".codex/sessions", ".codex/history.jsonl", ".cursor/projects", ".gemini/tmp"].map(h);
const HISTORIES = [".zsh_history", ".bash_history", ".zsh_sessions", ".python_history", ".node_repl_history", ".psql_history", ".mysql_history", ".irb_history", ".sqlite_history", ".lesshst"].map(h);
function kindOf(path) {
  if (TRANSCRIPTS.some((t) => path.startsWith(t))) return "transcript";
  if (HISTORIES.some((t) => path.startsWith(t))) return "history";
  if (path.endsWith(".log") || path.startsWith(h("Library/Logs")) || path.startsWith(h(".local/log"))) return "log";
  return path.startsWith(SRC + "/") ? "repo" : "config";
}

// Is it tracked by git? Walks up to $HOME looking for the repo root and caches `git ls-files`.
const rootCache = new Map(), filesCache = new Map();
function gitRoot(dir) {
  if (!dir.startsWith(HOME + "/")) return null;
  if (rootCache.has(dir)) return rootCache.get(dir);
  const r = existsSync(join(dir, ".git")) ? dir : gitRoot(dirname(dir));
  rootCache.set(dir, r);
  return r;
}
function tracked(path) {
  const root = gitRoot(dirname(path));
  if (!root) return false;
  if (!filesCache.has(root)) {
    const out = spawnSync("git", ["-C", root, "ls-files", "-z"], { maxBuffer: 1 << 28, encoding: "utf8" }).stdout || "";
    filesCache.set(root, new Set(out.split("\0").filter(Boolean).map((f) => join(root, f))));
  }
  return filesCache.get(root).has(path);
}

const modeOf = (path) => { try { return statSync(path).mode & 0o777; } catch { return null; } };
const bucketOf = (r) => r.tracked || r.source === "gitleaks" ? "0-git"
  : ["transcript", "log", "history"].includes(r.kind) ? "2-trail"
  : r.mode & 0o044 ? "1-readable" : "3-local";

// Anchor in docs/secrets.md with the recommended fix.
function fixFor(r) {
  const t = r.type, p = r.path;
  const a = r.source === "gitleaks" || r.tracked ? "in-git-always-rotate"
    : r.kind === "transcript" ? "agent-transcripts"
    : r.kind === "history" ? "shell-history"
    : r.kind === "log" ? "logs"
    : t === "ssh-key" ? "ssh-keys"
    : /^aws/.test(t) || p.includes("/.aws/") ? "aws"
    : /gcloud|\.gemini/.test(p) || /^(google|oauth|gcp)/.test(t) ? "google-cloud-and-oauth"
    : /^(github|gitlab)/.test(t) || /\.netrc$|\/gh\//.test(p) ? "github-and-git"
    : /^(npm|pypi|rubygems|docker)/.test(t) || /\.npmrc$|\.docker\//.test(p) ? "package-registries-and-docker"
    : /\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)$/.test(p) ? "shell-variables-from-the-keychain"
    : /\.claude|\.mcp|\.codex|\.cursor|\.config\/opencode/.test(p) ? "mcp-servers-and-agents"
    : t === "private-key" || t === "keystore" || t === "rails-master-key" ? "files-that-must-live-in-the-repo"
    : "env-files";
  return `${DOC}#${a}`;
}

// Runs ripgrep with some patterns over some paths and aggregates matches by (path, secret).
const found = new Map();
let omitted = 0;
function addRow(r, secret) {
  r.kind ??= kindOf(r.path);
  r.mode ??= modeOf(r.path);
  r.tracked ??= r.path.startsWith(HOME) && !r.path.includes("/.git/") ? tracked(r.path) : false;
  r.bucket = bucketOf(r);
  r.fix = fixFor(r);
  if (secret && secret.length >= 20) r.fp = createHash("sha256").update(secret).digest("hex").slice(0, 12);
  if (secret && secret.length >= 6 && JSON.stringify(r).includes(secret)) { omitted++; return; }
  const key = `${r.path}\0${r.type}\0${r.fp || r.line || r.note || ""}`;
  const prev = found.get(key);
  if (prev) prev.count++;
  else found.set(key, { ...r, count: 1 });
}

// ASCII mode for ripgrep: Unicode `\b` makes it several times slower on non-ASCII text.
const ascii = (src) => (src.startsWith("(?i)") ? "(?i-u)" + src.slice(4) : "(?-u)" + src);

function rg(patterns, paths, extra = []) {
  paths = paths.filter(existsSync);
  if (!paths.length) return Promise.resolve();
  const args = ["--no-config", "--hidden", "--no-ignore", "--no-messages", "-o", "-n", "--null", "--no-heading", "-H",
    "--color", "never", ...SKIP_GLOBS, ...extra,
    ...patterns.flatMap((p) => ["-e", ascii(p.src)]), "--", ...paths];
  const child = spawn("rg", args, { stdio: ["ignore", "pipe", "ignore"] });
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  rl.on("line", (l) => {
    const z = l.indexOf("\0"), c = l.indexOf(":", z);
    const path = l.slice(0, z), line = +l.slice(z + 1, c), text = l.slice(c + 1);
    const kind = kindOf(path);
    for (let p of patterns) {
      if (p.files && !p.files.test(path)) continue;
      let m = text.match(p.re);
      if (!m) continue;
      // ripgrep reports the leftmost match, so `NAME=sk-ant-…` arrives as an assignment:
      // classify the value with the specific patterns when one of them fits.
      const specific = p.type === "assignment" && A.find((q) => !q.files && q.re.test(m[2]));
      const name = m[1];
      if (specific) { p = specific; m = m[2].match(p.re); }
      const v = judge(p, m, kind);
      if (v && specific && !v.note) v.note = name;
      if (v) addRow({ source: "scan", kind, path, line, type: p.type, redacted: p.type === "private-key" ? "PEM" : redact(p, v.secret),
        ...(v.note ? { note: v.note } : {}), ...(v.public || PUBLIC.has(p.type) ? { public: true } : {}) }, v.secret);
      break;
    }
  });
  return new Promise((res) => child.on("close", res));
}

// Files that give away a secret by name, even when binary or patternless.
function byName() {
  const r = spawnSync("rg", ["--no-config", "--files", "--hidden", "--no-ignore", "--no-messages",
    ...SKIP_GLOBS, ...globs(["master.key", "*.p12", "*.pfx", "*.jks", "*.keystore"]), "--", SRC], { encoding: "utf8", maxBuffer: 1 << 26 });
  const files = (r.stdout || "").split("\n").filter(Boolean);
  for (const f of [".config/gcloud/credentials.db", ".config/gcloud/access_tokens.db"].map(h)) if (existsSync(f)) files.push(f);
  for (const f of files) {
    const type = f.endsWith("master.key") ? "rails-master-key" : f.endsWith(".db") ? "gcloud-credential-db" : "keystore";
    addRow({ source: "name", path: f, type, redacted: "" });
  }
}

// Private keys in ~/.ssh: type, permissions and passphrase. Only the first bytes are read here to
// spot a key; ssh-keygen opens it with an empty passphrase and its output is discarded.
function sshKeys() {
  const dir = h(".ssh");
  if (!existsSync(dir)) return [];
  return readdirSync(dir).map((n) => join(dir, n)).filter((f) => {
    try { return statSync(f).isFile() && readFileSync(f, "utf8").slice(0, 40).includes("PRIVATE KEY"); } catch { return false; }
  }).map((f) => {
    const noPass = spawnSync("ssh-keygen", ["-y", "-P", "", "-f", f], { stdio: ["ignore", "ignore", "ignore"] }).status === 0;
    const pub = existsSync(f + ".pub") ? f + ".pub" : noPass ? f : null;
    const l = pub ? (spawnSync("ssh-keygen", ["-l", "-f", pub], { encoding: "utf8" }).stdout || "").trim().split(" ") : [];
    const row = { source: "ssh", kind: "config", path: f, type: "ssh-key", redacted: "", passphrase: !noPass,
      keytype: l.length ? `${l.at(-1).replace(/[()]/g, "")} ${l[0]}` : "?" };
    row.mode = modeOf(f);
    row.bucket = noPass ? (row.mode & 0o077 ? "1-readable" : "3-local") : "ok";
    row.fix = `${DOC}#ssh-keys`;
    return row;
  });
}

// Git history with gitleaks (when installed), one repo per process, several at a time.
async function gitleaksAll() {
  if (!GITLEAKS) return { repos: 0, failed: 0 };
  const find = spawnSync("find", [SRC, "-maxdepth", "6", "-name", ".git", "-type", "d", "-prune",
    "-not", "-path", "*/node_modules/*", "-not", "-path", "*/deps/*"], { encoding: "utf8" });
  const repos = (find.stdout || "").split("\n").filter(Boolean).map(dirname);
  if (existsSync(h(".claude/.git"))) repos.push(h(".claude"));
  let failed = 0, i = 0;
  const one = (repo) => new Promise((res) => {
    const remote = !!(spawnSync("git", ["-C", repo, "remote"], { encoding: "utf8" }).stdout || "").trim();
    const c = spawn("gitleaks", ["git", "--redact", "--no-banner", "--log-level", "fatal", "--exit-code", "0",
      "--timeout", "600", "--report-format", "json", "--report-path", "-", repo], { stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    c.stdout.on("data", (d) => (out += d));
    c.on("close", () => {
      let list = [];
      try { list = JSON.parse(out || "[]"); } catch { failed++; }
      for (const f of list) {
        const row = { source: "gitleaks", kind: "repo", path: join(repo, f.File), line: f.StartLine, type: f.RuleID,
          redacted: "", commit: (f.Commit || "").slice(0, 10), date: (f.Date || "").slice(0, 10), repo: tilde(repo),
          mode: null, tracked: true, remote };
        addRow(row, f.Secret && f.Secret !== "REDACTED" ? f.Secret : "");
      }
      res();
    });
  });
  await Promise.all(Array.from({ length: 6 }, async () => { while (i < repos.length) await one(repos[i++]); }));
  return { repos: repos.length, failed };
}

// --- Run ---
const t0 = Date.now();
const credFiles = [".aws/credentials", ".aws/config", ".npmrc", ".netrc", ".docker/config.json", ".kube/config", ".pypirc",
  ".gem/credentials", ".git-credentials", ".gitconfig", ".codex/config.toml", ".codex/auth.json", ".claude.json",
  ".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", ".cursor/mcp.json", ".cursor/cli-config.json",
  ".gemini/settings.json", ".gemini/oauth_creds.json", ".config", ".mcp"].map(h);
// Source code inside config dirs (~/.mcp, ~/.config) is left to gitleaks: too noisy for B.
const CODE = ["ts", "tsx", "js", "mjs", "cjs", "py", "rb", "ex", "exs", "go", "rs", "java", "md", "html", "css", "map", "lock", "d.ts"];
const srcEnvGlobs = [".env*", "*.pem", "*.key", "*.p8", "credentials*", "secrets*", "*.secret.exs", "*.secrets.*"];

// Without gitleaks there is no history scan, so the whole ~/src working tree is scanned instead.
const srcArgs = GITLEAKS ? globs(srcEnvGlobs) : [];
console.error("Scanning config files, ~/src .env files and histories...");
await Promise.all([
  rg(AB, credFiles, ["--max-filesize", "50M", ...globs(CODE.map((e) => `!*.${e}`))]),
  rg(AB, [h(".claude")], ["--max-filesize", "50M", ...globs(["*.json", "!projects", "!plugins/cache"])]),
  rg(AB, [SRC], ["--max-filesize", "50M", ...srcArgs]),
  rg(AB, HISTORIES),
]);
byName();
console.error("Scanning logs and agent transcripts (several GB)...");
await Promise.all([
  rg(A, [SRC], ["-g", "*.log"]),
  rg(A, [h("Library/Logs"), h(".local/log")]),
  rg(A, TRANSCRIPTS),
]);
let gl = { repos: 0, failed: 0 };
if (GITLEAKS) { console.error("Scanning git history with gitleaks..."); gl = await gitleaksAll(); }
const ssh = sshKeys();

const rows = [...found.values(), ...ssh].map((r) => ({ ...r, path: tilde(r.path), mode: r.mode == null ? null : r.mode.toString(8) }));
mkdirSync(join(ROOT, "out"), { recursive: true });
const date = new Date().toISOString().slice(0, 10);
const file = join(ROOT, "out", `local-secrets-${date}.jsonl`);
writeFileSync(file, rows.map((r) => JSON.stringify(r)).join("\n") + "\n", { mode: 0o600 });

// --- Summary ---
const LABEL = {
  "0-git": "P0 · in git (rotate: removing it from history is not enough)",
  "1-readable": "P1 · file readable by group/others",
  "2-trail": "P2 · agent transcripts, logs and histories",
  "3-local": "P3 · untracked local files, closed permissions",
};
const real = rows.filter((r) => !r.public && r.source !== "ssh");
// Specific types first: a named token beats a generic `NAME=value` match.
const NOISY = new Set(["assignment", "generic-api-key"]);
const rank = (r) => (NOISY.has(r.type) ? 1 : 0);
const TOP = 15;
// "key n, key n, ..." sorted by count, highest first.
const countsLine = (keys, limit) => {
  const n = {};
  for (const k of keys) n[k] = (n[k] || 0) + 1;
  return Object.entries(n).sort((a, b) => b[1] - a[1]).slice(0, limit).map(([k, c]) => `${k} ${c}`).join(", ");
};
for (const [b, label] of Object.entries(LABEL)) {
  const list = real.filter((r) => r.bucket === b);
  const distinct = new Set(list.map((r) => r.fp || `${r.path}:${r.type}`)).size;
  console.log(`\n## ${label}: ${list.length} findings, ~${distinct} distinct secrets`);
  if (!list.length) continue;
  console.log("   types: " + countsLine(list.map((r) => r.type)));
  if (b === "0-git" && gl.repos) {
    // gitleaks repeats a secret once per commit: count distinct files per (repo, rule), noisy rules apart.
    const files = {};
    for (const r of list.filter((r) => r.source === "gitleaks" && !NOISY.has(r.type))) {
      const k = `${r.repo}  ${r.type}  ${r.remote ? "has remote" : "local only"}`;
      (files[k] ??= new Set()).add(r.path);
    }
    console.log("   gitleaks, specific rules (repo, rule, distinct files):");
    for (const [k, f] of Object.entries(files).sort((a, b) => b[1].size - a[1].size).slice(0, TOP)) console.log(`     ${k}  ${f.size}`);
    const generic = list.filter((r) => r.source === "gitleaks" && NOISY.has(r.type)).length;
    console.log(`   gitleaks generic-api-key: ${generic} matches, mostly noise; filter the jsonl by repo.`);
  }
  if (b === "2-trail") {
    const where = list.map((r) => (r.kind === "transcript" ? `${r.kind}:${r.path.split("/").slice(0, 3).join("/")}` : r.path));
    console.log("   where: " + countsLine(where, 8));
  }
  const fixes = [...new Set(list.map((r) => r.fix))];
  for (const r of list.filter((r) => r.kind !== "transcript" && r.source !== "gitleaks").sort((a, b) => rank(a) - rank(b)).slice(0, TOP)) {
    console.log(`   ${r.path}${r.line ? ":" + r.line : ""}  ${r.type}${r.note ? ` (${r.note})` : ""}  ${r.redacted}  ${r.mode ?? ""}${r.count > 1 ? `  x${r.count}` : ""}`);
  }
  console.log(`   fix: ${fixes.join(", ")}`);
}
console.log("\n## SSH keys");
for (const s of rows.filter((r) => r.source === "ssh")) console.log(`   ${s.passphrase ? "OK  " : "WARN"} ${s.path}  ${s.keytype}  ${s.mode}  ${s.passphrase ? "passphrase" : "NO passphrase"}`);
if (ssh.some((s) => !s.passphrase)) console.log(`   fix: ${DOC}#ssh-keys`);
console.log(`\n${rows.filter((r) => r.public).length} findings that are not secrets on their own (AWS key IDs, Sentry DSNs, test keys, anon or expired JWTs) in the jsonl.`);
console.log(GITLEAKS ? `gitleaks: ${gl.repos} repos, ${gl.failed} failed.` : `gitleaks is not installed: no git history scan, the ~/src working tree was scanned instead. See README.`);
if (omitted) console.log(`${omitted} rows omitted because the value appeared in the path or note.`);
console.log(`Details: ${tilde(file)} (${Math.round((Date.now() - t0) / 1000)} s)`);
