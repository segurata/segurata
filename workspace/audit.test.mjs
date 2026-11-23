// Tests without network or credentials: arguments, error paths and an audit with a mocked fetch.
//   node --test workspace/
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs, accessToken, checkToken, audit, summarize, AuditError, SCOPES, configDir } from "./audit.mjs";

const NOW = Date.parse("2026-11-23T00:00:00Z");
const json = (body, status = 200) => ({ ok: status < 400, status, statusText: "", json: async () => body });

test("parseArgs: domains and options", () => {
  assert.deepEqual(parseArgs(["Example.com", "example.org", "--inactive-days", "60", "--quota-project", "p1"]),
    { domains: ["example.com", "example.org"], inactiveDays: 60, quotaProject: "p1" });
  assert.throws(() => parseArgs([]), AuditError);
  assert.throws(() => parseArgs(["no-es-dominio"]), /does not look like a domain/);
  assert.throws(() => parseArgs(["a.com", "--inactive-days", "x"]), /whole number/);
  assert.throws(() => parseArgs(["a.com", "--force"]), /Unknown option/);
});

test("accessToken: without credentials it explains the one-time login, without running it", () => {
  const exec = () => assert.fail("must not call gcloud");
  const err = (() => { try { accessToken("no-existe.example", { env: {}, exec }); } catch (e) { return e; } })();
  assert.ok(err instanceof AuditError);
  assert.match(err.message, /gcloud auth application-default login/);
  assert.ok(err.message.includes(`CLOUDSDK_CONFIG="${configDir("no-existe.example")}"`));
  for (const s of SCOPES) assert.ok(err.message.includes(s));
  assert.equal(accessToken("x.com", { env: { WORKSPACE_ACCESS_TOKEN: "t" }, exec }), "t");
});

test("checkToken: missing scopes, account from another domain, valid token", async () => {
  const info = (scope, email) => async () => json({ scope, email });
  await assert.rejects(checkToken("a.com", "t", info("openid", "x@a.com")), /lacks scopes/);
  await assert.rejects(checkToken("a.com", "t", info(SCOPES.join(" "), "x@b.com")), /outside that domain/);
  await assert.rejects(checkToken("a.com", "t", async () => json({ error_description: "Invalid Value" }, 400)), /not valid/);
  assert.deepEqual(await checkToken("a.com", "t", info(SCOPES.slice(0, 2).join(" "), "x@a.com")), { email: "x@a.com", reports: false });
});

function mockFetch() {
  const calls = [];
  const users = [
    { primaryEmail: "boss@a.com", isAdmin: true, isEnrolledIn2Sv: true, isEnforcedIn2Sv: false, lastLoginTime: "2026-11-20T10:00:00Z" },
    { primaryEmail: "deleg@a.com", isDelegatedAdmin: true, isEnrolledIn2Sv: false, lastLoginTime: "2026-01-01T00:00:00Z" },
    { primaryEmail: "ok@a.com", isEnrolledIn2Sv: true, isEnforcedIn2Sv: true, lastLoginTime: "2026-11-22T00:00:00Z" },
    { primaryEmail: "gone@a.com", suspended: true, lastLoginTime: "2025-01-01T00:00:00Z" },
    { primaryEmail: "new@a.com", lastLoginTime: "1970-01-01T00:00:00.000Z", creationTime: "2026-11-01T00:00:00Z" },
  ];
  const tokens = {
    "boss@a.com": [{ clientId: "c1", displayText: "Zapier", scopes: ["https://mail.google.com/"] }],
    "ok@a.com": [{ clientId: "c1", displayText: "Zapier", scopes: ["drive"] }, { clientId: "c2", displayText: "Calendly", scopes: ["calendar"] }],
  };
  const fetchFn = async (url, opts) => {
    calls.push({ url, opts });
    const u = new URL(url);
    if (u.pathname.endsWith("/directory/v1/users")) {
      assert.equal(u.searchParams.get("customer"), "my_customer");
      return u.searchParams.get("pageToken") ? json({ users: users.slice(3) }) : json({ users: users.slice(0, 3), nextPageToken: "p2" });
    }
    const m = u.pathname.match(/\/users\/([^/]+)\/tokens$/);
    if (m) return json({ items: tokens[decodeURIComponent(m[1])] || [] });
    if (u.pathname.includes("/reports/v1/activity/users/all/applications/token")) {
      return json({ items: [{ id: { time: "2026-11-10T00:00:00Z" }, events: [{ name: "authorize", parameters: [{ name: "app_name", value: "Zapier" }, { name: "client_id", value: "c1" }] }] }] });
    }
    return json({ error: { message: "route not mocked" } }, 404);
  };
  return { fetchFn, calls };
}

test("audit with mocked fetch: pagination, grants, aggregates and activity", async () => {
  const { fetchFn, calls } = mockFetch();
  const res = await audit("a.com", "tok", { fetchFn, now: NOW, quotaProject: "qp" });
  assert.equal(res.users.length, 5);
  assert.ok(calls.every((c) => c.opts?.headers?.authorization === "Bearer tok" && c.opts.headers["x-goog-user-project"] === "qp"));
  assert.ok(!calls.some((c) => c.url.includes("gone%40a.com")), "does not request tokens of suspended accounts");
  assert.equal(res.users.find((u) => u.email === "new@a.com").lastLoginTime, null);
  assert.equal(res.users.find((u) => u.email === "new@a.com").inactiveDays, 22);
  assert.deepEqual(res.apps.map((a) => [a.app, a.users]), [["Zapier", 2], ["Calendly", 1]]);
  assert.deepEqual(res.apps[0].scopes, ["drive", "https://mail.google.com/"]);
  assert.deepEqual(res.activity, [{ type: "token-activity", app: "Zapier", clientId: "c1", authorize: 1, revoke: 0, lastEvent: "2026-11-10T00:00:00Z" }]);

  const text = summarize("a.com", res);
  const no2sv = text.split("2SV not enforced")[1].split("Admins")[0];
  assert.ok(no2sv.indexOf("boss@a.com") < no2sv.indexOf("deleg@a.com"), "superadmins first");
  assert.ok(no2sv.indexOf("deleg@a.com") < no2sv.indexOf("new@a.com"));
  assert.ok(!no2sv.includes("ok@a.com") && !no2sv.includes("gone@a.com"));
  assert.match(text, /deleg@a.com: 326 days/);
  assert.match(text, /gone@a.com: suspended/);
  assert.match(text, /2 · Zapier/);
});

test("audit: Admin SDK errors become actionable messages", async () => {
  const fail = (status, error) => async () => json({ error }, status);
  await assert.rejects(audit("a.com", "t", { fetchFn: fail(403, { message: "Not Authorized to access this resource/api" }) }), /admin of a.com/);
  await assert.rejects(audit("a.com", "t", { fetchFn: fail(401, { message: "Invalid Credentials" }) }), /gcloud auth application-default login/);
  await assert.rejects(audit("a.com", "t", { fetchFn: fail(403, { message: "Admin SDK API has not been used in project 1 before or it is disabled", status: "PERMISSION_DENIED" }) }), /--quota-project/);
});
