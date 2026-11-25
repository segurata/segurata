"""Tests for segurata-prowler with a fake prowler and a fake gcloud on PATH (testdata/fakebin) and
a synthetic OCSF fixture (testdata/ocsf). No real network, no real cloud account."""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "segurata-prowler")
FAKEBIN = os.path.join(HERE, "testdata", "fakebin")
FIXTURES = os.path.join(HERE, "testdata", "ocsf")

_loader = importlib.machinery.SourceFileLoader("segurata_prowler", SCRIPT)
_spec = importlib.util.spec_from_loader("segurata_prowler", _loader)
prowler = importlib.util.module_from_spec(_spec)
_loader.exec_module(prowler)

ALICE = "alice@example.com"
BOB = "bob@example.org"
ROBOT = "robot@demo-proj-alpha.iam.gserviceaccount.com"
ALPHA, BETA, GAMMA = "demo-proj-alpha", "demo-proj-beta", "demo-proj-gamma"
DELTA = "demo-proj-delta"  # hygiene failures next to exposures (testdata/ocsf/demo-proj-delta.json)
DEFAULTS = ["bigquery.googleapis.com", "logging.googleapis.com", "storage.googleapis.com", "serviceusage.googleapis.com"]


def token(account):
    return "ya29.TEST-not-a-real-token-for-" + account


class Fake:
    """A FAKE_DIR for the fake gcloud and prowler, and a way to run the connector against it."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="segurata-prowler-test-")
        os.makedirs(os.path.join(self.dir, "projects"))
        shutil.copytree(FIXTURES, os.path.join(self.dir, "ocsf"))
        self.accounts([ALICE, BOB, ROBOT])
        self.projects(ALICE, [ALPHA, BETA])
        self.projects(BOB, [BETA, GAMMA])

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def accounts(self, accounts):
        with open(os.path.join(self.dir, "accounts.json"), "w") as f:
            json.dump([{"account": a, "status": ""} for a in accounts], f)

    def projects(self, account, ids, parent=None):
        """parent, e.g. {"type": "organization", "id": "1"}, for every project; None for none."""
        rows = [{"projectId": p, "lifecycleState": "ACTIVE", "name": p} for p in ids]
        for r in rows:
            if parent:
                r["parent"] = parent
        with open(os.path.join(self.dir, "projects", account + ".json"), "w") as f:
            json.dump(rows, f)

    def profile(self, project, services=(), billing=False, **resources):
        """What the fake gcloud answers about project: enabled services, billing, and per list
        command group (compute, container, sql, run, functions, storage) a count of resources."""
        d = os.path.join(self.dir, "profile", project)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "services.json"), "w") as f:
            json.dump([{"name": "projects/1/services/" + s, "config": {"name": s}} for s in services], f)
        with open(os.path.join(d, "billing.json"), "w") as f:
            json.dump({"billingEnabled": billing, "projectId": project}, f)
        for group, n in resources.items():
            with open(os.path.join(d, group + ".json"), "w") as f:
                json.dump([{"name": "%s-%d" % (group, i)} for i in range(n)], f)

    def calls(self):
        with open(os.path.join(self.dir, "calls.log")) as f:
            return f.read()

    def flag(self, *parts):
        path = os.path.join(self.dir, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").close()

    def prowler_runs(self):
        """[(argv, env facts)] for each fake prowler run; argv[3] is the project."""
        path = os.path.join(self.dir, "prowler.log")
        if not os.path.exists(path):
            return []
        with open(path) as f:
            lines = f.read().splitlines()
        runs = []
        for args, env in zip(lines[0::2], lines[1::2]):
            facts = dict(kv.split("=", 1) for kv in env[len("ENV "):].split(" "))
            runs.append((["prowler"] + args[len("ARGS "):].split(" "), facts))
        return runs

    def run(self, config=None, protocol=1, env_extra=None):
        env = dict(os.environ, FAKE_DIR=self.dir, PATH=FAKEBIN + os.pathsep + "/usr/bin:/bin",
                   GOOGLE_APPLICATION_CREDENTIALS="/nonexistent/adc.json")
        env.update(env_extra or {})
        req = {"protocol": protocol, "config": config or {}}
        proc = subprocess.run([sys.executable, "-I", SCRIPT, "inventory"], input=json.dumps(req),
                              capture_output=True, text=True, env=env, timeout=60)
        records = [json.loads(line) for line in proc.stdout.splitlines()]
        return proc, records


def of(records, kind):
    return [r for r in records if r["type"] == kind]


class DescribeTest(unittest.TestCase):
    def test_describe_speaks_protocol_1_and_needs_both_clis(self):
        out = subprocess.run([sys.executable, "-I", SCRIPT, "describe"], capture_output=True, text=True, timeout=30)
        d = json.loads(out.stdout)
        self.assertEqual((d["name"], d["protocol"], d["needs"]), ("prowler", 1, ["cli:prowler", "cli:gcloud"]))
        self.assertEqual(d["theme"], {"id": "cloud"})
        self.assertNotIn("remediates", d)

    def test_other_protocols_and_bad_input_are_refused(self):
        for stdin in ('{"protocol": 2}', "not json"):
            p = subprocess.run([sys.executable, "-I", SCRIPT, "inventory"], input=stdin, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(p.returncode, 0, stdin)


class MappingTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIXTURES, ALPHA + ".json")) as f:
            self.records = json.load(f)

    def test_severity_and_kind_tables(self):
        self.assertEqual({k: prowler.severity_of({"severity": k.capitalize()}) for k in prowler.PROWLER_SEVERITIES},
                         {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"})
        self.assertEqual(prowler.kind_of(["internet-exposed", "secrets"]), "exposure")
        self.assertEqual(prowler.kind_of(["secrets", "identity-access"]), "credential")
        self.assertEqual(prowler.kind_of(["logging"]), "setting")
        self.assertEqual(prowler.kind_of([]), "setting")

    def test_overlap_rules(self):
        self.assertTrue(prowler.overlap("iam_sa_no_user_managed_keys", ""))
        self.assertTrue(prowler.overlap("iam_sa_no_administrative_privileges", "Account x has administrative privileges with roles/owner."))
        self.assertFalse(prowler.overlap("iam_sa_no_administrative_privileges", "Account x has administrative privileges with roles/storage.admin."))
        self.assertTrue(prowler.overlap("apikeys_api_restricted_with_gemini_api", "API key k does not have restrictions configured and Gemini (Generative Language) API is enabled for project p."))
        self.assertFalse(prowler.overlap("apikeys_api_restricted_with_gemini_api", "API key k has access to Gemini (Generative Language) API as well as other APIs."))
        self.assertFalse(prowler.overlap("apikeys_key_rotated_in_90_days", ""))
        self.assertFalse(prowler.overlap("iam_sa_user_managed_key_unused", ""))

    def test_failure_classification(self):
        self.assertEqual(prowler.classify("GCPNoAccesibleProjectsError[3000]: No Input Project IDs are active or can be accessed"), "denied")
        self.assertEqual(prowler.classify("<HttpError 403 when requesting https://x returned PERMISSION_DENIED>"), "denied")
        self.assertEqual(prowler.classify("google.auth.exceptions.RefreshError: invalid_grant"), "reauth")
        self.assertEqual(prowler.classify("<HttpError 401 when requesting https://x returned UNAUTHENTICATED>"), "reauth")
        self.assertEqual(prowler.classify("ValueError: snapshot 140137 not found in 2026-11-24T14:03"), "error")

    def test_severity_min_filters_and_narrows_the_run(self):
        config = prowler.Config({"severity_min": "high"})
        self.assertEqual(config.severities, ["high", "critical"])
        findings, counts = prowler.summarize(self.records, config, ALICE, ALPHA)
        self.assertEqual(sorted(f["severity"] for f in findings), ["critical", "high"])
        self.assertEqual(counts["below_min"], 3)
        self.assertEqual(prowler.Config({"severity_min": "info"}).severities, prowler.PROWLER_SEVERITIES)
        with self.assertRaises(ValueError):
            prowler.Config({"severity_min": "severe"})

    def test_prowler_command_line(self):
        config = prowler.Config({"checks": ["a", "iam_sa_no_user_managed_keys"], "excluded_checks": ["b"], "severity_min": "medium"})
        args = prowler.prowler_args("/bin/prowler", ALPHA, "/tmp/x", config)
        self.assertEqual(args[:4], ["/bin/prowler", "gcp", "--project-id", ALPHA])
        for flag in (["--output-formats", "json-ocsf"], ["--output-directory", "/tmp/x"], ["--output-filename", "prowler"],
                     ["--log-file", "/tmp/x/prowler.log"], ["--ignore-exit-code-3"], ["--no-banner"],
                     ["--severity", "medium", "high", "critical"]):
            self.assertTrue(any(args[i:i + len(flag)] == flag for i in range(len(args))), flag)
        self.assertNotIn("html", args)
        self.assertEqual(args[args.index("--checks") + 1:args.index("--checks") + 3], ["a", "iam_sa_no_user_managed_keys"])
        excluded = args[args.index("--excluded-checks") + 1:args.index("--severity")]
        self.assertEqual(excluded, ["b", "apikeys_api_restrictions_configured", "apikeys_key_exists", "iam_sa_user_managed_key_rotate_90_days"])
        overlaps = prowler.prowler_args("/bin/prowler", ALPHA, "/tmp/x", prowler.Config({"include_overlaps": True}))
        self.assertNotIn("--excluded-checks", overlaps)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()

    def tearDown(self):
        self.fake.close()

    def test_failed_checks_become_findings_and_the_rest_is_counted(self):
        proc, records = self.fake.run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        findings = of(records, "finding")
        by_check = {(f["evidence"]["check_id"], f["evidence"]["resource_uid"]): f for f in findings}
        self.assertEqual(sorted(k[0] for k in by_check), [
            "cloudstorage_bucket_public_access",
            "compute_firewall_ssh_access_from_the_internet_allowed",
            "compute_snapshot_not_outdated",
            "iam_organization_essential_contacts_configured",
            "iam_sa_no_administrative_privileges",  # roles/storage.admin; the roles/editor one is gcp's
            "iam_sa_user_managed_key_unused",
        ])
        bucket = by_check[("cloudstorage_bucket_public_access", "demo-public-assets")]
        self.assertEqual(bucket["account"], ALICE)
        self.assertEqual(bucket["scope"], ALPHA)
        self.assertEqual(bucket["resource"], {"type": "prowler_check", "id": "cloudstorage_bucket_public_access:demo-proj-alpha:demo-public-assets", "name": "demo-public-assets"})
        self.assertEqual((bucket["kind"], bucket["severity"]), ("exposure", "critical"))
        self.assertEqual(bucket["title"], "Bucket demo-public-assets is publicly accessible.")
        self.assertEqual(bucket["evidence"]["compliance"], {"CIS-2.0": ["5.1"], "CIS-3.0": ["5.1"]})
        self.assertEqual((bucket["evidence"]["service"], bucket["evidence"]["region"], bucket["evidence"]["project"]), ("cloudstorage", "europe-west1", ALPHA))
        self.assertEqual(bucket["remediation"]["url"], "https://hub.prowler.com/check/cloudstorage_bucket_public_access")
        self.assertIn("allUsers", bucket["remediation"]["summary"])
        self.assertIsNone(bucket["created_at"])
        self.assertNotIn("id", bucket)
        # One tracker item per check across projects, titled by the check (segurata's golden test
        # holds the same declarations: internal/tracker/golden_test.go).
        self.assertEqual(bucket["track"], {
            "group": "check", "key": "cloudstorage_bucket_public_access", "count": "scopes", "noun": "project", "nouns": "projects",
            "title": "Cloud Storage bucket is not publicly accessible fails in {count} (Prowler cloudstorage_bucket_public_access)",
            "title_one": "Cloud Storage bucket is not publicly accessible fails in demo-proj-alpha (Prowler cloudstorage_bucket_public_access)"})
        admin = by_check[("iam_sa_no_administrative_privileges", "uploader@demo-proj-alpha.iam.gserviceaccount.com")]
        self.assertEqual((admin["kind"], admin["severity"]), ("setting", "high"))
        self.assertNotIn("**", admin["remediation"]["summary"])
        key = by_check[("iam_sa_user_managed_key_unused", "0000test0key0id")]
        self.assertEqual((key["kind"], key["severity"]), ("credential", "medium"))
        self.assertEqual(by_check[("iam_organization_essential_contacts_configured", ALPHA)]["severity"], "info")
        ssh = by_check[("compute_firewall_ssh_access_from_the_internet_allowed", "2222222222222222222")]
        self.assertEqual((ssh["account"], ssh["scope"]), (ALICE, BETA))  # alice lists beta first

        statuses = {(s["account"], s.get("scope")): s for s in of(records, "status")}
        alpha = statuses[(ALICE, ALPHA)]
        self.assertEqual(alpha["state"], "ok")
        self.assertIn("5 FAIL, 1 PASS, 1 MANUAL; 1 muted, 2 already checked by gcp", alpha["detail"])
        self.assertIn("APIs disabled (nothing to check there): dataproc", alpha["detail"])
        self.assertEqual(statuses[(ALICE, BETA)]["state"], "ok")
        self.assertEqual(statuses[(BOB, GAMMA)]["state"], "ok")  # no OCSF file: nothing to report
        self.assertEqual((statuses[(ALICE, None)]["state"], statuses[(BOB, None)]["state"]), ("ok", "ok"))
        self.assertNotIn((ROBOT, None), statuses, "service accounts are credentials, not identities to scan with")

    def test_runs_as_each_account_with_its_token_never_adc_and_cleans_up(self):
        proc, records = self.fake.run()
        runs = self.fake.prowler_runs()
        self.assertEqual(sorted((a[3], f["account"]) for a, f in runs), [(ALPHA, ALICE), (BETA, ALICE), (GAMMA, BOB)])
        for args, facts in runs:
            self.assertEqual(facts["adc"], "unset")
            self.assertEqual(facts["project"], args[3])
            self.assertEqual(facts["outdir_mode"], "700")
            self.assertFalse(os.path.exists(facts["outdir"]), "the output directory is deleted")
            self.assertIn("--excluded-checks", args)
        for account in (ALICE, BOB):
            self.assertNotIn(token(account), proc.stdout + proc.stderr)
        self.assertNotIn("ya29.", proc.stdout + proc.stderr)
        with open(os.path.join(self.fake.dir, "calls.log")) as f:
            calls = f.read()
        self.assertNotIn("application-default", calls)
        self.assertNotIn("config set", calls)

    def test_ids_are_stable_across_runs(self):
        _, first = self.fake.run()
        _, second = self.fake.run()
        key = lambda rs: sorted((f["account"], f["resource"]["type"], f["resource"]["id"]) for f in of(rs, "finding"))
        self.assertEqual(key(first), key(second))

    def test_include_overlaps_reports_what_gcp_also_reports(self):
        _, records = self.fake.run({"include_overlaps": True})
        checks = [f["evidence"]["check_id"] for f in of(records, "finding")]
        self.assertIn("apikeys_api_restrictions_configured", checks)
        self.assertEqual(checks.count("iam_sa_no_administrative_privileges"), 2)
        for args, _ in self.fake.prowler_runs():
            self.assertNotIn("--excluded-checks", args)

    def test_accounts_projects_and_skips_from_config(self):
        _, records = self.fake.run({"accounts": [BOB, "carol@example.com"], "projects": [BETA, "demo-proj-nope"], "skip_projects": [GAMMA]})
        self.assertEqual([a[3] for a, _ in self.fake.prowler_runs()], [BETA])
        statuses = {(s["account"], s.get("scope")): s["state"] for s in of(records, "status")}
        self.assertEqual(statuses[("carol@example.com", None)], "missing_credentials")
        self.assertEqual(statuses[(BOB, BETA)], "ok")
        scopes = {s["scope"]: s for s in of(records, "scope")}
        self.assertFalse(scopes[ALICE]["inspected"])  # a person left out of accounts
        self.assertNotIn(ROBOT, scopes)
        self.assertFalse(scopes["demo-proj-nope"]["inspected"])
        self.assertNotIn(GAMMA, scopes, "projects not in config.projects are not declared")
        carol = [s for s in of(records, "status") if s["account"] == "carol@example.com"][0]
        self.assertIn("gcloud auth login carol@example.com", carol["detail"])

    def test_skip_projects_are_declared_uninspected(self):
        _, records = self.fake.run({"skip_projects": [GAMMA]})
        self.assertEqual(sorted(a[3] for a, _ in self.fake.prowler_runs()), [ALPHA, BETA])
        self.assertIn({"type": "scope", "scope": GAMMA, "inspected": False, "reason": "expected: in connectors.prowler.config.skip_projects"}, records)

    def test_skip_projects_accept_patterns(self):
        _, records = self.fake.run({"skip_projects": ["demo-proj-g*"]})
        self.assertEqual(sorted(a[3] for a, _ in self.fake.prowler_runs()), [ALPHA, BETA])
        self.assertIn({"type": "scope", "scope": GAMMA, "inspected": False, "reason": "expected: in connectors.prowler.config.skip_projects"}, records)

    def test_expired_login_is_reauth_for_that_account_only(self):
        self.fake.flag("notoken", BOB)
        _, records = self.fake.run()
        statuses = {(s["account"], s.get("scope")): s for s in of(records, "status")}
        self.assertEqual(statuses[(BOB, None)]["state"], "reauth")
        self.assertIn("gcloud auth login " + BOB, statuses[(BOB, None)]["detail"])
        self.assertNotIn(GAMMA, [a[3] for a, _ in self.fake.prowler_runs()])
        self.assertEqual(statuses[(ALICE, ALPHA)]["state"], "ok")

    def test_denied_project_falls_back_to_the_next_account(self):
        self.fake.flag("deny", BETA, ALICE)
        _, records = self.fake.run()
        beta = [s for s in of(records, "status") if s.get("scope") == BETA]
        self.assertEqual([(s["account"], s["state"]) for s in beta], [(ALICE, "ok")])
        self.assertIn("read as " + BOB, beta[0]["detail"])
        ssh = [f for f in of(records, "finding") if f["scope"] == BETA][0]
        self.assertEqual(ssh["account"], ALICE, "ids do not depend on who answered")

    def test_denied_for_every_account_is_noscope_on_the_project(self):
        self.fake.flag("deny", BETA, ALICE)
        self.fake.flag("deny", BETA, BOB)
        _, records = self.fake.run()
        beta = [s for s in of(records, "status") if s.get("scope") == BETA]
        self.assertEqual([(s["account"], s["state"]) for s in beta], [(ALICE, "noscope")])
        self.assertIn(ALICE, beta[0]["detail"])
        self.assertIn(BOB, beta[0]["detail"])
        self.assertIn("roles/viewer", beta[0]["detail"])
        self.assertFalse([f for f in of(records, "finding") if f["scope"] == BETA])

    def test_timeout_is_an_error_on_that_project(self):
        self.fake.flag("slow", ALPHA)
        _, records = self.fake.run({"timeout": 1})
        alpha = [s for s in of(records, "status") if s.get("scope") == ALPHA]
        self.assertEqual([s["state"] for s in alpha], ["error"])
        self.assertIn("within 1 s", alpha[0]["detail"])
        self.assertEqual([s["state"] for s in of(records, "status") if s.get("scope") == BETA], ["ok"])

    def test_sigterm_stops_prowler_and_removes_its_output(self):
        """segurata ends a cancelled plugin with SIGTERM to its process group. Prowler runs in a
        session of its own, so the plugin kills it and removes its output directory itself."""
        self.fake.flag("slow", ALPHA)
        env = dict(os.environ, FAKE_DIR=self.fake.dir, PATH=FAKEBIN + os.pathsep + "/usr/bin:/bin")
        plugin = subprocess.Popen([sys.executable, "-I", SCRIPT, "inventory"], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env)
        plugin.stdin.write(json.dumps({"protocol": 1, "config": {"projects": [ALPHA]}}))
        plugin.stdin.close()
        pid_file = os.path.join(self.fake.dir, "slow", ALPHA + ".pid")
        deadline = time.monotonic() + 20
        while not os.path.exists(pid_file) or not os.path.getsize(pid_file):
            self.assertLess(time.monotonic(), deadline, "Prowler never started")
            time.sleep(0.05)
        with open(pid_file) as f:
            pgid = int(f.read())
        outdir = self.fake.prowler_runs()[0][1]["outdir"]
        plugin.send_signal(signal.SIGTERM)
        self.assertNotEqual(plugin.wait(timeout=10), 0)
        deadline = time.monotonic() + 5
        while True:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                break
            if time.monotonic() > deadline:
                os.killpg(pgid, signal.SIGKILL)
                self.fail("Prowler outlived the plugin")
            time.sleep(0.05)
        self.assertFalse(os.path.exists(outdir), "the output directory is left behind")

    def test_crash_is_an_error_with_prowlers_reason(self):
        self.fake.flag("crash", GAMMA)
        _, records = self.fake.run()
        gamma = [s for s in of(records, "status") if s.get("scope") == GAMMA][0]
        self.assertEqual((gamma["account"], gamma["state"]), (BOB, "error"))
        self.assertIn("boom while loading checks", gamma["detail"])

    def test_unreadable_api_state_leaves_the_project_uninspected(self):
        self.fake.flag("unknown", ALPHA)
        _, records = self.fake.run()
        alpha = [s for s in of(records, "status") if s.get("scope") == ALPHA][0]
        self.assertEqual(alpha["state"], "noscope")
        self.assertIn("HTTP 403) on compute,", alpha["detail"])
        self.assertIn("roles/serviceusage.serviceUsageViewer", alpha["detail"])
        self.assertTrue([f for f in of(records, "finding") if f["scope"] == ALPHA], "what was read is still reported")

    def test_refused_project_calls_leave_it_uninspected_but_organization_calls_do_not(self):
        self.fake.flag("refused", BETA)
        _, records = self.fake.run()
        beta = [s for s in of(records, "status") if s.get("scope") == BETA][0]
        self.assertEqual(beta["state"], "noscope")
        self.assertIn("HTTP 403) on storage,", beta["detail"])
        self.assertNotIn("essentialcontacts", beta["detail"])

    def test_missing_prowler_or_gcloud_is_unsupported_everywhere(self):
        empty = tempfile.mkdtemp()
        try:
            os.symlink(os.path.join(FAKEBIN, "gcloud"), os.path.join(empty, "gcloud"))
            _, records = self.fake.run(env_extra={"PATH": empty + os.pathsep + "/usr/bin:/bin"})
        finally:
            shutil.rmtree(empty)
        self.assertEqual([(s["account"], s["scope"], s["state"]) for s in of(records, "status")], [("gcp", "*", "unsupported")])
        self.assertIn("pipx install", of(records, "status")[0]["detail"])

    def test_prowler_path_from_config(self):
        bin_dir = tempfile.mkdtemp()
        try:
            os.symlink(os.path.join(FAKEBIN, "gcloud"), os.path.join(bin_dir, "gcloud"))
            _, records = self.fake.run({"prowler_path": os.path.join(FAKEBIN, "prowler")},
                                       env_extra={"PATH": bin_dir + os.pathsep + "/usr/bin:/bin"})
        finally:
            shutil.rmtree(bin_dir)
        self.assertTrue(of(records, "finding"))

    def test_parallel_runs_give_the_same_result(self):
        _, serial = self.fake.run()
        _, parallel = self.fake.run({"parallel": 3})
        key = lambda rs: sorted(json.dumps(r, sort_keys=True) for r in rs)
        self.assertEqual(key(serial), key(parallel))

    def test_other_providers(self):
        _, records = self.fake.run({"providers": ["aws", "oracle"]})
        self.assertEqual([(s["account"], s["state"]) for s in of(records, "status")], [("aws", "unsupported"), ("oracle", "error")])
        self.assertEqual(self.fake.prowler_runs(), [])

    def test_bad_config_is_an_error_status(self):
        _, records = self.fake.run({"severity_min": "severe"})
        self.assertEqual([(s["state"], s["scope"]) for s in of(records, "status")], [("error", "*")])


def profile(cls="unknown", in_org=None, **over):
    p = dict(prowler.UNKNOWN_PROFILE, **over)
    p.update({"class": cls, "in_organization": in_org})
    return p


def known(services_non_default=0, billing=False, **resources):
    p = {"services_enabled": services_non_default + 4, "services_non_default": services_non_default,
         "billing_enabled": billing, "in_organization": True, "unread": [],
         "resources": {k: 0 for k, _, _, _ in prowler.RESOURCE_KINDS}}
    p["resources"].update(resources)
    return p


class ProfileTest(unittest.TestCase):
    def test_classification(self):
        c = prowler.classify_profile
        self.assertEqual(c(known()), "empty")
        self.assertEqual(c(known(services_non_default=5)), "empty")
        self.assertEqual(c(known(services_non_default=6)), "light")
        self.assertEqual(c(known(buckets=2)), "light", "buckets without billing")
        self.assertEqual(c(known(buckets=2, billing=True)), "production", "billing on with resources")
        self.assertEqual(c(known(billing=True)), "empty", "billing on with nothing to bill")
        for kind in ("compute_instances", "gke_clusters", "sql_instances", "run_services", "functions"):
            self.assertEqual(c(known(**{kind: 1})), "production", kind)

    def test_what_was_not_read_never_makes_a_project_look_idle(self):
        c = prowler.classify_profile
        self.assertEqual(c(known(sql_instances=None)), "unknown")
        self.assertEqual(c(known(sql_instances=None, run_services=3)), "production", "a workload is enough")
        self.assertEqual(c(dict(known(), services_non_default=None)), "unknown")
        self.assertEqual(c(dict(known(buckets=1), billing_enabled=None)), "unknown")
        self.assertEqual(c(dict(known(), billing_enabled=None)), "empty", "billing only matters with resources")

    def test_default_services_follow_googles_list(self):
        self.assertEqual(len(prowler.DEFAULT_SERVICES), 23)
        self.assertIn("serviceusage.googleapis.com", prowler.DEFAULT_SERVICES)
        self.assertNotIn("compute.googleapis.com", prowler.DEFAULT_SERVICES)

    def test_gcloud_runs_only_read_commands(self):
        g = prowler.Gcloud("/nonexistent/gcloud")
        for args in (("projects", "delete", "p"), ("services", "enable", "x"), ("config", "set", "account", "a"),
                     ("compute", "instances", "delete", "vm"), ("storage", "rm", "gs://b")):
            with self.assertRaises(ValueError, msg=args):
                g.run(*args)
        for command in prowler.READ_COMMANDS:
            self.assertIn(command[-1], ("list", "describe", "print-access-token"), command)


class RelevanceTest(unittest.TestCase):
    LOG = "logging_sink_created"
    SSH = "compute_firewall_ssh_access_from_the_internet_allowed"

    def weigh(self, check, severity, prof, kind="setting", **config):
        return prowler.weigh(check, kind, severity, prof, prowler.Config(config))

    def test_hygiene_checks_follow_the_profile(self):
        self.assertEqual(self.weigh(self.LOG, "medium", profile("empty")), ("info", "hygiene check in an empty project"))
        self.assertEqual(self.weigh(self.LOG, "medium", profile("light"))[0], "low")
        self.assertEqual(self.weigh("iam_cloud_asset_inventory_enabled", "high", profile("light"))[0], "medium")
        self.assertEqual(self.weigh(self.LOG, "info", profile("light")), ("info", ""))
        for cls in ("production", "unknown"):
            self.assertEqual(self.weigh(self.LOG, "medium", profile(cls)), ("medium", ""), cls)

    def test_exposure_is_never_lowered_by_the_profile(self):
        self.assertEqual(self.weigh(self.SSH, "critical", profile("empty"), kind="exposure"), ("critical", ""))
        self.assertEqual(self.weigh("compute_instance_default_service_account_in_use_with_full_api_access", "high",
                                    profile("empty")), ("high", ""))
        self.assertEqual(self.weigh(self.LOG, "medium", profile("empty"), kind="exposure"), ("medium", ""),
                         "a hygiene check whose categories say internet-exposed is protected")
        self.assertEqual(self.weigh(self.LOG, "medium", profile("empty"), kind="credential"), ("medium", ""))
        self.assertFalse(prowler.HYGIENE_CHECKS & prowler.PROTECTED_CHECKS)

    def test_toggle_and_overrides(self):
        self.assertEqual(self.weigh(self.LOG, "medium", profile("empty"), relevance=False), ("medium", ""))
        self.assertEqual(self.weigh(self.LOG, "medium", profile("empty"), relevance_overrides={self.LOG: "keep"}), ("medium", ""))
        self.assertEqual(self.weigh("kms_key_rotation_enabled", "low", profile("production"),
                                    relevance_overrides={"kms_key_rotation_enabled": "info"}),
                         ("info", "relevance_overrides sets it to info"))
        for bad in ({self.LOG: "drop"}, ["x"]):
            with self.assertRaises(ValueError):
                prowler.Config({"relevance_overrides": bad})

    def test_not_applicable(self):
        aa = "iam_account_access_approval_enabled"
        sev, why = self.weigh(aa, "high", profile("production", in_org=False))
        self.assertEqual(sev, "info")
        self.assertIn("Access Transparency", why)
        self.assertTrue(why.startswith("not applicable: "))
        self.assertEqual(self.weigh(aa, "high", profile("production", in_org=True)), ("high", ""), "fixable inside an organization")
        self.assertEqual(self.weigh(aa, "high", profile("production", in_org=None)), ("high", ""), "unknown parent: not assumed")
        self.assertEqual(self.weigh(aa, "high", profile("light", in_org=True))[0], "medium", "still a hygiene check")
        mine = {"not_applicable": [{"check": self.LOG, "reason": "logs go to the SIEM through the org sink"}]}
        self.assertEqual(self.weigh(self.LOG, "medium", profile("production", in_org=True), **mine),
                         ("info", "not applicable: logs go to the SIEM through the org sink"))
        self.assertEqual(self.weigh(aa, "high", profile("production", in_org=False), **mine), ("high", ""),
                         "a configured list replaces the default one")
        self.assertEqual(self.weigh(aa, "high", profile("production", in_org=False), not_applicable=[]), ("high", ""))
        for bad in ([{"check": "x"}], [{"reason": "y"}], [{"check": 5, "reason": "y"}], ["x"],
                    [{"check": "x", "reason": "y", "where": "sometimes"}], {"x": "y"}):
            with self.assertRaises(ValueError, msg=bad):
                prowler.Config({"not_applicable": bad})


class RelevanceInventoryTest(unittest.TestCase):
    """A project's profile, read with gcloud, weighs its findings end to end."""

    def setUp(self):
        self.fake = Fake()
        self.fake.projects(ALICE, [DELTA])
        self.fake.projects(BOB, [])

    def tearDown(self):
        self.fake.close()

    def run_delta(self, config=None):
        _, records = self.fake.run(dict({"projects": [DELTA]}, **(config or {})))
        findings = {f["evidence"]["check_id"]: f for f in of(records, "finding")}
        status = [s for s in of(records, "status") if s.get("scope") == DELTA][0]
        return findings, status

    def test_empty_project_keeps_exposures_and_quiets_hygiene(self):
        self.fake.profile(DELTA, services=DEFAULTS + ["generativelanguage.googleapis.com"])
        findings, status = self.run_delta()
        sev = {c: f["severity"] for c, f in findings.items()}
        self.assertEqual(sev, {
            "logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled": "info",
            "logging_sink_created": "info",
            "iam_cloud_asset_inventory_enabled": "info",
            "iam_account_access_approval_enabled": "info",
            "compute_firewall_rdp_access_from_the_internet_allowed": "critical",
            "compute_instance_default_service_account_in_use_with_full_api_access": "high",
        })
        sink = findings["logging_sink_created"]["evidence"]
        self.assertEqual((sink["prowler_severity"], sink["relevance"]), ("medium", "hygiene check in an empty project"))
        self.assertEqual(sink["profile"]["class"], "empty")
        self.assertEqual((sink["profile"]["services_non_default"], sink["profile"]["in_organization"]), (1, False))
        aa = findings["iam_account_access_approval_enabled"]["evidence"]
        self.assertTrue(aa["relevance"].startswith("not applicable: "))
        self.assertEqual(aa["prowler_severity"], "high")
        self.assertNotIn("relevance", findings["compute_firewall_rdp_access_from_the_internet_allowed"]["evidence"])
        self.assertEqual(status["state"], "ok")
        self.assertIn("profile empty: 1 non-default services, billing off; 3 lowered by relevance, 1 not applicable", status["detail"])
        calls = self.fake.calls()
        self.assertIn("storage buckets list --project=" + DELTA, calls)
        for skipped in ("compute instances", "container clusters", "sql instances", "run services", "functions list"):
            self.assertNotIn(skipped, calls, "a disabled API has nothing to list")

    def test_light_project_lowers_hygiene_one_level(self):
        self.fake.projects(ALICE, [DELTA], parent={"type": "organization", "id": "1"})
        self.fake.profile(DELTA, services=DEFAULTS + ["firebase.googleapis.com"], storage=1)
        findings, status = self.run_delta()
        self.assertEqual(findings["logging_sink_created"]["severity"], "low")
        self.assertEqual(findings["iam_cloud_asset_inventory_enabled"]["severity"], "medium")
        self.assertEqual(findings["iam_account_access_approval_enabled"]["severity"], "medium", "in an organization: hygiene, not n/a")
        self.assertEqual(findings["compute_firewall_rdp_access_from_the_internet_allowed"]["severity"], "critical")
        self.assertIn("profile light: 1 non-default services, 1 buckets, billing off; 4 lowered", status["detail"])

    def test_production_project_keeps_prowlers_severity(self):
        self.fake.projects(ALICE, [DELTA], parent={"type": "folder", "id": "7"})
        self.fake.profile(DELTA, services=DEFAULTS + ["run.googleapis.com"], run=2)
        findings, status = self.run_delta()
        self.assertTrue(all(f["severity"] == f["evidence"]["prowler_severity"] for f in findings.values()))
        self.assertFalse([f for f in findings.values() if "relevance" in f["evidence"]])
        self.assertTrue(findings["logging_sink_created"]["evidence"]["profile"]["in_organization"], "a folder is under an organization")
        self.assertIn("profile production: 1 non-default services, 2 run services, billing off; 0 lowered", status["detail"])

    def test_unreadable_profile_changes_nothing_but_not_applicable(self):
        findings, status = self.run_delta()  # no services or billing answer; resource lists read as empty
        self.assertEqual(findings["logging_sink_created"]["severity"], "medium")
        self.assertEqual(findings["logging_sink_created"]["evidence"]["profile"]["class"], "unknown")
        self.assertEqual(findings["iam_account_access_approval_enabled"]["severity"], "info", "the parent comes from projects list")
        self.assertIn("profile unknown: not read: services, billing;", status["detail"])

    def test_denied_resource_list_is_unknown_not_empty(self):
        self.fake.profile(DELTA, services=DEFAULTS + ["sqladmin.googleapis.com"])
        self.fake.flag("profile", DELTA, "deny-sql")
        findings, status = self.run_delta()
        self.assertEqual(findings["logging_sink_created"]["severity"], "medium")
        self.assertEqual(findings["logging_sink_created"]["evidence"]["profile"]["unread"], ["sql_instances"])
        self.assertIn("not read: sql_instances", status["detail"])

    def test_throttled_read_is_retried_once_and_failures_are_logged_with_the_reason(self):
        self.fake.profile(DELTA, services=DEFAULTS)
        self.fake.flag("profile", DELTA, "flaky-billing")
        findings, _ = self.run_delta()
        self.assertEqual(findings["logging_sink_created"]["evidence"]["profile"]["unread"], [])
        self.assertEqual(self.fake.calls().count("billing projects describe " + DELTA), 2)
        os.remove(os.path.join(self.fake.dir, "profile", DELTA, "billing.json"))
        _, records = self.fake.run({"projects": [DELTA]})
        logs = [r["msg"] for r in of(records, "log")]
        self.assertIn("%s: profile could not read billing as %s: ERROR: (gcloud) fake has no" % (DELTA, ALICE), "\n".join(logs))

    def test_relevance_off_still_records_the_profile(self):
        self.fake.profile(DELTA, services=DEFAULTS)
        findings, _ = self.run_delta({"relevance": False})
        self.assertEqual(findings["logging_sink_created"]["severity"], "medium")
        self.assertEqual(findings["logging_sink_created"]["evidence"]["profile"]["class"], "empty")

    def test_profile_is_read_as_the_account_that_answered(self):
        self.fake.projects(BOB, [DELTA])
        self.fake.flag("deny", DELTA, ALICE)
        self.fake.profile(DELTA, services=DEFAULTS)
        findings, _ = self.run_delta()
        self.assertEqual(findings["logging_sink_created"]["account"], ALICE)
        self.assertIn("services list --enabled --project=%s --account=%s" % (DELTA, BOB), self.fake.calls())
        self.assertNotIn("services list --enabled --project=%s --account=%s" % (DELTA, ALICE), self.fake.calls())


class ScrubTest(unittest.TestCase):
    def test_tokens_never_leave_through_any_record(self):
        import io
        out = io.StringIO()
        emit = prowler.Emitter(out)
        emit.add_secret("opaque-secret-value")
        emit.status("a", "error", "gcloud said opaque-secret-value and ya29.another-TEST-token")
        emit.finding({"title": "x", "evidence": {"nested": ["ya29.TEST-x"]}})
        self.assertNotIn("opaque-secret-value", out.getvalue())
        self.assertNotIn("ya29.", out.getvalue())


if __name__ == "__main__":
    unittest.main()
