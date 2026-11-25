"""Tests for segurata-hibp against a fake HIBP server on 127.0.0.1. No real network."""

import importlib.machinery
import importlib.util
import io
import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "segurata-hibp")

_loader = importlib.machinery.SourceFileLoader("segurata_hibp", SCRIPT)
_spec = importlib.util.spec_from_loader("segurata_hibp", _loader)
hibp = importlib.util.module_from_spec(_spec)
_loader.exec_module(hibp)

# Synthetic, obviously fake key: it must never show up in output.
KEY = "0000test0000not0a0real0key000000"
NOW = datetime(2026, 11, 24, tzinfo=timezone.utc)


def breach(name, classes, breach_date="2013-10-04", added="2013-12-04T00:00:00Z", **flags):
    b = {
        "Name": name, "Title": name, "Domain": name.lower() + ".com", "BreachDate": breach_date,
        "AddedDate": added, "ModifiedDate": added, "PwnCount": 1000, "Description": "<p>x</p>",
        "DataClasses": classes, "IsVerified": True, "IsFabricated": False, "IsSensitive": False,
        "IsRetired": False, "IsSpamList": False, "IsMalware": False, "IsStealerLog": False,
        "IsSubscriptionFree": False, "LogoPath": "https://example.com/logo.png",
    }
    b.update(flags)
    return b


class FakeHIBP:
    """Serves /api/v3/breachedaccount/<email> from a dict of email -> list of (status, body, headers)."""

    def __init__(self, answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                fake.requests.append((self.command, parsed.path, urllib.parse.parse_qs(parsed.query), {k.lower(): v for k, v in self.headers.items()}))
                email = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
                queue = fake.answers.get(email) or [(404, None, {})]
                status, body, headers = queue.pop(0) if len(queue) > 1 else queue[0]
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                if body is not None:
                    self.wfile.write(json.dumps(body).encode())

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = "http://127.0.0.1:%d/api/v3" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def run(req, sleeps=None):
    out = io.StringIO()
    hibp.inventory(req, hibp.Emitter(out), sleep=(sleeps.append if sleeps is not None else lambda s: None), now=NOW)
    return [json.loads(line) for line in out.getvalue().splitlines()], out.getvalue()


def request(server, emails, **config):
    config.update({"emails": emails, "base_url": server.url, "request_delay_seconds": 0})
    return {"protocol": 2, "config": config, "secrets": {"HIBP_API_KEY": KEY}}


class DescribeTest(unittest.TestCase):
    def test_describe_speaks_protocol_2_and_needs_the_key(self):
        out = io.StringIO()
        self.assertEqual(hibp.main(["segurata-hibp", "describe"], stdout=out), 0)
        d = json.loads(out.getvalue())
        self.assertEqual((d["name"], d["protocol"], d["needs"]), ("hibp", 2, ["secret:HIBP_API_KEY"]))
        self.assertNotIn("remediates", d)
        self.assertEqual(d["covers"], [{"id": "hibp"}])


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.server = None

    def tearDown(self):
        if self.server:
            self.server.close()

    def serve(self, answers):
        self.server = FakeHIBP(answers)
        return self.server

    def test_missing_key_is_a_status_with_how_to_get_one(self):
        records, _ = run({"protocol": 2, "config": {"emails": ["a@example.com"]}})
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "missing_credentials")
        self.assertIn("https://haveibeenpwned.com/API/Key", records[0]["detail"])
        self.assertIn("keychain:", records[0]["detail"])

    def test_no_emails_is_an_error_status(self):
        records, _ = run({"protocol": 2, "config": {}, "secrets": {"HIBP_API_KEY": KEY}})
        self.assertEqual([r["state"] for r in records], ["error"])

    def test_one_finding_per_breach_with_headers_and_full_response(self):
        s = self.serve({"me+tag@example.com": [(200, [
            breach("Adobe", ["Email addresses", "Password hints", "Passwords", "Usernames"]),
            breach("Cards", ["Credit cards", "Email addresses"], breach_date="2023-01-01", added="2023-02-01T00:00:00Z"),
            breach("Forum", ["Email addresses", "Usernames"], breach_date="2023-05-01", added="2023-06-01T00:00:00Z"),
            breach("Fresh", ["Email addresses", "Passwords"], breach_date="2026-06-01", added="2026-07-01T10:00:00Z"),
            breach("Old", ["Email addresses"], breach_date="2010-01-01", added="2011-01-01T00:00:00Z"),
            breach("Spam", ["Email addresses", "Passwords"], IsSpamList=True, Domain=""),
            breach("Fake", ["Passwords"], IsFabricated=True),
        ], {})]})
        records, raw = run(request(s, ["me+tag@example.com"]))
        method, path, query, headers = s.requests[0]
        self.assertEqual(method, "GET")
        self.assertEqual(path, "/api/v3/breachedaccount/me%2Btag%40example.com")
        self.assertEqual(query, {"truncateResponse": ["false"]})
        self.assertEqual(headers.get("hibp-api-key"), KEY)
        self.assertEqual(headers.get("user-agent"), "segurata-hibp")

        findings = {r["resource"]["id"]: r for r in records if r["type"] == "finding"}
        self.assertEqual({k: f["severity"] for k, f in findings.items()}, {
            "Adobe": "high",     # passwords, old: still high, the password may be reused
            "Cards": "medium",   # financial data, no password
            "Forum": "low",      # addresses and usernames only
            "Fresh": "critical", # passwords within the last year
            "Old": "info",       # no passwords, over five years old
            "Spam": "low",       # spam list caps at low
            "Fake": "info",      # fabricated
        })
        adobe = findings["Adobe"]
        self.assertEqual((adobe["kind"], adobe["account"], adobe["resource"]["type"]), ("exposure", "me+tag@example.com", "breach"))
        self.assertIn("adobe.com", adobe["remediation"]["summary"])
        self.assertIn("anywhere else", adobe["remediation"]["summary"])
        self.assertEqual(adobe["remediation"]["url"], "https://adobe.com")
        self.assertEqual(adobe["created_at"], "2013-10-04T00:00:00Z")
        self.assertIsNone(adobe["last_used_at"])
        self.assertNotIn("id", adobe)  # the core computes stable ids
        self.assertIn("the service behind Spam", findings["Spam"]["remediation"]["summary"])
        self.assertTrue(findings["Forum"]["remediation"]["summary"].startswith("No password"))
        statuses = [r for r in records if r["type"] == "status"]
        self.assertEqual([(r["account"], r["state"], r["detail"]) for r in statuses], [("me+tag@example.com", "ok", "7 breaches")])
        self.assertNotIn(KEY, raw)

    def test_not_found_means_not_breached(self):
        s = self.serve({})
        records, _ = run(request(s, ["clean@example.com"], include_unverified=False))
        self.assertEqual([(r["type"], r["state"]) for r in records], [("status", "ok")])
        self.assertEqual(s.requests[0][2]["IncludeUnverified"], ["false"])

    def test_a_rejected_key_stops_and_says_so(self):
        s = self.serve({"a@example.com": [(401, None, {})]})
        records, raw = run(request(s, ["a@example.com", "b@example.com"]))
        self.assertEqual(len(s.requests), 1, "no point asking again with a rejected key")
        self.assertEqual([(r["account"], r["state"]) for r in records], [("haveibeenpwned", "missing_credentials")])
        self.assertNotIn(KEY, raw)

    def test_forbidden_stops(self):
        s = self.serve({"a@example.com": [(403, None, {})]})
        records, _ = run(request(s, ["a@example.com", "b@example.com"]))
        self.assertEqual(len(s.requests), 1)
        self.assertEqual(records[0]["state"], "error")
        self.assertIn("403", records[0]["detail"])

    def test_rate_limit_waits_for_retry_after_then_retries(self):
        s = self.serve({"a@example.com": [(429, None, {"retry-after": "2"}), (200, [breach("Adobe", ["Passwords"])], {})]})
        sleeps = []
        records, _ = run(request(s, ["a@example.com"]), sleeps)
        self.assertEqual(sleeps, [2])
        self.assertEqual([r["type"] for r in records], ["log", "finding", "status"])

    def test_rate_limit_gives_up_after_retries_and_stops(self):
        s = self.serve({"a@example.com": [(429, None, {"retry-after": "1"})]})
        sleeps = []
        records, _ = run(request(s, ["a@example.com", "b@example.com"]), sleeps)
        self.assertEqual(len(sleeps), hibp.MAX_RETRIES)
        self.assertEqual(records[-1]["state"], "error")
        self.assertTrue(all(r[1].endswith("a%40example.com") for r in s.requests))

    def test_bad_address_does_not_stop_the_others_and_requests_are_spaced(self):
        s = self.serve({"bad": [(400, None, {})]})
        req = request(s, ["bad", "good@example.com"])
        req["config"]["request_delay_seconds"] = 6
        sleeps = []
        records, _ = run(req, sleeps)
        self.assertEqual([(r["account"], r["state"]) for r in records], [("bad", "error"), ("good@example.com", "ok")])
        self.assertEqual(sleeps, [6])

    def test_base_url_must_not_send_the_key_elsewhere(self):
        for url in ("http://example.com/api/v3", "ftp://127.0.0.1/"):
            records, _ = run({"protocol": 2, "config": {"emails": ["a@example.com"], "base_url": url}, "secrets": {"HIBP_API_KEY": KEY}})
            self.assertEqual(records[0]["state"], "error", url)

    def test_runs_as_a_program_over_protocol_1(self):
        s = self.serve({"a@example.com": [(200, [breach("Adobe", ["Passwords"])], {})]})
        req = request(s, ["a@example.com"])
        req["protocol"] = 1
        proc = subprocess.run([sys.executable, "-I", SCRIPT, "inventory"], input=json.dumps(req), capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        types = [json.loads(line)["type"] for line in proc.stdout.splitlines()]
        self.assertEqual(types, ["finding", "status"])
        self.assertNotIn(KEY, proc.stdout + proc.stderr)
        bad = subprocess.run([sys.executable, "-I", SCRIPT, "inventory"], input='{"protocol":3}', capture_output=True, text=True, timeout=30)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
