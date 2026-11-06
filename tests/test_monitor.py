import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import monitor


def package(identifier="example", version="1.0.0", installed="1.0.0"):
    return monitor.normalize({"properties": {
        "contentId": identifier, "contentKind": "Solution", "displayName": identifier,
        "publisherDisplayName": "Microsoft", "version": version,
        "installedVersion": installed,
    }})


def catalog(*items):
    return {monitor.package_key(item): item for item in items}


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "catalog.sqlite3"
        self.db = monitor.connect(self.path, "workspace")

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def baseline(self):
        return monitor.check(self.db, lambda: catalog(package()), [])

    def updated(self):
        return monitor.check(self.db, lambda: catalog(
            package(version="1.1.0"), package("new", installed=""),
        ), [])

    def test_baseline_is_quiet_and_persistent(self):
        result = self.baseline()
        self.assertTrue(result["baseline_created"])
        self.assertEqual(result["changes_detected"], 0)
        self.db.close()
        self.db = monitor.connect(self.path, "workspace")
        self.assertFalse(self.baseline()["baseline_created"])

    def test_three_changes_and_no_repeat_events(self):
        self.baseline()
        self.assertEqual(self.updated()["changes_detected"], 3)
        self.assertEqual(self.updated()["changes_detected"], 0)
        self.assertEqual(len(monitor.pending_rows(self.db)), 3)
        kinds = {json.loads(row["payload"])["change_type"] for row in monitor.pending_rows(self.db)}
        self.assertEqual(kinds, {"new_package", "published_version_changed", "installed_version_gap"})

    def test_failed_retrieval_preserves_baseline(self):
        self.baseline()
        before = list(self.db.execute("SELECT * FROM packages"))
        def fail():
            raise monitor.MonitorError("partial fetch failed")
        with self.assertRaises(monitor.MonitorError):
            monitor.check(self.db, fail, [])
        self.assertEqual([tuple(r) for r in before],
                         [tuple(r) for r in self.db.execute("SELECT * FROM packages")])
        self.assertEqual(self.updated()["changes_detected"], 3)

    def test_disappeared_package_is_not_new_when_it_returns(self):
        monitor.check(self.db, lambda: catalog(package(), package("other")), [])
        monitor.check(self.db, lambda: catalog(package("other")), [])
        self.assertEqual(
            monitor.check(self.db, lambda: catalog(package(), package("other")), [])["changes_detected"], 0
        )

    def test_filter_retains_history_without_queueing(self):
        self.baseline()
        result = monitor.check(self.db, lambda: catalog(package(version="2")), ["Another Publisher"])
        self.assertEqual(result["changes_detected"], 2)
        self.assertEqual(monitor.pending_rows(self.db), [])
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2)

    def test_deprecation_and_missing_installed_metadata(self):
        old = package()
        new = package(installed="")
        new["deprecated"] = True
        self.assertEqual(
            [e["change_type"] for e in monitor.changes(catalog(old), catalog(new))], ["deprecated"]
        )

    def test_gap_reappears_after_resolution(self):
        self.baseline()
        monitor.check(self.db, lambda: catalog(package(version="2")), [])
        monitor.check(self.db, lambda: catalog(package(version="2", installed="2")), [])
        result = monitor.check(self.db, lambda: catalog(package(version="2", installed="1")), [])
        self.assertEqual(result["changes_detected"], 1)

    def test_notification_failure_keeps_pending(self):
        self.baseline()
        self.updated()
        def fail(url, payload):
            raise monitor.MonitorError("receiver failed")
        with self.assertRaises(monitor.MonitorError):
            monitor.deliver(self.db, "workspace", "https://example.test/trigger", fail)
        self.assertEqual(len(monitor.pending_rows(self.db)), 3)

    def test_notification_success_and_stable_digest(self):
        self.baseline()
        self.updated()
        before = monitor.digest(monitor.pending_rows(self.db), "workspace")
        received = []
        self.assertEqual(monitor.deliver(
            self.db, "workspace", "https://example.test/trigger",
            lambda url, payload: received.append(payload),
        ), 3)
        self.assertEqual(received[0], before)
        self.assertEqual(received[0]["schema_version"], 1)
        self.assertEqual(len(received[0]["events"]), 3)
        self.assertIn("installed_version_gap", received[0]["text"])
        self.assertEqual(monitor.pending_rows(self.db), [])
        self.assertEqual(monitor.deliver(
            self.db, "workspace", "https://example.test/trigger",
            lambda *_: self.fail("should not send an empty digest"),
        ), 0)

    def test_delivery_batch_limit(self):
        self.baseline()
        monitor.check(self.db, lambda: catalog(*(package(str(i), installed="") for i in range(30))), [])
        self.assertEqual(monitor.deliver(
            self.db, "workspace", "https://example.test/trigger", lambda *_: None,
        ), 25)
        self.assertEqual(len(monitor.pending_rows(self.db)), 5)

    def test_other_workspace_database_rejected(self):
        with self.assertRaises(monitor.MonitorError):
            monitor.connect(self.path, "another-workspace")

    def test_cli_fixture_persistence_and_status(self):
        root = Path(monitor.__file__).parent
        config = json.loads((root / "demo.config.json").read_text(encoding="utf-8"))
        config["database"] = str(Path(self.temp.name) / "cli.sqlite3")
        config_path = Path(self.temp.name) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        prefix = [sys.executable, str(root / "monitor.py"), "--config", str(config_path)]
        first = subprocess.run(
            prefix + ["check", "--fixture", str(root / "demo-baseline.json")],
            capture_output=True, text=True, check=True,
        )
        self.assertTrue(json.loads(first.stdout)["baseline_created"])
        changed = subprocess.run(
            prefix + ["check", "--fixture", str(root / "demo-changes.json")],
            capture_output=True, text=True, check=True,
        )
        decoder = json.JSONDecoder()
        summary, end = decoder.raw_decode(changed.stdout)
        payload = json.loads(changed.stdout[end:])
        self.assertEqual(summary["changes_detected"], 3)
        self.assertEqual(len(payload["events"]), 3)
        repeated = subprocess.run(
            prefix + ["check", "--fixture", str(root / "demo-changes.json")],
            capture_output=True, text=True, check=True,
        )
        self.assertEqual(decoder.raw_decode(repeated.stdout)[0]["changes_detected"], 0)
        status = subprocess.run(prefix + ["status"], capture_output=True, text=True, check=True)
        state = json.loads(status.stdout)
        self.assertEqual(state["catalog_count"], 2)
        self.assertEqual(state["pending_count"], 3)
        history = subprocess.run(prefix + ["history"], capture_output=True, text=True, check=True)
        self.assertEqual(len(json.loads(history.stdout)), 3)
        refused = subprocess.run(
            prefix + ["check", "--fixture", str(root / "demo-changes.json"), "--send"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("cannot be combined", refused.stderr)

    def test_cli_token_uses_configured_subscription(self):
        with patch("monitor.shutil.which", return_value="az.cmd"), patch("monitor.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, "synthetic-token\n", "")
            self.assertEqual(monitor.cli_token("subscription"), "synthetic-token")
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--subscription") + 1], "subscription")
            self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_cli_token_failure_is_explicit_and_does_not_expose_output(self):
        with patch("monitor.shutil.which", return_value="az.cmd"), patch("monitor.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 1, "", "private diagnostic")
            with self.assertRaises(monitor.MonitorError) as error:
                monitor.cli_token("subscription")
            self.assertNotIn("private diagnostic", str(error.exception))
            run.side_effect = subprocess.TimeoutExpired("az", 120)
            with self.assertRaisesRegex(monitor.MonitorError, "timed out"):
                monitor.cli_token("subscription")


class CatalogTests(unittest.TestCase):
    url = "https://management.azure.com/subscriptions/example/contentProductPackages?api-version=2025-09-01"

    @staticmethod
    def raw(identifier="example"):
        item = package(identifier)
        return {"properties": {
            "contentId": item["content_id"], "contentKind": item["kind"],
            "displayName": item["name"], "version": item["version"],
        }}

    def test_pagination(self):
        next_url = self.url + "&$skipToken=next"
        pages = {self.url: {"value": [self.raw()], "nextLink": next_url},
                 next_url: {"value": [self.raw("other")]}}
        self.assertEqual(len(monitor.fetch_catalog(self.url, pages.__getitem__)), 2)

    def test_untrusted_nextlink_rejected_before_request(self):
        calls = []
        def get(url):
            calls.append(url)
            return {"value": [self.raw()], "nextLink": "https://evil.test/"}
        with self.assertRaises(monitor.MonitorError):
            monitor.fetch_catalog(self.url, get)
        self.assertEqual(calls, [self.url])

    def test_invalid_empty_duplicate_and_loop_catalogs(self):
        for page in ({}, {"value": []}, {"value": [self.raw(), self.raw()]},
                     {"value": [self.raw()], "nextLink": self.url},
                     {"value": [{"properties": {"version": "1"}}]}):
            with self.subTest(page=page), self.assertRaises(monitor.MonitorError):
                monitor.fetch_catalog(self.url, lambda _: page)

    def test_flags_parse_false_string(self):
        raw = self.raw()
        raw["properties"]["isDeprecated"] = "false"
        self.assertFalse(monitor.normalize(raw)["deprecated"])
        raw["properties"]["isDeprecated"] = "true"
        self.assertTrue(monitor.normalize(raw)["deprecated"])
        raw["properties"]["isDeprecated"] = "garbage"
        with self.assertRaises(monitor.MonitorError):
            monitor.normalize(raw)

    def test_unsafe_webhook_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            db = monitor.connect(Path(directory) / "test.sqlite3", "scope")
            try:
                with self.assertRaises(monitor.MonitorError):
                    monitor.deliver(db, "scope", "http://example.test/", lambda *_: None)
            finally:
                db.close()

    def test_http_read_retries_but_send_does_not(self):
        error = monitor.HTTPError(self.url, 503, "Unavailable", {}, None)
        with patch("monitor.build_opener") as build, patch("monitor.time.sleep") as sleep:
            build.return_value.open.side_effect = error
            with self.assertRaises(monitor.MonitorError):
                monitor.request_json(self.url, token="synthetic")
            self.assertEqual(build.return_value.open.call_count, 4)
            self.assertEqual(sleep.call_count, 3)
            build.return_value.open.reset_mock()
            with self.assertRaises(monitor.MonitorError):
                monitor.request_json(self.url, payload={"text": "synthetic"})
            self.assertEqual(build.return_value.open.call_count, 1)


if __name__ == "__main__":
    unittest.main()
