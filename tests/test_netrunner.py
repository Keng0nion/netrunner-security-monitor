# pyright: reportUninitializedInstanceVariable=false
from __future__ import annotations

import io
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, final
from unittest import mock

from source import netrunner
from source.data_platform import DataStore


def status_event(run_id, collector):
    return {
        "schema_version": 1,
        "run_id": run_id,
        "event_type": "collector_status",
        "collector": collector,
        "status": "running",
    }


def complete_event(run_id, collector, status="success", object_count=0, error=None):
    event = {
        "schema_version": 1,
        "run_id": run_id,
        "event_type": "collector_complete",
        "collector": collector,
        "status": status,
        "object_count": object_count,
        "zero_objects": status == "success" and object_count == 0,
    }
    if error:
        event["error"] = error
    return event


def observation_event(run_id, collector, suffix):
    attributes = {"name": f"device-{suffix}"}
    if collector == "spy.network":
        attributes.update({"ip": f"192.0.2.{suffix}", "mac": f"02:00:00:00:00:{suffix:02X}"})
        identity = {"type": "mac", "value": attributes["mac"]}
    elif collector == "spy.wifi":
        attributes.update({"ssid": f"wifi-{suffix}", "bssid": f"02:00:00:00:01:{suffix:02X}"})
        identity = {"type": "bssid", "value": attributes["bssid"]}
    else:
        attributes.update({"address": f"02:00:00:00:02:{suffix:02X}"})
        identity = {"type": "bluetooth", "value": attributes["address"]}
    return {
        "schema_version": 1,
        "run_id": run_id,
        "source": collector,
        "kind": "observation",
        "identity": identity,
        "attributes": attributes,
    }


class FakeProcess:
    stdout: io.StringIO
    stderr: io.StringIO
    return_code: int
    timeout_once: bool
    wait_calls: int
    killed: bool

    def __init__(
        self,
        stdout: str,
        stderr: str = "",
        return_code: int = 0,
        timeout_once: bool = False,
    ) -> None:
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO(stderr)
        self.return_code = return_code
        self.timeout_once = timeout_once
        self.wait_calls = 0
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.timeout_once and self.wait_calls == 1:
            time.sleep(0.02)
            raise subprocess.TimeoutExpired(["node"], timeout or 0.0)
        return self.return_code

    def kill(self) -> None:
        self.killed = True


@final
class SpyProtocolTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    store: DataStore
    scan_run: dict[str, Any]

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="netrunner-protocol-")
        self.store = DataStore(data_dir=Path(self.temporary.name))
        self.scan_run = self.store.start_run(
            command="test-spy",
            mode="home",
            target=None,
            collectors=list(netrunner.SPY_COLLECTORS),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def run_payload(self, lines, return_code=0, timeout_once=False):
        stdout = "\n".join(json.dumps(line) if not isinstance(line, str) else line for line in lines) + "\n"
        process = FakeProcess(stdout, "diagnostic\n", return_code, timeout_once)
        with mock.patch.object(netrunner.shutil, "which", return_value="/mock/node"), \
             mock.patch.object(netrunner.subprocess, "Popen", return_value=process):
            result = netrunner.run_spy_collector(
                self.store, self.scan_run, timeout_seconds=0.01 if timeout_once else 2
            )
        return result, process

    def successful_zero_payload(self):
        lines = []
        for collector in netrunner.SPY_COLLECTORS:
            lines.extend([
                status_event(self.scan_run["id"], collector),
                complete_event(self.scan_run["id"], collector),
            ])
        return lines

    def test_status_events_are_not_ingested_and_successful_zero_objects_is_success(self):
        result, _ = self.run_payload(self.successful_zero_payload())
        self.assertTrue(result["ok"])
        self.assertEqual(result["accepted"], 0)
        self.assertEqual(result["rejected"], [])
        self.assertEqual(result["successful_collectors"], list(netrunner.SPY_COLLECTORS))
        with self.store.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 0)
        statuses = {
            item["collector"]: item
            for item in self.store.get_collector_results(self.scan_run["id"])
        }
        self.assertTrue(all(item["status"] == "success" for item in statuses.values()))
        self.assertTrue(all(item["zero_objects"] for item in statuses.values()))

    def test_command_failed_channel_and_nonzero_exit_are_errors(self):
        lines = []
        for collector in netrunner.SPY_COLLECTORS:
            status = "command_failed" if collector == "spy.wifi" else "success"
            error = "airport denied" if collector == "spy.wifi" else None
            lines.extend([
                status_event(self.scan_run["id"], collector),
                complete_event(self.scan_run["id"], collector, status=status, error=error),
            ])
        result, _ = self.run_payload(lines, return_code=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["collector_results"]["spy.wifi"]["status"], "command_failed")
        self.assertTrue(any("airport denied" in item for item in result["errors"]))
        self.assertTrue(any("退出码 1" in item for item in result["errors"]))

    def test_missing_completion_is_protocol_failure(self):
        lines = self.successful_zero_payload()[:-1]
        result, _ = self.run_payload(lines)
        self.assertFalse(result["ok"])
        self.assertEqual(result["collector_results"]["spy.bluetooth"]["status"], "protocol_failed")
        self.assertTrue(any("缺少 collector_complete" in item for item in result["errors"]))

    def test_invalid_json_line_is_protocol_failure(self):
        lines = self.successful_zero_payload()
        lines.insert(1, "{not-json")
        result, _ = self.run_payload(lines)
        self.assertFalse(result["ok"])
        self.assertEqual(result["accepted"], 0)
        self.assertTrue(any("非法 JSON" in item for item in result["errors"]))

    def test_run_id_mismatch_is_rejected(self):
        lines = self.successful_zero_payload()
        bad = observation_event("wrong-run", "spy.network", 7)
        lines.insert(1, bad)
        result, _ = self.run_payload(lines)
        self.assertFalse(result["ok"])
        self.assertEqual(result["accepted"], 0)
        self.assertTrue(any("run_id 不匹配" in item for item in result["errors"]))

    def test_timeout_preserves_and_ingests_partial_jsonl(self):
        lines = [
            status_event(self.scan_run["id"], "spy.network"),
            observation_event(self.scan_run["id"], "spy.network", 8),
        ]
        result, process = self.run_payload(lines, timeout_once=True)
        self.assertFalse(result["ok"])
        self.assertTrue(result["timed_out"])
        self.assertTrue(process.killed)
        self.assertEqual(result["accepted"], 1)
        self.assertTrue(any("超时前 JSONL" in item for item in result["errors"]))
        with self.store.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 1)
            artifact_paths = [Path(row[0]) for row in conn.execute(
                "SELECT path FROM raw_artifacts WHERE collector = 'spy'"
            )]
        self.assertTrue(any("device-8" in path.read_text(encoding="utf-8") for path in artifact_paths))


@final
class UnifiedCollectorTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    store: DataStore

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="netrunner-unified-")
        self.store = DataStore(data_dir=Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def test_target_validation(self):
        self.assertEqual(netrunner.validate_profile_target("quick", "example.com"), "domain")
        self.assertEqual(netrunner.validate_profile_target("quick", "192.0.2.10"), "ip")
        self.assertEqual(netrunner.validate_profile_target("full", "192.0.2.10"), "ip")
        invalid = [
            ("home", "192.0.2.10"),
            ("quick", None),
            ("quick", "192.0.2.0/24"),
            ("full", "example.com"),
            ("full", "192.0.2.0/24"),
        ]
        for profile, target in invalid:
            with self.subTest(profile=profile, target=target), self.assertRaises(ValueError):
                netrunner.validate_profile_target(profile, target)

    def test_quick_domain_keeps_local_audit_separate(self):
        class FakeScanner:
            target = "sentinel"

            def __init__(self):
                self.scan_errors = []

            def scan_network(self, target_ip=None):
                FakeScanner.target = target_ip
                return [{
                    "ip": "192.0.2.20", "mac": "02:00:00:00:10:20", "ports": [],
                    "services": [], "device_type": "unknown", "confidence": 0.1,
                    "risk_score": 0,
                }]

        class FakeFramework:
            def nmap_scan(self, target, quick=False):
                return {
                    "tool": "nmap", "target": target, "return_code": 0,
                    "open_ports": {
                        "hosts": [{"hostnames": [target], "addresses": [], "ports": []}],
                        "ports": [],
                    },
                }

        spy = {
            "ok": True,
            "accepted": 0,
            "errors": [],
            "collector_results": {
                collector: {"status": "success", "object_count": 0, "zero_objects": True}
                for collector in netrunner.SPY_COLLECTORS
            },
        }
        with mock.patch.object(netrunner, "NetworkScanner", FakeScanner), \
             mock.patch.object(netrunner, "PenTestFramework", FakeFramework), \
             mock.patch.object(netrunner, "run_spy_collector", return_value=spy):
            result = netrunner.collect_profile(self.store, "quick", "example.com")
        self.assertIsNone(FakeScanner.target)
        self.assertEqual(result["run"]["status"], "complete")

    def test_audit_scan_errors_degrade_unified_run(self):
        class FailedAuditScanner:
            def __init__(self):
                self.scan_errors = []

            def scan_network(self, target_ip=None):
                self.scan_errors = ["ARP access denied"]
                return []

        def fake_spy(store, run):
            results = {}
            for collector in netrunner.SPY_COLLECTORS:
                store.record_collector_result(run["id"], collector, "success", 0)
                results[collector] = {"status": "success", "object_count": 0, "zero_objects": True}
            return {"ok": True, "accepted": 0, "errors": [], "collector_results": results}

        with mock.patch.object(netrunner, "NetworkScanner", FailedAuditScanner), \
             mock.patch.object(netrunner, "run_spy_collector", side_effect=fake_spy):
            result = netrunner.collect_profile(self.store, "home", None)
        self.assertEqual(result["run"]["status"], "partial")
        self.assertEqual(result["run"]["collector_states"]["audit"], "command_failed")
        self.assertTrue(any("ARP access denied" in item for item in result["run"]["errors"]))
        self.assertIn("audit", result["analysis"]["data_quality"]["failed_collectors"])

    def test_full_uses_all_nmap_hosts_to_select_nikto_ports(self):
        class FakeScanner:
            def __init__(self):
                self.scan_errors = []

            def scan_network(self, target_ip=None):
                return [{
                    "ip": "192.0.2.30", "mac": "02:00:00:00:10:30", "ports": [],
                    "services": [], "device_type": "unknown", "confidence": 0.1,
                    "risk_score": 0,
                }]

        class FakeFramework:
            nikto_ports = []

            def nmap_scan(self, target, quick=False):
                return {
                    "tool": "nmap", "target": target, "return_code": 0,
                    "open_ports": {
                        "hosts": [
                            {
                                "addresses": [{"address": target, "type": "ipv4"}],
                                "hostnames": [], "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
                            },
                            {
                                "addresses": [{"address": "192.0.2.31", "type": "ipv4"}],
                                "hostnames": [], "ports": [
                                    {"port": 8080, "protocol": "tcp", "service": "http-proxy"},
                                    {"port": 443, "protocol": "tcp", "service": "https"},
                                ],
                            },
                        ],
                        "ports": [],
                    },
                }

            def masscan_scan(self, target):
                return {
                    "tool": "masscan", "target": target, "return_code": 0,
                    "ports": [], "structured_output": [],
                }

            def nikto_scan(self, target, port):
                FakeFramework.nikto_ports.append(port)
                return {
                    "tool": "nikto", "target": f"{target}:{port}", "return_code": 0,
                    "vulnerabilities": [], "vuln_count": 0, "structured_output": {},
                }

        def fake_spy(store, run):
            results = {}
            for collector in netrunner.SPY_COLLECTORS:
                store.record_collector_result(run["id"], collector, "success", 0)
                results[collector] = {"status": "success", "object_count": 0, "zero_objects": True}
            return {"ok": True, "accepted": 0, "errors": [], "collector_results": results}

        with mock.patch.object(netrunner, "NetworkScanner", FakeScanner), \
             mock.patch.object(netrunner, "PenTestFramework", FakeFramework), \
             mock.patch.object(netrunner, "run_spy_collector", side_effect=fake_spy):
            result = netrunner.collect_profile(self.store, "full", "192.0.2.30")
        self.assertEqual(FakeFramework.nikto_ports, [443, 8080])
        self.assertEqual(result["run"]["status"], "complete")
        quality = result["analysis"]["data_quality"]
        self.assertIn("spy.wifi", quality["zero_object_collectors"])
        self.assertEqual(quality["coverage_ratio"], 1.0)
        self.assertLess(quality["observation_coverage_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
