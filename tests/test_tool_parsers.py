# pyright: reportUninitializedInstanceVariable=false
from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import final
from unittest import mock

from source import audit_engine, penetration_test, recon
from source.audit_engine import NetworkScanner, SecurityAudit
from source.data_platform import DataStore
from source.penetration_test import PenTestFramework, classify_target, run_cmd


@final
class ToolParserTests(unittest.TestCase):
    framework: PenTestFramework

    def setUp(self):
        self.framework = PenTestFramework()

    def test_nmap_xml_parser_keeps_single_host_compatibility(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <hostnames><hostname name="camera.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="554">
        <state state="open"/>
        <service name="rtsp" product="Camera Server" version="1.2"/>
      </port>
      <port protocol="tcp"><state state="open"/></port>
    </ports>
    <os><osmatch name="Embedded Linux"/></os>
  </host>
</nmaprun>"""
        parsed = self.framework.parse_nmap_output(xml)
        self.assertEqual(len(parsed["hosts"]), 1)
        self.assertEqual(parsed["os"], "Embedded Linux")
        self.assertEqual(parsed["hostnames"], ["camera.local"])
        self.assertEqual(parsed["addresses"][0]["address"], "192.168.1.20")
        self.assertEqual(parsed["ports"][0]["port"], 554)
        self.assertEqual(parsed["ports"][0]["service"], "rtsp")
        self.assertEqual(len(parsed["ports"]), 1)
        self.assertEqual(parsed["hosts"][0]["ports"], parsed["ports"])

    def test_nmap_xml_parser_separates_multiple_hosts(self):
        xml = """<nmaprun>
  <host>
    <address addr="192.168.1.20" addrtype="ipv4"/>
    <hostnames><hostname name="one.example"/></hostnames>
    <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
  </host>
  <host>
    <address addr="192.168.1.21" addrtype="ipv4"/>
    <hostnames><hostname name="two.example"/></hostnames>
    <ports><port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port></ports>
    <os><osmatch name="Linux"/></os>
  </host>
</nmaprun>"""
        parsed = self.framework.parse_nmap_output(xml)
        self.assertEqual(len(parsed["hosts"]), 2)
        first, second = parsed["hosts"]
        self.assertEqual(first["addresses"][0]["address"], "192.168.1.20")
        self.assertEqual(first["hostnames"], ["one.example"])
        self.assertEqual(first["ports"][0]["port"], 22)
        self.assertEqual(second["addresses"][0]["address"], "192.168.1.21")
        self.assertEqual(second["hostnames"], ["two.example"])
        self.assertEqual(second["os"], "Linux")
        self.assertEqual(second["ports"][0]["protocol"], "udp")
        self.assertEqual([item["port"] for item in parsed["ports"]], [22, 53])
        self.assertEqual(parsed["addresses"], [])

    def test_nmap_text_fallback_supports_no_version_and_tcp_udp(self):
        output = """PORT STATE SERVICE VERSION
22/tcp open ssh
53/udp open domain dnsmasq 2.80
Running: Linux 6.X
"""
        parsed = self.framework.parse_nmap_output(output)
        self.assertEqual(parsed["ports"][0], {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "",
        })
        self.assertEqual(parsed["ports"][1]["protocol"], "udp")
        self.assertEqual(parsed["ports"][1]["version"], "dnsmasq 2.80")
        self.assertEqual(parsed["os"], "Linux 6.X")

    def test_masscan_json_parser(self):
        data = [
            {
                "ip": "192.168.1.30",
                "ports": [
                    {"port": 22, "proto": "tcp", "status": "open"},
                    {"port": 80, "proto": "tcp", "status": "open", "service": {"name": "http"}},
                ],
            },
            {"ip": "192.168.1.31", "port": 443, "proto": "tcp", "status": "open"},
        ]
        parsed = self.framework.parse_masscan_output(data)
        self.assertEqual([item["port"] for item in parsed], [22, 80, 443])
        self.assertEqual(parsed[1]["service"], "http")
        self.assertEqual(parsed[2]["ip"], "192.168.1.31")

    def test_masscan_parser_rejects_wrong_types(self):
        invalid_values = [
            {"ip": "192.168.1.1"},
            ["not-a-host"],
            [{"ip": "192.168.1.1", "ports": {"port": 80}}],
            [{"ip": "192.168.1.1", "ports": ["bad"]}],
            [{"ip": "192.168.1.1", "ports": [{"port": "http"}]}],
        ]
        for value in invalid_values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.framework.parse_masscan_output(value)

    def test_masscan_scan_marks_malformed_json_as_failure(self):
        self.framework.tools["masscan"] = "/mock/masscan"

        def fake_run(cmd, timeout=60):
            output_path = Path(cmd[cmd.index("-oJ") + 1])
            output_path.write_text(json.dumps({"not": "a-list"}), encoding="utf-8")
            return "", "", 0

        with mock.patch.object(penetration_test, "run_cmd", side_effect=fake_run):
            result = self.framework.masscan_scan("192.0.2.10")
        self.assertNotEqual(result["return_code"], 0)
        self.assertIn("parse_error", result)
        self.assertEqual(result["ports"], [])

    def test_nikto_malformed_top_level_and_items_are_failures(self):
        self.framework.tools["nikto"] = "/mock/nikto"
        payloads = [
            ["not-a-dict"],
            {"vulnerabilities": [{"severity": "high"}, "not-a-dict"]},
        ]
        for payload in payloads:
            def fake_run(cmd, timeout=60, payload=payload):
                output_path = Path(cmd[cmd.index("-output") + 1])
                output_path.write_text(json.dumps(payload), encoding="utf-8")
                return "", "", 0

            with self.subTest(payload=payload), mock.patch.object(
                penetration_test, "run_cmd", side_effect=fake_run
            ):
                result = self.framework.nikto_scan("192.0.2.10", 80)
            self.assertNotEqual(result["return_code"], 0)
            self.assertIn("parse_error", result)
            self.assertEqual(result["vulnerabilities"], [])
            self.assertEqual(result["vuln_count"], 0)

    def test_missing_tools_return_structured_failures(self):
        self.framework.tools = {name: None for name in self.framework.tools}
        results = [
            self.framework.nmap_scan("192.0.2.10"),
            self.framework.masscan_scan("192.0.2.10"),
            self.framework.nikto_scan("192.0.2.10", 80),
            self.framework.theharvester_scan("example.com"),
        ]
        for result in results:
            with self.subTest(tool=result["tool"]):
                self.assertNotEqual(result["return_code"], 0)
                self.assertTrue(result["error"])
                self.assertIn("stderr", result)
                self.assertIn("output", result)

    def test_nmap_preserves_stderr_and_nonzero_semantics(self):
        self.framework.tools["nmap"] = "/mock/nmap"
        with mock.patch.object(
            penetration_test, "run_cmd", return_value=("<nmaprun/>", "permission denied", 1)
        ):
            result = self.framework.nmap_scan("192.0.2.10", quick=True)
        self.assertEqual(result["stderr"], "permission denied")
        self.assertEqual(result["error"], "permission denied")
        self.assertEqual(result["return_code"], 1)

    def test_report_uses_risk_accurate_language_and_safe_filename(self):
        self.framework.results = {
            "nmap": {
                "tool": "nmap",
                "return_code": 0,
                "open_ports": {
                    "hosts": [],
                    "ports": [{"port": 23, "protocol": "tcp", "state": "open", "service": "telnet"}],
                },
            }
        }
        for target in ["192.0.2.0/24", "../../evil"]:
            opened = mock.mock_open()
            with self.subTest(target=target), mock.patch("builtins.open", opened):
                report = self.framework.generate_report(target)
            filename = opened.call_args.args[0]
            self.assertEqual(filename, os.path.basename(filename))
            self.assertNotIn("/", filename)
            self.assertEqual(report["summary"]["risk_level"], "高风险")
            self.assertIn(23, report["summary"]["sensitive_ports"])

        self.framework.results = {
            "nmap": {"tool": "nmap", "return_code": 0, "open_ports": {"hosts": [], "ports": []}}
        }
        with mock.patch("builtins.open", mock.mock_open()):
            report = self.framework.generate_report("example.com")
        self.assertEqual(report["summary"]["risk_level"], "未发现已知风险")

        self.framework.results = {}
        with mock.patch("builtins.open", mock.mock_open()):
            report = self.framework.generate_report("example.com")
        self.assertEqual(report["summary"]["risk_level"], "未发现已知风险")
        self.assertEqual(report["summary"]["evidence_status"], "不足")

    def test_node_jsonl_help_keeps_stdout_machine_clean(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js not installed")
        script = Path(__file__).resolve().parents[1] / "源码" / "spy_detector.js"
        result = subprocess.run(
            [node, str(script), "--jsonl", "--help"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("--jsonl", result.stderr)


class CommandAndValidationTests(unittest.TestCase):
    def test_run_cmd_rejects_string_without_invoking_subprocess(self):
        with mock.patch.object(penetration_test.subprocess, "run") as subprocess_run:
            with self.assertRaises(TypeError):
                run_cmd("nmap 192.0.2.1")
        subprocess_run.assert_not_called()

    def test_strict_target_validation(self):
        self.assertEqual(classify_target("192.0.2.1"), "ip")
        self.assertEqual(classify_target("192.0.2.0/24"), "cidr")
        self.assertEqual(classify_target("scanner.example.com"), "domain")
        invalid_targets = [
            "-192.0.2.1",
            " 192.0.2.1",
            "192.0.2.1\n",
            "https://example.com",
            "999.1.1.1",
            "192.0.2.0/99",
            "bad_domain.example",
            "localhost",
        ]
        for target in invalid_targets:
            with self.subTest(target=target), self.assertRaises(ValueError):
                classify_target(target)

    def test_masscan_rejects_domain_with_clear_failure(self):
        framework = PenTestFramework()
        framework.tools["masscan"] = "/mock/masscan"
        result = framework.masscan_scan("example.com")
        self.assertNotEqual(result["return_code"], 0)
        self.assertIn("仅接受 IPv4", result["error"])

    def test_penetration_scan_modes_are_mutually_exclusive(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            penetration_test.main([
                "192.0.2.1", "--nmap-only", "--nikto-only", "--no-store"
            ])
        self.assertEqual(raised.exception.code, 2)


@final
class PersistenceAndReconTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    store: DataStore

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tool-parser-store-")
        self.store = DataStore(data_dir=Path(self.temporary.name))

    def tearDown(self):
        self.temporary.cleanup()

    def test_pentest_persist_empty_missing_and_mixed_runs(self):
        with mock.patch("source.data_platform.DataStore", return_value=self.store):
            _, empty_run, _ = penetration_test.persist_results(
                "192.0.2.1", "pentest-test", {}
            )
            self.assertEqual(empty_run["status"], "failed")

            all_missing = {
                "nmap": {
                    "tool": "nmap", "target": "192.0.2.1", "return_code": 127,
                    "error": "nmap 未安装", "open_ports": {"hosts": [], "ports": []},
                },
                "masscan": {
                    "tool": "masscan", "target": "192.0.2.1", "return_code": 127,
                    "error": "masscan 未安装", "ports": [],
                },
            }
            _, failed_run, _ = penetration_test.persist_results(
                "192.0.2.1", "pentest-test", all_missing
            )
            self.assertEqual(failed_run["status"], "failed")

            mixed = {
                "nmap": {
                    "tool": "nmap", "target": "192.0.2.1", "return_code": 0,
                    "open_ports": {"hosts": [], "ports": []},
                },
                "masscan": {
                    "tool": "masscan", "target": "192.0.2.1", "return_code": 127,
                    "error": "masscan 未安装", "ports": [],
                },
            }
            _, partial_run, _ = penetration_test.persist_results(
                "192.0.2.1", "pentest-test", mixed
            )
            self.assertEqual(partial_run["status"], "partial")
            persisted_run = self.store.get_run(partial_run["id"])
            if persisted_run is None:
                self.fail("持久化后的运行记录不存在")
            self.assertEqual(persisted_run["status"], "partial")

    def test_recon_persists_each_result_under_its_own_target(self):
        class FakeStore:
            def __init__(self):
                self.ingested = []
                self.finished = None

            def start_run(self, **kwargs):
                return {"id": "run-1", **kwargs}

            def ingest_tool_result(self, run_id, tool, target, result):
                self.ingested.append((tool, target))
                return {"accepted": 1, "rejected": [], "assets": 1}

            def finish_run(self, run_id, status, error=None):
                self.finished = (status, error)

            def analyze(self, run_id):
                return {}

        fake_store = FakeStore()
        results = {
            "nmap": {
                "tool": "nmap", "target": "192.0.2.1", "return_code": 0,
                "open_ports": {"hosts": [], "ports": []},
            },
            "theharvester": {
                "tool": "theharvester", "target": "example.com", "domain": "example.com",
                "return_code": 0, "structured_output": {},
            },
        }
        with mock.patch.object(recon, "DataStore", return_value=fake_store):
            analysis = recon.persist_results("192.0.2.1", "all", results)
        self.assertEqual(
            fake_store.ingested,
            [("nmap", "192.0.2.1"), ("theharvester", "example.com")],
        )
        if fake_store.finished is None:
            self.fail("recon 未结束运行记录")
        self.assertEqual(fake_store.finished[0], "complete")
        self.assertEqual(analysis["run_status"], "complete")

    def test_recon_rejects_invalid_combinations(self):
        invalid_argv = [
            ["192.0.2.1", "--type", "theharvester", "--no-store"],
            ["192.0.2.1", "--type", "nikto", "--domain", "example.com", "--no-store"],
        ]
        for argv in invalid_argv:
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                recon.main(argv)
            self.assertEqual(raised.exception.code, 2)

    def test_recon_default_all_reports_skipped_osint_explicitly(self):
        fake_recon = mock.Mock()
        fake_recon.nmap_scan.return_value = {
            "tool": "nmap", "target": "192.0.2.1", "return_code": 0,
            "open_ports": {"hosts": [], "ports": []},
        }
        fake_recon.masscan_scan.return_value = {
            "tool": "masscan", "target": "192.0.2.1", "return_code": 0, "ports": [],
        }
        fake_recon.nikto_scan.return_value = {
            "tool": "nikto", "target": "192.0.2.1:80", "return_code": 0,
            "vulnerabilities": [], "vuln_count": 0,
        }
        stdout = io.StringIO()
        with mock.patch.object(recon, "ReconModule", return_value=fake_recon), \
             redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = recon.main(["192.0.2.1", "--no-store", "--json"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(set(payload["results"]), {"nmap", "masscan", "nikto", "theharvester"})
        self.assertNotEqual(payload["results"]["theharvester"]["return_code"], 0)
        self.assertIn("--domain", payload["results"]["theharvester"]["error"])


class AuditEngineTests(unittest.TestCase):
    def test_probe_ports_keeps_services_aligned_with_sorted_ports(self):
        class FakeSocket:
            timeout: float

            def __init__(self) -> None:
                self.timeout = 0.0

            def settimeout(self, timeout: float) -> None:
                self.timeout = timeout

            def connect_ex(self, address):
                return 0

            def close(self):
                return None

        scanner = NetworkScanner()
        service_by_port = {22: "SSH", 443: "HTTPS"}
        with mock.patch.object(
            audit_engine.socket, "socket", side_effect=lambda *args, **kwargs: FakeSocket()
        ), mock.patch.object(
            scanner, "probe_service", side_effect=lambda ip, port: service_by_port[port]
        ):
            ports, services = scanner.probe_ports("192.0.2.1", [443, 22])
        self.assertEqual(sorted(ports), [22, 443])
        self.assertEqual(services, ["SSH", "HTTPS"])

    def test_explicit_ipv4_scans_even_when_missing_from_arp(self):
        scanner = NetworkScanner()
        with mock.patch.object(scanner, "get_local_ip", return_value="192.0.2.254"), \
             mock.patch.object(scanner, "get_mac_address", return_value="AA:BB:CC:DD:EE:FF"), \
             mock.patch.object(scanner, "scan_arp", return_value=[]), \
             mock.patch.object(scanner, "probe_ports", return_value=({22}, ["SSH"])):
            devices = scanner.scan_network("192.0.2.10")
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["ip"], "192.0.2.10")
        self.assertEqual(devices[0]["mac"], "N/A")
        self.assertEqual(devices[0]["ports"], [22])
        self.assertEqual(devices[0]["services"], ["SSH"])

    def test_audit_target_validation_is_strict_and_precedes_scanning(self):
        scanner = NetworkScanner()
        for target in ["example.com", "192.0.2.0/24", "https://192.0.2.1", "-192.0.2.1", "999.1.1.1"]:
            with self.subTest(target=target), mock.patch.object(scanner, "scan_arp") as scan_arp, self.assertRaises(ValueError):
                scanner.scan_network(target)
            scan_arp.assert_not_called()

        with mock.patch("source.data_platform.DataStore") as data_store, \
             redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            audit_engine.main(["--target", "example.com", "--quiet"])
        self.assertEqual(raised.exception.code, 2)
        data_store.assert_not_called()

    def test_windows_arp_parser_accepts_leading_spaces(self):
        scanner = NetworkScanner()
        completed = SimpleNamespace(
            returncode=0,
            stdout="  192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic\n",
            stderr="",
        )
        with mock.patch.object(audit_engine.sys, "platform", "win32"), \
             mock.patch.object(audit_engine.subprocess, "run", return_value=completed):
            devices = scanner.scan_arp()
        self.assertEqual(devices, [{"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"}])
        self.assertIsNone(scanner.arp_error)

    def test_arp_command_failure_is_recorded(self):
        scanner = NetworkScanner()
        completed = SimpleNamespace(returncode=1, stdout="", stderr="access denied")
        with mock.patch.object(audit_engine.subprocess, "run", return_value=completed):
            devices = scanner.scan_arp()
        self.assertEqual(devices, [])
        arp_error = scanner.arp_error
        if arp_error is None:
            self.fail("ARP 命令失败时未记录错误")
        self.assertIn("access denied", arp_error)

    def test_audit_run_with_arp_failure_cannot_be_complete(self):
        temporary = tempfile.TemporaryDirectory(prefix="audit-status-")
        self.addCleanup(temporary.cleanup)
        store = DataStore(data_dir=Path(temporary.name))
        fake_scanner = mock.Mock()
        fake_scanner.scan_errors = ["ARP 扫描失败: access denied"]
        fake_scanner.scan_network.return_value = [{
            "ip": "192.0.2.10",
            "mac": "N/A",
            "vendor": "未知厂商",
            "device_type": "未知设备",
            "confidence": 0.3,
            "ports": [],
            "services": [],
            "risk_score": 0,
        }]
        real_scanner_class = audit_engine.NetworkScanner
        with mock.patch("source.data_platform.DataStore", return_value=store), \
             mock.patch.object(real_scanner_class, "__new__", return_value=fake_scanner), \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            audit_engine.main(["--target", "192.0.2.10", "--quiet"])
        latest_run = store.latest_run()
        if latest_run is None:
            self.fail("审计运行记录不存在")
        self.assertEqual(latest_run["status"], "partial")

    def test_audit_no_findings_does_not_claim_safe(self):
        self.assertEqual(SecurityAudit().calc_risk_level([]), "未发现已知风险")


if __name__ == "__main__":
    unittest.main()
