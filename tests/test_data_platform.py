# pyright: reportUninitializedInstanceVariable=false
from __future__ import annotations

import argparse
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import final
from unittest import mock

from source import netrunner
from source.data_platform import DataStore, normalize_address


@final
class DataPlatformTests(unittest.TestCase):
    temporary: tempfile.TemporaryDirectory[str]
    data_dir: Path
    store: DataStore

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="netrunner-test-")
        self.data_dir = Path(self.temporary.name)
        self.store = DataStore(data_dir=self.data_dir)

    def tearDown(self):
        self.temporary.cleanup()

    def start_run(self, collectors=None):
        return self.store.start_run(
            command="test",
            mode="home",
            target=None,
            collectors=collectors or ["audit"],
        )

    def ingest_device(self, run_id, mac, ip, ports=None, source="audit.network"):
        return self.store.ingest_event({
            "run_id": run_id,
            "source": source,
            "kind": "device_observation",
            "identity": {"type": "mac", "value": mac},
            "attributes": {
                "mac": mac,
                "ip": ip,
                "ports": ports or [],
            },
        })

    def test_sqlite_schema_initializes(self):
        self.assertTrue(self.store.db_path.is_file())
        with sqlite3.connect(self.store.db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
        for table in {
            "scan_runs", "collector_results", "assets", "asset_aliases", "observations", "services",
            "raw_artifacts", "findings", "threat_scores", "baselines",
        }:
            self.assertIn(table, tables)

    def test_mac_normalization_supports_macos_short_octets(self):
        self.assertEqual(normalize_address("0:1a:eb:a6:4a:60"), "00:1A:EB:A6:4A:60")
        self.assertEqual(normalize_address("AA-BB-CC-DD-EE-FF"), "AA:BB:CC:DD:EE:FF")

    def test_history_detects_new_missing_assets_and_opened_ports(self):
        baseline = self.start_run()
        first_asset = self.ingest_device(
            baseline["id"], "0:1a:eb:a6:4a:60", "192.168.50.10", [80]
        )
        self.ingest_device(
            baseline["id"], "AA:BB:CC:DD:EE:02", "192.168.50.20", []
        )
        self.store.finish_run(baseline["id"], "complete")

        current = self.start_run()
        current_first_asset = self.ingest_device(
            current["id"], "00:1A:EB:A6:4A:60", "192.168.50.10", [80, 554]
        )
        new_asset = self.ingest_device(
            current["id"], "AA:BB:CC:DD:EE:03", "192.168.50.30", []
        )
        self.store.finish_run(current["id"], "complete")

        changes = self.store.compare_runs(current["id"])
        self.assertEqual(first_asset, current_first_asset)
        self.assertEqual([item["id"] for item in changes["new_assets"]], [new_asset])
        self.assertEqual(
            [item["identity_value"] for item in changes["missing_assets"]],
            ["AA:BB:CC:DD:EE:02"],
        )
        self.assertIn(
            ("00:1A:EB:A6:4A:60", 554),
            {(item["identity_value"], item["port"]) for item in changes["opened_ports"]},
        )

    def test_mac_ip_alias_links_nmap_to_same_asset(self):
        run = self.start_run(["audit", "nmap"])
        asset_id = self.ingest_device(
            run["id"], "AA:BB:CC:DD:EE:10", "192.168.50.40", []
        )
        ingestion = self.store.ingest_tool_result(run["id"], "nmap", "192.168.50.40", {
            "tool": "nmap",
            "target": "192.168.50.40",
            "return_code": 0,
            "open_ports": {
                "ports": [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
                "os": None,
                "hostnames": [],
            },
        })
        self.assertEqual(ingestion["assets"], 1)
        with self.store.connect() as conn:
            observed_assets = {
                row["asset_id"]
                for row in conn.execute(
                    "SELECT asset_id FROM observations WHERE run_id = ?", (run["id"],)
                )
            }
        self.assertEqual(observed_assets, {asset_id})

    def test_risk_score_uses_independent_channels_and_structured_findings(self):
        run = self.start_run(["audit", "nmap", "nikto"])
        self.ingest_device(run["id"], "AA:BB:CC:DD:EE:11", "192.168.50.41", [554])
        self.store.ingest_tool_result(run["id"], "nmap", "192.168.50.41", {
            "tool": "nmap",
            "return_code": 0,
            "open_ports": {"ports": [{"port": 554, "protocol": "tcp", "state": "open", "service": "rtsp"}]},
        })
        self.store.ingest_tool_result(run["id"], "nikto", "192.168.50.41", {
            "tool": "nikto",
            "target": "192.168.50.41:80",
            "return_code": 0,
            "vulnerabilities": [{"severity": "high", "msg": "test structured finding"}],
            "vuln_count": 1,
        })
        self.store.finish_run(run["id"], "complete")

        analysis = self.store.analyze(run["id"])
        asset = analysis["assets"][0]
        self.assertGreaterEqual(asset["score"], 8.0)
        self.assertGreaterEqual(asset["confidence"], 0.7)
        self.assertEqual(
            set(asset["source_channels"]),
            {"local_network", "active_network_scanner", "web_vulnerability_scanner"},
        )
        self.assertIn("scanner_vulnerability", {factor["rule_id"] for factor in asset["factors"]})

    def test_data_quality_warns_when_collectors_have_no_observations(self):
        run = self.start_run(["audit", "spy.wifi", "spy.bluetooth"])
        self.ingest_device(run["id"], "AA:BB:CC:DD:EE:12", "192.168.50.42", [])
        self.store.finish_run(run["id"], "complete")
        quality = self.store.analyze(run["id"])["data_quality"]
        self.assertEqual(quality["coverage_ratio"], 0.33)
        self.assertEqual(
            quality["collectors_without_observations"],
            ["spy.bluetooth", "spy.wifi"],
        )
        self.assertTrue(any("0 分不等同" in warning for warning in quality["warnings"]))

    def test_external_analyzer_success(self):
        run = self.start_run()
        self.ingest_device(run["id"], "AA:BB:CC:DD:EE:13", "192.168.50.43", [])
        self.store.finish_run(run["id"], "complete")

        script = self.data_dir / "external_analyzer.py"
        script.write_text(
            "import json, sys\n"
            "payload = json.load(sys.stdin)\n"
            "assert payload['contract_version'] == 1\n"
            "json.dump({'overall_score': 9.1, 'overall_level': 'critical', 'assets': []}, sys.stdout)\n",
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {
            "NETRUNNER_ANALYZER_CMD": f"{sys.executable} {script}",
            "NETRUNNER_ANALYZER_TIMEOUT": "10",
        }, clear=False):
            analysis = self.store.analyze(run["id"])

        self.assertEqual(analysis["overall_score"], 9.1)
        self.assertEqual(analysis["overall_level"], "critical")
        self.assertEqual(analysis["asset_count"], 1)
        self.assertEqual(len(analysis["assets"]), 1)
        self.assertEqual(analysis["analysis_backend"]["type"], "external_process")
        self.assertFalse(analysis["analysis_backend"]["fallback"])

    def test_external_analyzer_failure_falls_back(self):
        run = self.start_run()
        self.ingest_device(run["id"], "AA:BB:CC:DD:EE:14", "192.168.50.44", [23])
        self.store.finish_run(run["id"], "complete")

        script = self.data_dir / "broken_analyzer.py"
        script.write_text("import sys\nsys.stderr.write('broken')\nraise SystemExit(3)\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {
            "NETRUNNER_ANALYZER_CMD": f"{sys.executable} {script}",
        }, clear=False):
            analysis = self.store.analyze(run["id"])

        self.assertGreater(analysis["overall_score"], 0)
        self.assertTrue(analysis["analysis_backend"]["fallback"])
        self.assertIn("已回退", analysis["backend_warning"])

    def test_failed_tool_results_are_stored_but_rejected_without_observations(self):
        run = self.start_run(["nmap", "nikto"])
        results = [
            ("nmap", {
                "return_code": 2,
                "open_ports": {"ports": [{"port": 22}]},
                "stderr": "failed",
            }),
            ("nmap", {
                "return_code": 0,
                "timed_out": True,
                "open_ports": {"ports": [{"port": 80}]},
            }),
            ("nmap", {"return_code": 0, "open_ports": "not parsed"}),
            ("masscan", {"return_code": 0, "output": "", "stderr": "", "ports": []}),
            ("nikto", {"return_code": 0, "output": "", "stderr": "", "vulnerabilities": []}),
            ("nikto", {"return_code": 0, "vulnerabilities": {"bad": "shape"}}),
            ("nikto", {"return_code": 0, "vulnerabilities": [{"severity": ["high"]}]}),
            ("nikto", ["bad top-level shape"]),
        ]
        for tool, result in results:
            ingestion = self.store.ingest_tool_result(run["id"], tool, "192.0.2.10", result)
            self.assertEqual(ingestion["accepted"], 0)
            self.assertTrue(ingestion["rejected"])
            self.assertIn("rejected", ingestion["rejected"][0])

        with self.store.connect() as conn:
            observation_count = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE run_id = ?", (run["id"],)
            ).fetchone()[0]
            artifacts = conn.execute(
                "SELECT path FROM raw_artifacts WHERE run_id = ?", (run["id"],)
            ).fetchall()
        self.assertEqual(observation_count, 0)
        self.assertEqual(len(artifacts), len(results))
        self.assertTrue(all(Path(row["path"]).is_file() for row in artifacts))

    def test_nmap_hosts_and_masscan_ips_are_ingested_as_independent_assets(self):
        run = self.start_run(["nmap", "masscan"])
        nmap_ingestion = self.store.ingest_tool_result(run["id"], "nmap", "192.0.2.0/24", {
            "return_code": 0,
            "hosts": [
                {
                    "addresses": [{"address": "192.0.2.11", "type": "ipv4"}],
                    "hostnames": [{"name": "one.example"}],
                    "ports": [{"port": 22, "protocol": "tcp", "service": "ssh"}],
                },
                {
                    "ip": "192.0.2.12",
                    "ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
                },
            ],
        })
        masscan_ingestion = self.store.ingest_tool_result(run["id"], "masscan", "198.51.100.0/24", {
            "return_code": 0,
            "ports": [
                {"ip": "198.51.100.21", "port": 80, "proto": "tcp", "service": "unknown"},
                {"ip": "198.51.100.21", "port": 443, "proto": "tcp", "service": "unknown"},
                {"ip": "198.51.100.22", "port": 22, "proto": "tcp", "service": "unknown"},
            ],
        })
        self.assertEqual(nmap_ingestion, {"accepted": 2, "rejected": [], "assets": 2})
        self.assertEqual(masscan_ingestion, {"accepted": 2, "rejected": [], "assets": 2})

        with self.store.connect() as conn:
            identities = {
                (row["identity_type"], row["identity_value"])
                for row in conn.execute(
                    """SELECT DISTINCT a.identity_type, a.identity_value
                       FROM assets a JOIN observations o ON o.asset_id = a.id
                       WHERE o.run_id = ?""",
                    (run["id"],),
                )
            }
            service_counts = {
                row["identity_value"]: row["count"]
                for row in conn.execute(
                    """SELECT a.identity_value, COUNT(s.id) AS count
                       FROM assets a JOIN services s ON s.asset_id = a.id
                       WHERE s.run_id = ? GROUP BY a.id""",
                    (run["id"],),
                )
            }
        self.assertEqual(identities, {
            ("ip", "192.0.2.11"), ("ip", "192.0.2.12"),
            ("ip", "198.51.100.21"), ("ip", "198.51.100.22"),
        })
        self.assertNotIn(("domain", "198.51.100.0/24"), identities)
        self.assertEqual(service_counts["198.51.100.21"], 2)

    def test_masscan_cidr_record_without_ip_is_rejected(self):
        run = self.start_run(["masscan"])
        ingestion = self.store.ingest_tool_result(run["id"], "masscan", "203.0.113.0/24", {
            "return_code": 0,
            "ports": [{"port": 80, "proto": "tcp"}],
        })
        self.assertEqual(ingestion["accepted"], 0)
        self.assertIn("CIDR", ingestion["rejected"][0])
        with self.store.connect() as conn:
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM observations WHERE run_id = ?", (run["id"],)
            ).fetchone()[0], 0)

    def test_trusted_mac_ip_observation_merges_existing_ip_asset_transactionally(self):
        run = self.start_run(["audit", "nmap"])
        ip_asset = self.store.ingest_event({
            "run_id": run["id"],
            "source": "tool.nmap",
            "kind": "host_observation",
            "identity": {"type": "ip", "value": "192.0.2.50"},
            "attributes": {
                "ip": "192.0.2.50",
                "ports": [{
                    "port": 22, "protocol": "tcp", "state": "open", "service": "ssh",
                    "product": "OpenSSH", "version": "9.7", "script": {"key": "value"},
                }],
            },
        })
        self.store.add_alias(ip_asset, "hostname", "old-host.local")
        mac_asset = self.store.ingest_event({
            "run_id": run["id"],
            "source": "audit.network",
            "kind": "device_observation",
            "identity": {"type": "mac", "value": "AA:BB:CC:DD:EE:50"},
            "attributes": {
                "mac": "AA:BB:CC:DD:EE:50",
                "ports": [{"port": 22, "service": "unknown", "version": ""}],
            },
        })
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO findings
                   (run_id, asset_id, rule_id, severity, score, confidence, title, description, evidence_json)
                   VALUES (?, ?, 'ip-finding', 'high', 5.0, 0.8, 'ip', 'ip', '{}')""",
                (run["id"], ip_asset),
            )
            conn.execute(
                """INSERT INTO findings
                   (run_id, asset_id, rule_id, severity, score, confidence, title, description, evidence_json)
                   VALUES (?, ?, 'mac-finding', 'low', 1.0, 0.5, 'mac', 'mac', '{}')""",
                (run["id"], mac_asset),
            )
            conn.execute(
                """INSERT INTO threat_scores
                   (run_id, asset_id, score, level, confidence, factors_json)
                   VALUES (?, ?, 7.0, 'high', 0.8, '[{"rule_id":"ip"}]')""",
                (run["id"], ip_asset),
            )
            conn.execute(
                """INSERT INTO threat_scores
                   (run_id, asset_id, score, level, confidence, factors_json)
                   VALUES (?, ?, 2.0, 'low', 0.5, '[{"rule_id":"mac"}]')""",
                (run["id"], mac_asset),
            )

        merged_asset = self.ingest_device(
            run["id"], "AA:BB:CC:DD:EE:50", "192.0.2.50", [22]
        )
        self.assertEqual(merged_asset, mac_asset)
        with self.store.connect() as conn:
            assets = conn.execute("SELECT id, identity_type, identity_value FROM assets").fetchall()
            observation_assets = {
                row[0] for row in conn.execute("SELECT DISTINCT asset_id FROM observations")
            }
            service = conn.execute(
                "SELECT * FROM services WHERE run_id = ? AND asset_id = ? AND port = 22",
                (run["id"], mac_asset),
            ).fetchone()
            finding_assets = {
                row[0] for row in conn.execute("SELECT DISTINCT asset_id FROM findings")
            }
            score = conn.execute(
                "SELECT * FROM threat_scores WHERE run_id = ? AND asset_id = ?",
                (run["id"], mac_asset),
            ).fetchone()
            aliases = {
                (row["identity_type"], row["identity_value"], row["asset_id"])
                for row in conn.execute("SELECT * FROM asset_aliases")
            }
        self.assertEqual([(row["id"], row["identity_type"], row["identity_value"]) for row in assets], [
            (mac_asset, "mac", "AA:BB:CC:DD:EE:50")
        ])
        self.assertEqual(observation_assets, {mac_asset})
        self.assertEqual(finding_assets, {mac_asset})
        self.assertEqual(service["service"], "ssh")
        self.assertEqual(service["product"], "OpenSSH")
        self.assertEqual(service["version"], "9.7")
        self.assertEqual(score["score"], 7.0)
        self.assertEqual(len(json.loads(score["factors_json"])), 2)
        self.assertIn(("ip", "192.0.2.50", mac_asset), aliases)
        self.assertIn(("hostname", "old-host.local", mac_asset), aliases)

    def test_masscan_unknown_service_does_not_overwrite_nmap_metadata(self):
        run = self.start_run(["nmap", "masscan"])
        self.store.ingest_tool_result(run["id"], "nmap", "192.0.2.60", {
            "return_code": 0,
            "open_ports": {"ports": [{
                "port": 443, "protocol": "tcp", "state": "open", "service": "https",
                "product": "nginx", "version": "1.25", "banner": "TLS", "scripts": {"a": 1},
            }]},
        })
        self.store.ingest_tool_result(run["id"], "masscan", "192.0.2.60", {
            "return_code": 0,
            "ports": [{
                "ip": "192.0.2.60", "port": 443, "proto": "tcp", "status": "open",
                "service": "unknown", "product": "", "version": None,
            }],
        })
        with self.store.connect() as conn:
            service = conn.execute(
                "SELECT * FROM services WHERE run_id = ? AND port = 443", (run["id"],)
            ).fetchone()
        attributes = json.loads(service["attributes_json"])
        self.assertEqual(service["service"], "https")
        self.assertEqual(service["product"], "nginx")
        self.assertEqual(service["version"], "1.25")
        self.assertEqual(service["banner"], "TLS")
        self.assertEqual(attributes["scripts"], {"a": 1})
        self.assertEqual(attributes["sources"], ["tool.masscan", "tool.nmap"])

    def test_history_and_persistence_ignore_future_wrong_scope_and_unusable_runs(self):
        failed = self.start_run()
        self.ingest_device(failed["id"], "AA:BB:CC:DD:EE:61", "192.0.2.61", [23])
        self.store.finish_run(failed["id"], "failed")

        running = self.start_run()
        self.ingest_device(running["id"], "AA:BB:CC:DD:EE:61", "192.0.2.61", [23])

        wrong_scope = self.start_run(["different"])
        self.ingest_device(wrong_scope["id"], "AA:BB:CC:DD:EE:61", "192.0.2.61", [23])
        self.store.finish_run(wrong_scope["id"], "complete")

        partial = self.start_run()
        self.ingest_device(partial["id"], "AA:BB:CC:DD:EE:62", "192.0.2.62", [23])
        self.store.finish_run(partial["id"], "partial")

        current = self.start_run()
        self.ingest_device(current["id"], "AA:BB:CC:DD:EE:61", "192.0.2.61", [23])
        self.ingest_device(current["id"], "AA:BB:CC:DD:EE:62", "192.0.2.62", [23])
        self.store.finish_run(current["id"], "complete")

        future = self.start_run()
        self.ingest_device(future["id"], "AA:BB:CC:DD:EE:61", "192.0.2.61", [23])
        self.ingest_device(future["id"], "AA:BB:CC:DD:EE:62", "192.0.2.62", [23])
        self.store.finish_run(future["id"], "complete")

        assets = {
            asset["identity_value"]: asset
            for asset in self.store.analyze_run(current["id"])["assets"]
        }
        first_rules = {factor["rule_id"] for factor in assets["AA:BB:CC:DD:EE:61"]["factors"]}
        second_rules = {factor["rule_id"] for factor in assets["AA:BB:CC:DD:EE:62"]["factors"]}
        self.assertEqual(assets["AA:BB:CC:DD:EE:61"]["history_runs"], 0)
        self.assertNotIn("persistent_risk_exposure", first_rules)
        self.assertEqual(assets["AA:BB:CC:DD:EE:62"]["history_runs"], 1)
        self.assertIn("persistent_risk_exposure", second_rules)

    def test_baseline_validation_and_default_report_exclude_running(self):
        valid = self.start_run()
        self.store.finish_run(valid["id"], "complete")
        failed = self.start_run()
        self.store.finish_run(failed["id"], "failed")
        running_baseline = self.start_run()
        other_scope = self.start_run(["other"])
        self.store.finish_run(other_scope["id"], "complete")
        current = self.start_run()
        self.store.finish_run(current["id"], "complete")
        later = self.start_run()
        self.store.finish_run(later["id"], "complete")
        newest_running = self.start_run()

        with self.assertRaisesRegex(ValueError, "complete/partial"):
            self.store.set_baseline(failed["id"])
        with self.assertRaisesRegex(ValueError, "complete/partial"):
            self.store.set_baseline(running_baseline["id"])
        self.store.set_baseline(valid["id"])
        self.assertEqual(self.store.compare_runs(current["id"])["baseline_id"], valid["id"])
        with self.assertRaisesRegex(ValueError, "未知基线"):
            self.store.compare_runs(current["id"], "missing")
        with self.assertRaisesRegex(ValueError, "相同"):
            self.store.compare_runs(current["id"], current["id"])
        with self.assertRaisesRegex(ValueError, "scope"):
            self.store.compare_runs(current["id"], other_scope["id"])
        with self.assertRaisesRegex(ValueError, "状态"):
            self.store.compare_runs(current["id"], failed["id"])
        with self.assertRaisesRegex(ValueError, "状态"):
            self.store.compare_runs(current["id"], running_baseline["id"])
        with self.assertRaisesRegex(ValueError, "早于"):
            self.store.compare_runs(current["id"], later["id"])

        latest = self.store.latest_run()
        latest_with_running = self.store.latest_run(include_running=True)
        self.assertIsNotNone(latest)
        self.assertIsNotNone(latest_with_running)
        self.assertEqual(latest["id"] if latest else None, later["id"])
        self.assertEqual(
            latest_with_running["id"] if latest_with_running else None,
            newest_running["id"],
        )
        self.assertEqual(self.store.report()["run"]["id"], later["id"])

    def test_nikto_finding_keeps_original_severity(self):
        run = self.start_run(["nikto"])
        ingestion = self.store.ingest_tool_result(run["id"], "nikto", "192.0.2.70", {
            "return_code": 0,
            "target": "192.0.2.70:80",
            "vulnerabilities": [
                {"severity": "high", "msg": "high finding"},
                {"severity": "medium", "msg": "medium finding"},
            ],
            "vuln_count": 2,
        })
        self.assertEqual(ingestion["accepted"], 2)
        self.store.finish_run(run["id"], "complete")
        self.store.analyze_run(run["id"])
        with self.store.connect() as conn:
            severities = [
                row[0] for row in conn.execute(
                    """SELECT severity FROM findings
                       WHERE run_id = ? AND rule_id = 'scanner_vulnerability'
                       ORDER BY id""",
                    (run["id"],),
                )
            ]
        self.assertEqual(severities, ["high", "medium"])

    def test_store_raw_uses_unique_paths_for_repeated_names(self):
        run = self.start_run()
        first = self.store.store_raw(run["id"], "test", "same.json", {"value": 1})
        second = self.store.store_raw(run["id"], "test", "same.json", {"value": 2})
        self.assertNotEqual(first, second)
        self.assertEqual(json.loads(Path(first).read_text(encoding="utf-8")), {"value": 1})
        self.assertEqual(json.loads(Path(second).read_text(encoding="utf-8")), {"value": 2})
        self.assertFalse(any(path.name.endswith(".tmp") for path in Path(run["raw_directory"]).iterdir()))
        with self.store.connect() as conn:
            paths = [
                row[0] for row in conn.execute(
                    "SELECT path FROM raw_artifacts WHERE run_id = ?", (run["id"],)
                )
            ]
        self.assertEqual(len(paths), len(set(paths)))

    def test_external_asset_patch_is_safe_recomputed_and_persisted(self):
        run = self.start_run()
        asset_id = self.ingest_device(
            run["id"], "AA:BB:CC:DD:EE:80", "192.0.2.80", []
        )
        self.store.finish_run(run["id"], "complete")
        script = self.data_dir / "asset_patch_analyzer.py"
        script.write_text(
            "import json, sys\n"
            "payload = json.load(sys.stdin)\n"
            "asset_id = payload['built_in_analysis']['assets'][0]['asset_id']\n"
            "json.dump({'overall_score': 7.2, 'overall_level': 'high', "
            "'assets': [{'asset_id': asset_id, 'score': 7.2}]}, sys.stdout)\n",
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {
            "NETRUNNER_ANALYZER_CMD": f"{sys.executable} {script}",
        }, clear=False):
            analysis = self.store.analyze(run["id"])

        asset = analysis["assets"][0]
        self.assertEqual(asset["asset_id"], asset_id)
        self.assertEqual(asset["score"], 7.2)
        self.assertEqual(asset["level"], "high")
        for field in (
            "identity_type", "identity_value", "confidence", "history_runs", "factors",
            "sources", "source_channels",
        ):
            self.assertIn(field, asset)
        self.assertEqual(analysis["asset_count"], 1)
        self.assertEqual(analysis["high_or_critical_assets"], 1)
        with self.store.connect() as conn:
            persisted = conn.execute(
                "SELECT score, level FROM threat_scores WHERE run_id = ? AND asset_id = ?",
                (run["id"], asset_id),
            ).fetchone()
        self.assertEqual((persisted["score"], persisted["level"]), (7.2, "high"))

    def test_invalid_external_levels_and_asset_ids_fall_back(self):
        run = self.start_run()
        self.ingest_device(run["id"], "AA:BB:CC:DD:EE:81", "192.0.2.81", [23])
        self.store.finish_run(run["id"], "complete")
        cases = [
            (
                "invalid_level_analyzer.py",
                "{'overall_score': 9.0, 'overall_level': 'low', "
                "'assets': [{'asset_id': 999999, 'score': 9.0}]}",
                "阈值不一致",
            ),
            (
                "invalid_level_name_analyzer.py",
                "{'overall_score': 9.0, 'overall_level': 'severe', 'assets': []}",
                "仅允许",
            ),
            (
                "unknown_asset_analyzer.py",
                "{'overall_score': 9.0, 'overall_level': 'critical', "
                "'assets': [{'asset_id': 999999, 'score': 9.0}]}",
                "不属于当前批次",
            ),
            (
                "bad_asset_field_analyzer.py",
                "{'overall_score': 9.0, 'overall_level': 'critical', "
                "'assets': [{'asset_id': 1, 'score': 'nine'}]}",
                "必须是 0 到 10 的数字",
            ),
        ]
        for filename, payload, expected_warning in cases:
            script = self.data_dir / filename
            script.write_text(
                "import json, sys\n"
                "json.load(sys.stdin)\n"
                f"json.dump({payload}, sys.stdout)\n",
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {
                "NETRUNNER_ANALYZER_CMD": f"{sys.executable} {script}",
            }, clear=False):
                analysis = self.store.analyze(run["id"])
            self.assertTrue(analysis["analysis_backend"]["fallback"])
            self.assertIn(expected_warning, analysis["backend_warning"])
            self.assertEqual(analysis["overall_level"], "low")

    def test_no_store_uses_isolated_temporary_database(self):
        created_data_dirs = []
        real_store = DataStore

        class TrackingStore(real_store):
            def __init__(self, db_path=None, data_dir=None):
                created_data_dirs.append(Path(data_dir) if data_dir else None)
                super().__init__(db_path=db_path, data_dir=data_dir)

        def fake_collect(store, profile, target):
            run = store.start_run("test-no-store", profile, target, ["test"])
            store.finish_run(run["id"], "complete")
            return {
                "run": {**run, "status": "complete", "errors": []},
                "analysis": {
                    "overall_score": 0.0,
                    "overall_level": "none",
                    "asset_count": 0,
                    "high_or_critical_assets": 0,
                    "new_asset_count": 0,
                    "missing_asset_count": 0,
                    "new_port_count": 0,
                    "assets": [],
                },
            }

        args = argparse.Namespace(profile="home", target=None, no_store=True, json=True)
        with mock.patch.object(netrunner, "DataStore", TrackingStore), \
             mock.patch.object(netrunner, "collect_profile", fake_collect), \
             redirect_stdout(io.StringIO()):
            result = netrunner.command_collect(args)

        self.assertEqual(result, 0)
        self.assertEqual(len(created_data_dirs), 1)
        self.assertIsNotNone(created_data_dirs[0])
        self.assertNotEqual(created_data_dirs[0], self.store.data_dir)
        self.assertFalse(created_data_dirs[0].exists())


if __name__ == "__main__":
    unittest.main()
