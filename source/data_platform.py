#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETRUNNER 本地数据平台。

负责统一保存扫描批次、设备资产、观测、服务、原始证据和威胁分析结果。
所有持久化均使用 Python 标准库与 SQLite，不依赖外部数据库服务。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = Path(os.environ.get("NETRUNNER_DATA_DIR", PROJECT_ROOT / "data"))

PORT_RISK_RULES: Dict[int, Dict[str, Any]] = {
    21: {"rule": "ftp_exposed", "weight": 1.4, "title": "FTP 明文服务暴露", "description": "FTP 通常以明文传输凭据和数据。"},
    22: {"rule": "ssh_exposed", "weight": 0.8, "title": "SSH 远程管理服务", "description": "SSH 暴露本身不是漏洞，但应确认仅允许可信来源和强认证。"},
    23: {"rule": "telnet_exposed", "weight": 3.0, "title": "Telnet 明文远程登录", "description": "Telnet 缺少传输加密，凭据可能被窃取。"},
    80: {"rule": "http_unencrypted", "weight": 0.5, "title": "未加密 HTTP 服务", "description": "管理页面若使用 HTTP，通信内容可能被监听或篡改。"},
    445: {"rule": "smb_exposed", "weight": 2.1, "title": "SMB 文件服务暴露", "description": "应确认 SMB 补丁、访问控制与网络隔离状态。"},
    554: {"rule": "rtsp_exposed", "weight": 2.8, "title": "RTSP 视频流服务", "description": "RTSP 常见于网络摄像头，应确认认证、固件和访问范围。"},
    1433: {"rule": "mssql_exposed", "weight": 2.0, "title": "Microsoft SQL Server 暴露", "description": "数据库端口不应对非必要网络开放。"},
    3306: {"rule": "mysql_exposed", "weight": 2.0, "title": "MySQL 服务暴露", "description": "数据库端口不应对非必要网络开放。"},
    3389: {"rule": "rdp_exposed", "weight": 2.7, "title": "RDP 远程桌面暴露", "description": "RDP 是常见攻击入口，应限制来源并启用强认证。"},
    5432: {"rule": "postgres_exposed", "weight": 2.0, "title": "PostgreSQL 服务暴露", "description": "数据库端口不应对非必要网络开放。"},
    5900: {"rule": "vnc_exposed", "weight": 2.2, "title": "VNC 远程桌面暴露", "description": "VNC 应限制来源并检查加密与认证配置。"},
    6379: {"rule": "redis_exposed", "weight": 3.4, "title": "Redis 服务暴露", "description": "Redis 暴露可能导致未授权访问或数据泄露。"},
    27017: {"rule": "mongodb_exposed", "weight": 3.4, "title": "MongoDB 服务暴露", "description": "MongoDB 暴露可能导致未授权访问或数据泄露。"},
}

VULNERABILITY_WEIGHTS = {
    "critical": 8.5,
    "high": 5.8,
    "medium": 2.6,
    "low": 0.8,
    "info": 0.2,
    "unknown": 1.2,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def parse_json(value: Optional[str], fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def normalize_address(value: str) -> str:
    raw_value = (value or "").strip()
    parts = re.split(r"[:-]", raw_value)
    if len(parts) == 6 and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", part) for part in parts):
        return ":".join(part.zfill(2).upper() for part in parts)

    clean = re.sub(r"[^0-9A-Fa-f]", "", raw_value)
    if len(clean) == 12:
        return ":".join(clean[i:i + 2] for i in range(0, 12, 2)).upper()
    return raw_value.lower()


def normalize_identity(identity_type: str, value: str) -> Tuple[str, str]:
    identity_type = (identity_type or "unknown").strip().lower()
    value = (value or "").strip()
    if identity_type in {"mac", "bssid", "bluetooth"}:
        value = normalize_address(value)
    elif identity_type in {"domain", "hostname", "ssid"}:
        value = value.rstrip(".").lower()
    elif identity_type == "ip":
        value = value.lower()
    return identity_type, value


def severity_for_score(score: float) -> str:
    if score >= 8.5:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 3.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


class DataStore:
    """SQLite 数据仓库和本地原始证据目录。"""

    def __init__(self, db_path: Optional[Path] = None, data_dir: Optional[Path] = None):
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR).expanduser().resolve()
        self.db_path = Path(db_path or self.data_dir / "monitor.db").expanduser().resolve()
        self.raw_root = self.data_dir / "raw"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def _initialize(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            command TEXT NOT NULL,
            mode TEXT NOT NULL,
            target TEXT,
            scope_key TEXT NOT NULL,
            collectors_json TEXT NOT NULL,
            status TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            schema_version INTEGER NOT NULL,
            raw_directory TEXT NOT NULL,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_runs_scope_time
            ON scan_runs(scope_key, started_at DESC);

        CREATE TABLE IF NOT EXISTS collector_results (
            run_id TEXT NOT NULL,
            collector TEXT NOT NULL,
            status TEXT NOT NULL,
            object_count INTEGER NOT NULL DEFAULT 0,
            zero_objects INTEGER NOT NULL DEFAULT 0,
            error TEXT,
            details_json TEXT NOT NULL DEFAULT '{}',
            completed_at TEXT NOT NULL,
            PRIMARY KEY(run_id, collector),
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_collector_results_run_status
            ON collector_results(run_id, status);

        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identity_type TEXT NOT NULL,
            identity_value TEXT NOT NULL,
            label TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            last_run_id TEXT NOT NULL,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE(identity_type, identity_value),
            FOREIGN KEY(last_run_id) REFERENCES scan_runs(id)
        );

        CREATE TABLE IF NOT EXISTS asset_aliases (
            identity_type TEXT NOT NULL,
            identity_value TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(identity_type, identity_value),
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            source TEXT NOT NULL,
            kind TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            ip TEXT,
            mac TEXT,
            hostname TEXT,
            confidence REAL,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_observations_run_asset
            ON observations(run_id, asset_id);
        CREATE INDEX IF NOT EXISTS idx_observations_asset_time
            ON observations(asset_id, observed_at DESC);

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            protocol TEXT NOT NULL DEFAULT 'tcp',
            port INTEGER NOT NULL,
            state TEXT NOT NULL DEFAULT 'open',
            service TEXT,
            product TEXT,
            version TEXT,
            banner TEXT,
            attributes_json TEXT NOT NULL DEFAULT '{}',
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE,
            UNIQUE(run_id, asset_id, protocol, port)
        );
        CREATE INDEX IF NOT EXISTS idx_services_run_asset
            ON services(run_id, asset_id);

        CREATE TABLE IF NOT EXISTS raw_artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            collector TEXT NOT NULL,
            path TEXT NOT NULL,
            media_type TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            score REAL NOT NULL,
            confidence REAL NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_findings_run_asset
            ON findings(run_id, asset_id);

        CREATE TABLE IF NOT EXISTS threat_scores (
            run_id TEXT NOT NULL,
            asset_id INTEGER NOT NULL,
            score REAL NOT NULL,
            level TEXT NOT NULL,
            confidence REAL NOT NULL,
            factors_json TEXT NOT NULL,
            PRIMARY KEY(run_id, asset_id),
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE,
            FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS baselines (
            scope_key TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            set_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS platform_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
        with self.connect() as conn:
            conn.executescript(schema)
            migration = conn.execute(
                "SELECT value FROM platform_metadata WHERE key = 'identity_cleanup_v1'"
            ).fetchone()
            if not migration:
                self._repair_legacy_identities(conn)
                conn.execute(
                    """INSERT INTO platform_metadata(key, value, updated_at)
                       VALUES ('identity_cleanup_v1', 'complete', ?)""",
                    (utc_now(),),
                )

    @staticmethod
    def _is_multicast_ip(value: str) -> bool:
        try:
            return ip_address(value).is_multicast
        except ValueError:
            return False

    def _repair_legacy_identities(self, conn: sqlite3.Connection) -> None:
        """修正旧版 macOS ARP 短 MAC，并从规范化层移除组播伪资产。

        原始证据文件始终保留不变；这里只修复可查询、可比较的 SQLite 层。
        """
        address_types = {"mac", "bssid", "bluetooth"}
        assets = conn.execute(
            "SELECT id, identity_type, identity_value FROM assets"
        ).fetchall()
        for row in assets:
            identity_type = str(row["identity_type"])
            if identity_type not in address_types:
                continue
            old_value = str(row["identity_value"])
            new_value = normalize_address(old_value)
            if new_value == old_value:
                continue
            conflict = conn.execute(
                "SELECT id FROM assets WHERE identity_type = ? AND identity_value = ?",
                (identity_type, new_value),
            ).fetchone()
            if not conflict:
                conn.execute(
                    "UPDATE assets SET identity_value = ? WHERE id = ?",
                    (new_value, row["id"]),
                )

        aliases = conn.execute(
            "SELECT identity_type, identity_value, asset_id, created_at FROM asset_aliases"
        ).fetchall()
        for row in aliases:
            identity_type = str(row["identity_type"])
            old_value = str(row["identity_value"])
            if identity_type == "ip" and self._is_multicast_ip(old_value):
                conn.execute(
                    "DELETE FROM asset_aliases WHERE identity_type = ? AND identity_value = ?",
                    (identity_type, old_value),
                )
                continue
            if identity_type not in address_types:
                continue
            new_value = normalize_address(old_value)
            if new_value == old_value:
                continue
            conn.execute(
                """INSERT OR IGNORE INTO asset_aliases
                   (identity_type, identity_value, asset_id, created_at)
                   VALUES (?, ?, ?, ?)""",
                (identity_type, new_value, row["asset_id"], row["created_at"]),
            )
            conn.execute(
                "DELETE FROM asset_aliases WHERE identity_type = ? AND identity_value = ?",
                (identity_type, old_value),
            )

        multicast_observations = conn.execute(
            "SELECT id, ip FROM observations WHERE ip IS NOT NULL"
        ).fetchall()
        for observation in multicast_observations:
            if self._is_multicast_ip(str(observation["ip"])):
                conn.execute("DELETE FROM observations WHERE id = ?", (observation["id"],))
        conn.execute(
            "DELETE FROM assets WHERE NOT EXISTS (SELECT 1 FROM observations WHERE observations.asset_id = assets.id)"
        )

    @staticmethod
    def make_scope_key(mode: str, target: Optional[str], collectors: Sequence[str]) -> str:
        value = json_text({
            "mode": mode or "default",
            "target": (target or "local").strip().lower(),
            "collectors": sorted(set(collectors)),
        })
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]

    def start_run(
        self,
        command: str,
        mode: str,
        target: Optional[str],
        collectors: Sequence[str],
        run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        run_id = run_id or str(uuid.uuid4())
        started_at = utc_now()
        day = started_at[:10]
        raw_directory = self.raw_root / day / run_id
        raw_directory.mkdir(parents=True, exist_ok=True)
        scope_key = self.make_scope_key(mode, target, collectors)
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO scan_runs
                   (id, command, mode, target, scope_key, collectors_json, status,
                    started_at, schema_version, raw_directory)
                   VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?, ?)""",
                (
                    run_id, command, mode, target, scope_key,
                    json_text(sorted(set(collectors))), started_at,
                    SCHEMA_VERSION, str(raw_directory),
                ),
            )
        return {
            "id": run_id,
            "command": command,
            "mode": mode,
            "target": target,
            "scope_key": scope_key,
            "collectors": sorted(set(collectors)),
            "started_at": started_at,
            "raw_directory": str(raw_directory),
        }

    def finish_run(self, run_id: str, status: str = "complete", error: Optional[str] = None) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE scan_runs SET status = ?, finished_at = ?, error = ? WHERE id = ?",
                (status, utc_now(), error, run_id),
            )

    def record_collector_result(
        self,
        run_id: str,
        collector: str,
        status: str,
        object_count: int = 0,
        error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        collector = str(collector or "").strip()
        status = str(status or "").strip().lower()
        if not collector:
            raise ValueError("collector 不能为空")
        if not status:
            raise ValueError("collector status 不能为空")
        if isinstance(object_count, bool) or not isinstance(object_count, int) or object_count < 0:
            raise ValueError("collector object_count 必须是非负整数")
        zero_objects = status == "success" and object_count == 0
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO collector_results
                   (run_id, collector, status, object_count, zero_objects, error,
                    details_json, completed_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(run_id, collector) DO UPDATE SET
                     status = excluded.status,
                     object_count = excluded.object_count,
                     zero_objects = excluded.zero_objects,
                     error = excluded.error,
                     details_json = excluded.details_json,
                     completed_at = excluded.completed_at""",
                (
                    run_id, collector, status, object_count, int(zero_objects), error,
                    json_text(details or {}), utc_now(),
                ),
            )

    def get_collector_results(self, run_id: str) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """SELECT run_id, collector, status, object_count, zero_objects,
                          error, details_json, completed_at
                   FROM collector_results WHERE run_id = ? ORDER BY collector""",
                (run_id,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["zero_objects"] = bool(item["zero_objects"])
            item["details"] = parse_json(item.pop("details_json", None), {})
            results.append(item)
        return results

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def latest_run(self, include_running: bool = False) -> Optional[Dict[str, Any]]:
        with self.connect() as conn:
            if include_running:
                row = conn.execute(
                    "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT 1"
                ).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM scan_runs
                       WHERE status != 'running'
                       ORDER BY started_at DESC LIMIT 1"""
                ).fetchone()
        return dict(row) if row else None

    def list_runs(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def store_raw(
        self,
        run_id: str,
        collector: str,
        filename: str,
        data: Any,
        media_type: str = "application/json",
    ) -> str:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"未知扫描批次: {run_id}")
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", filename).strip("._") or "artifact.txt"
        requested_path = Path(safe_name)
        suffix = requested_path.suffix
        stem = requested_path.stem or "artifact"
        unique_name = f"{stem}_{datetime.now(timezone.utc).strftime('%H%M%S%f')}_{uuid.uuid4().hex}{suffix}"
        raw_directory = Path(run["raw_directory"])
        raw_directory.mkdir(parents=True, exist_ok=True)
        destination = raw_directory / unique_name
        temporary = raw_directory / f".{unique_name}.{uuid.uuid4().hex}.tmp"

        if isinstance(data, bytes):
            payload = data
        elif isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = json_text(data).encode("utf-8")

        try:
            with temporary.open("xb") as artifact:
                artifact.write(payload)
                artifact.flush()
                os.fsync(artifact.fileno())
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()

        with self.connect() as conn:
            conn.execute(
                """INSERT INTO raw_artifacts(run_id, collector, path, media_type, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (run_id, collector, str(destination), media_type, utc_now()),
            )
        return str(destination)

    @staticmethod
    def _is_mac_address(value: str) -> bool:
        return bool(re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", normalize_address(value)))

    @staticmethod
    def _normalized_ip(value: Any) -> Optional[str]:
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            parsed = ip_address(value.strip())
        except ValueError:
            return None
        if parsed.is_multicast:
            return None
        return str(parsed)

    @staticmethod
    def _is_missing_service_value(value: Any) -> bool:
        return value is None or (
            isinstance(value, str)
            and value.strip().lower() in {"", "unknown", "n/a", "none", "null", "-"}
        )

    @classmethod
    def _merge_metadata(cls, existing: Any, incoming: Any) -> Any:
        if isinstance(existing, dict) and isinstance(incoming, dict):
            merged = dict(existing)
            for key, value in incoming.items():
                if key in merged:
                    merged[key] = cls._merge_metadata(merged[key], value)
                elif not cls._is_missing_service_value(value):
                    merged[key] = value
            return merged
        if isinstance(existing, list) and isinstance(incoming, list):
            return incoming if incoming else existing
        return existing if cls._is_missing_service_value(incoming) else incoming

    def _upsert_service(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        asset_id: int,
        service: Dict[str, Any],
        source: Optional[str] = None,
    ) -> None:
        port_value = service.get("port")
        if isinstance(port_value, bool) or port_value is None:
            return
        port_text = str(port_value)
        if not port_text.isdigit():
            return
        port = int(port_text)
        if not 1 <= port <= 65535:
            return
        protocol_value = service.get("protocol") or service.get("proto") or "tcp"
        protocol = str(protocol_value).strip().lower() or "tcp"
        incoming_attributes = dict(service)
        incoming_sources = incoming_attributes.get("sources")
        source_items = incoming_sources if isinstance(incoming_sources, list) else []
        sources = {
            str(item) for item in source_items
            if isinstance(item, str) and item.strip()
        }
        if source:
            sources.add(source)
        if sources:
            incoming_attributes["sources"] = sorted(sources)

        existing = conn.execute(
            """SELECT * FROM services
               WHERE run_id = ? AND asset_id = ? AND protocol = ? AND port = ?""",
            (run_id, asset_id, protocol, port),
        ).fetchone()
        if not existing:
            conn.execute(
                """INSERT INTO services
                   (run_id, asset_id, protocol, port, state, service, product, version, banner, attributes_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id, asset_id, protocol, port,
                    service.get("state") or service.get("status") or "open",
                    service.get("service") or service.get("name"),
                    service.get("product"), service.get("version"), service.get("banner"),
                    json_text(incoming_attributes),
                ),
            )
            return

        old_attributes = parse_json(existing["attributes_json"], {})
        merged_attributes = self._merge_metadata(old_attributes, incoming_attributes)
        old_sources = old_attributes.get("sources") if isinstance(old_attributes, dict) else []
        old_source_items = old_sources if isinstance(old_sources, list) else []
        merged_sources = {
            str(item) for item in old_source_items
            if isinstance(item, str) and item.strip()
        }
        merged_sources.update(sources)
        if merged_sources:
            merged_attributes["sources"] = sorted(merged_sources)

        def preferred(field: str, *incoming_keys: str) -> Any:
            incoming = None
            for key in incoming_keys:
                candidate = service.get(key)
                if not self._is_missing_service_value(candidate):
                    incoming = candidate
                    break
            return existing[field] if self._is_missing_service_value(incoming) else incoming

        conn.execute(
            """UPDATE services SET state = ?, service = ?, product = ?, version = ?,
                                      banner = ?, attributes_json = ?
               WHERE id = ?""",
            (
                preferred("state", "state", "status"),
                preferred("service", "service", "name"),
                preferred("product", "product"),
                preferred("version", "version"),
                preferred("banner", "banner"),
                json_text(merged_attributes), existing["id"],
            ),
        )

    def _merge_assets(
        self,
        conn: sqlite3.Connection,
        source_asset_id: int,
        target_asset_id: int,
    ) -> int:
        if source_asset_id == target_asset_id:
            return target_asset_id
        source = conn.execute("SELECT * FROM assets WHERE id = ?", (source_asset_id,)).fetchone()
        target = conn.execute("SELECT * FROM assets WHERE id = ?", (target_asset_id,)).fetchone()
        if not source or not target:
            raise ValueError("无法合并不存在的资产")

        source_services = conn.execute(
            "SELECT * FROM services WHERE asset_id = ? ORDER BY id", (source_asset_id,)
        ).fetchall()
        for row in source_services:
            service = {
                **parse_json(row["attributes_json"], {}),
                "port": row["port"],
                "protocol": row["protocol"],
                "state": row["state"],
                "service": row["service"],
                "product": row["product"],
                "version": row["version"],
                "banner": row["banner"],
            }
            self._upsert_service(conn, row["run_id"], target_asset_id, service)
        conn.execute("DELETE FROM services WHERE asset_id = ?", (source_asset_id,))

        source_scores = conn.execute(
            "SELECT * FROM threat_scores WHERE asset_id = ?", (source_asset_id,)
        ).fetchall()
        for source_score in source_scores:
            target_score = conn.execute(
                "SELECT * FROM threat_scores WHERE run_id = ? AND asset_id = ?",
                (source_score["run_id"], target_asset_id),
            ).fetchone()
            if not target_score:
                conn.execute(
                    "UPDATE threat_scores SET asset_id = ? WHERE run_id = ? AND asset_id = ?",
                    (target_asset_id, source_score["run_id"], source_asset_id),
                )
                continue
            target_factors = parse_json(target_score["factors_json"], [])
            source_factors = parse_json(source_score["factors_json"], [])
            factors: List[Any] = []
            seen_factors = set()
            for factor in list(target_factors) + list(source_factors):
                marker = json_text(factor)
                if marker not in seen_factors:
                    seen_factors.add(marker)
                    factors.append(factor)
            preferred_score = source_score if float(source_score["score"]) > float(target_score["score"]) else target_score
            conn.execute(
                """UPDATE threat_scores SET score = ?, level = ?, confidence = ?, factors_json = ?
                   WHERE run_id = ? AND asset_id = ?""",
                (
                    preferred_score["score"], preferred_score["level"],
                    max(float(source_score["confidence"]), float(target_score["confidence"])),
                    json_text(factors), source_score["run_id"], target_asset_id,
                ),
            )
            conn.execute(
                "DELETE FROM threat_scores WHERE run_id = ? AND asset_id = ?",
                (source_score["run_id"], source_asset_id),
            )

        conn.execute("UPDATE observations SET asset_id = ? WHERE asset_id = ?", (target_asset_id, source_asset_id))
        conn.execute("UPDATE findings SET asset_id = ? WHERE asset_id = ?", (target_asset_id, source_asset_id))
        conn.execute("UPDATE asset_aliases SET asset_id = ? WHERE asset_id = ?", (target_asset_id, source_asset_id))
        conn.execute(
            """INSERT INTO asset_aliases(identity_type, identity_value, asset_id, created_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(identity_type, identity_value) DO UPDATE SET asset_id = excluded.asset_id""",
            (source["identity_type"], source["identity_value"], target_asset_id, utc_now()),
        )

        source_attributes = parse_json(source["attributes_json"], {})
        target_attributes = parse_json(target["attributes_json"], {})
        merged_attributes = self._merge_metadata(source_attributes, target_attributes)
        source_last_seen = str(source["last_seen"])
        target_last_seen = str(target["last_seen"])
        if source_last_seen > target_last_seen:
            last_seen = source_last_seen
            last_run_id = source["last_run_id"]
        else:
            last_seen = target_last_seen
            last_run_id = target["last_run_id"]
        conn.execute(
            """UPDATE assets SET label = ?, first_seen = ?, last_seen = ?, last_run_id = ?,
                                  attributes_json = ? WHERE id = ?""",
            (
                target["label"] or source["label"],
                min(str(source["first_seen"]), str(target["first_seen"])),
                last_seen, last_run_id, json_text(merged_attributes), target_asset_id,
            ),
        )
        conn.execute("DELETE FROM assets WHERE id = ?", (source_asset_id,))
        return target_asset_id

    def _canonicalize_trusted_mac_ip(
        self,
        conn: sqlite3.Connection,
        asset_id: int,
        mac_value: str,
        ip_value: str,
        run_id: str,
        observed_at: str,
        attributes: Dict[str, Any],
    ) -> int:
        normalized_mac = normalize_address(mac_value)
        normalized_ip = self._normalized_ip(ip_value)
        if not self._is_mac_address(normalized_mac) or not normalized_ip:
            return asset_id

        canonical_mac = conn.execute(
            "SELECT id FROM assets WHERE identity_type = 'mac' AND identity_value = ?",
            (normalized_mac,),
        ).fetchone()
        if canonical_mac and int(canonical_mac["id"]) != asset_id:
            asset_id = self._merge_assets(conn, asset_id, int(canonical_mac["id"]))
        else:
            current = conn.execute(
                "SELECT identity_type, identity_value FROM assets WHERE id = ?", (asset_id,)
            ).fetchone()
            if current and (current["identity_type"], current["identity_value"]) != ("mac", normalized_mac):
                conn.execute(
                    """INSERT INTO asset_aliases(identity_type, identity_value, asset_id, created_at)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(identity_type, identity_value) DO UPDATE SET asset_id = excluded.asset_id""",
                    (current["identity_type"], current["identity_value"], asset_id, utc_now()),
                )
                conn.execute(
                    "UPDATE assets SET identity_type = 'mac', identity_value = ? WHERE id = ?",
                    (normalized_mac, asset_id),
                )

        canonical_ip = conn.execute(
            "SELECT id FROM assets WHERE identity_type = 'ip' AND identity_value = ?",
            (normalized_ip,),
        ).fetchone()
        if canonical_ip and int(canonical_ip["id"]) != asset_id:
            asset_id = self._merge_assets(conn, int(canonical_ip["id"]), asset_id)

        row = conn.execute("SELECT attributes_json FROM assets WHERE id = ?", (asset_id,)).fetchone()
        merged_attributes = self._merge_metadata(
            parse_json(row["attributes_json"], {}) if row else {}, attributes
        )
        conn.execute(
            """UPDATE assets SET last_seen = ?, last_run_id = ?, attributes_json = ? WHERE id = ?""",
            (observed_at, run_id, json_text(merged_attributes), asset_id),
        )
        conn.execute(
            """INSERT INTO asset_aliases(identity_type, identity_value, asset_id, created_at)
               VALUES ('ip', ?, ?, ?)
               ON CONFLICT(identity_type, identity_value) DO UPDATE SET asset_id = excluded.asset_id""",
            (normalized_ip, asset_id, utc_now()),
        )
        return asset_id

    def _resolve_asset(
        self,
        conn: sqlite3.Connection,
        identity_type: str,
        identity_value: str,
        run_id: str,
        observed_at: str,
        attributes: Dict[str, Any],
    ) -> int:
        identity_type, identity_value = normalize_identity(identity_type, identity_value)
        if not identity_value:
            raise ValueError("观测事件缺少稳定身份值")

        alias = conn.execute(
            "SELECT asset_id FROM asset_aliases WHERE identity_type = ? AND identity_value = ?",
            (identity_type, identity_value),
        ).fetchone()
        if alias:
            asset_id = int(alias["asset_id"])
            row = conn.execute("SELECT attributes_json FROM assets WHERE id = ?", (asset_id,)).fetchone()
            merged = self._merge_metadata(
                parse_json(row["attributes_json"], {}) if row else {}, attributes
            )
            conn.execute(
                """UPDATE assets SET last_seen = ?, last_run_id = ?, attributes_json = ?
                   WHERE id = ?""",
                (observed_at, run_id, json_text(merged), asset_id),
            )
            return asset_id

        row = conn.execute(
            "SELECT * FROM assets WHERE identity_type = ? AND identity_value = ?",
            (identity_type, identity_value),
        ).fetchone()
        if row:
            old_attributes = parse_json(row["attributes_json"], {})
            merged = self._merge_metadata(old_attributes, attributes)
            conn.execute(
                """UPDATE assets SET last_seen = ?, last_run_id = ?, attributes_json = ?
                   WHERE id = ?""",
                (observed_at, run_id, json_text(merged), row["id"]),
            )
            return int(row["id"])

        cursor = conn.execute(
            """INSERT INTO assets
               (identity_type, identity_value, label, first_seen, last_seen, last_run_id, attributes_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                identity_type, identity_value,
                attributes.get("name") or attributes.get("hostname") or attributes.get("ssid"),
                observed_at, observed_at, run_id, json_text(attributes),
            ),
        )
        if cursor.lastrowid is None:
            raise RuntimeError("创建资产记录失败")
        return int(cursor.lastrowid)

    def add_alias(self, asset_id: int, identity_type: str, identity_value: str) -> None:
        identity_type, identity_value = normalize_identity(identity_type, identity_value)
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO asset_aliases(identity_type, identity_value, asset_id, created_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(identity_type, identity_value)
                   DO UPDATE SET asset_id = excluded.asset_id""",
                (identity_type, identity_value, asset_id, utc_now()),
            )

    def ingest_event(self, event: Dict[str, Any]) -> int:
        required = {"run_id", "source", "kind", "identity"}
        missing = sorted(required - set(event))
        if missing:
            raise ValueError(f"观测事件缺少字段: {', '.join(missing)}")
        identity = event.get("identity") or {}
        attributes = dict(event.get("attributes") or {})
        evidence = dict(event.get("evidence") or {})
        observed_at = event.get("observed_at") or utc_now()
        identity_type = identity.get("type") or "unknown"
        identity_value = identity.get("value") or ""

        with self.connect() as conn:
            asset_id = self._resolve_asset(
                conn, identity_type, identity_value, event["run_id"], observed_at, attributes
            )
            ip_value = attributes.get("ip")
            mac_value = attributes.get("mac")
            if identity_type == "mac" and ip_value:
                asset_id = self._canonicalize_trusted_mac_ip(
                    conn, asset_id, str(mac_value or identity_value), str(ip_value),
                    event["run_id"], observed_at, attributes,
                )
            conn.execute(
                """INSERT INTO observations
                   (run_id, asset_id, source, kind, observed_at, ip, mac, hostname,
                    confidence, attributes_json, evidence_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["run_id"], asset_id, event["source"], event["kind"], observed_at,
                    attributes.get("ip"), attributes.get("mac"),
                    attributes.get("hostname") or attributes.get("name"),
                    event.get("confidence"), json_text(attributes), json_text(evidence),
                ),
            )

            # 同一条受信观测同时携带 MAC 与 IP 时，可安全地把 IP 作为该资产的别名。
            # 这让后续按 IP 运行的 Nmap/Nikto 结果能关联到 ARP 发现的长期 MAC 资产，
            # 但不会仅凭厂商或名称相似度自动合并不同设备。
            if identity_type == "mac" and ip_value:
                alias_value = self._normalized_ip(str(ip_value))
                if alias_value:
                    conn.execute(
                        """INSERT INTO asset_aliases(identity_type, identity_value, asset_id, created_at)
                           VALUES ('ip', ?, ?, ?)
                           ON CONFLICT(identity_type, identity_value)
                           DO UPDATE SET asset_id = excluded.asset_id""",
                        (alias_value, asset_id, utc_now()),
                    )

            raw_services = event.get("services") or attributes.get("services") or []
            raw_ports = event.get("ports") or attributes.get("ports") or attributes.get("openPorts") or []
            if not isinstance(raw_services, list):
                raw_services = []
            if not isinstance(raw_ports, list):
                raw_ports = []
            service_by_port: Dict[int, Dict[str, Any]] = {}
            for item in raw_services:
                if not isinstance(item, dict) or item.get("port") is None:
                    continue
                if not isinstance(item.get("port"), bool) and str(item["port"]).isdigit():
                    service_by_port[int(item["port"])] = item
            for item in raw_ports:
                if isinstance(item, dict):
                    port = item.get("port")
                    service = item
                else:
                    port = item
                    service = service_by_port.get(int(port), {}) if str(port).isdigit() else {}
                if isinstance(port, bool) or port is None or not str(port).isdigit():
                    continue
                normalized_service = {**service, "port": int(port)}
                self._upsert_service(
                    conn, event["run_id"], asset_id, normalized_service, event["source"]
                )
        return asset_id

    def ingest_events(self, events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        accepted = 0
        rejected: List[str] = []
        asset_ids = set()
        for index, event in enumerate(events, start=1):
            try:
                asset_ids.add(self.ingest_event(event))
                accepted += 1
            except Exception as exc:
                rejected.append(f"event {index}: {exc}")
        return {"accepted": accepted, "rejected": rejected, "assets": len(asset_ids)}

    def ingest_audit_devices(self, run_id: str, devices: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
        events = []
        for device in devices:
            mac = device.get("mac") or ""
            identity_type = "mac" if mac and mac != "N/A" else "ip"
            identity_value = mac if identity_type == "mac" else device.get("ip", "")
            services = []
            service_names = list(device.get("services") or [])
            for index, port in enumerate(device.get("ports") or []):
                services.append({
                    "port": int(port),
                    "protocol": "tcp",
                    "state": "open",
                    "service": service_names[index] if index < len(service_names) else None,
                })
            events.append({
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "source": "audit.network",
                "kind": "device_observation",
                "observed_at": utc_now(),
                "identity": {"type": identity_type, "value": identity_value},
                "confidence": device.get("confidence"),
                "attributes": {
                    **device,
                    "ports": list(device.get("ports") or []),
                    "services": services,
                    "classification": device.get("device_type"),
                    "classification_confidence": device.get("confidence"),
                },
                "evidence": {"origin": "arp_and_socket_probe"},
            })
        return self.ingest_events(events)

    @staticmethod
    def _target_identity(value: Any, allow_domain: bool = True) -> Optional[Tuple[str, str]]:
        if not isinstance(value, str) or not value.strip():
            return None
        raw_value = value.strip()
        try:
            network = ip_network(raw_value, strict=False)
            if "/" in raw_value:
                return None
            return "ip", str(network.network_address)
        except ValueError:
            pass

        parsed = urlsplit(raw_value if "://" in raw_value else f"//{raw_value}")
        host = parsed.hostname
        if not host:
            return None
        normalized_ip = DataStore._normalized_ip(host)
        if normalized_ip:
            return "ip", normalized_ip
        normalized_host = host.rstrip(".").lower()
        if allow_domain and normalized_host and "/" not in normalized_host:
            return "domain", normalized_host
        return None

    @staticmethod
    def _validate_tool_ports(value: Any, label: str) -> List[Dict[str, Any]]:
        if not isinstance(value, list):
            raise ValueError(f"{label} 必须是数组")
        ports: List[Dict[str, Any]] = []
        for index, item in enumerate(value, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"{label}[{index}] 必须是对象")
            port = item.get("port")
            if isinstance(port, bool) or port is None:
                raise ValueError(f"{label}[{index}].port 必须是 1 到 65535 的整数")
            port_text = str(port)
            if not port_text.isdigit():
                raise ValueError(f"{label}[{index}].port 必须是 1 到 65535 的整数")
            port_number = int(port_text)
            if not 1 <= port_number <= 65535:
                raise ValueError(f"{label}[{index}].port 必须是 1 到 65535 的整数")
            normalized = {**item, "port": port_number}
            service_value = normalized.get("service")
            if isinstance(service_value, dict):
                service_name = service_value.get("name")
                if service_name is not None and not isinstance(service_name, str):
                    raise ValueError(f"{label}[{index}].service.name 必须是字符串")
                normalized["service"] = service_name
            for field in ("protocol", "proto", "state", "status", "service", "name", "product", "version", "banner"):
                field_value = normalized.get(field)
                if field_value is not None and not isinstance(field_value, str):
                    raise ValueError(f"{label}[{index}].{field} 必须是字符串")
            ports.append(normalized)
        return ports

    @staticmethod
    def _nmap_host_ip(host: Dict[str, Any]) -> Optional[str]:
        for key in ("ip", "address", "addr"):
            normalized = DataStore._normalized_ip(host.get(key))
            if normalized:
                return normalized
        addresses = host.get("addresses")
        if isinstance(addresses, dict):
            candidates = list(addresses.values())
        elif isinstance(addresses, list):
            candidates = addresses
        else:
            candidates = []
        for candidate in candidates:
            if isinstance(candidate, dict):
                value = candidate.get("address") or candidate.get("addr") or candidate.get("value")
            else:
                value = candidate
            normalized = DataStore._normalized_ip(value)
            if normalized:
                return normalized
        return None

    @staticmethod
    def _normalized_hostnames(value: Any) -> List[str]:
        if not isinstance(value, list):
            return []
        hostnames = []
        for item in value:
            if isinstance(item, str) and item.strip():
                hostnames.append(item.strip().rstrip(".").lower())
            elif isinstance(item, dict):
                name = item.get("name") or item.get("hostname")
                if isinstance(name, str) and name.strip():
                    hostnames.append(name.strip().rstrip(".").lower())
        return hostnames

    @staticmethod
    def _tool_rejection_reason(result: Dict[str, Any]) -> Optional[str]:
        return_code = result.get("return_code")
        if return_code is not None:
            if isinstance(return_code, bool):
                return "return_code 类型无效"
            try:
                numeric_code = int(return_code)
            except (TypeError, ValueError):
                return "return_code 类型无效"
            if numeric_code != 0:
                return f"工具退出码为 {numeric_code}"
        timeout_flag = result.get("timed_out") is True or result.get("timeout") is True
        status = str(result.get("status") or "").strip().lower()
        error_text = " ".join(
            str(result.get(key) or "") for key in ("error", "stderr")
        ).lower()
        if (
            timeout_flag
            or status in {"timeout", "timed_out"}
            or "超时" in error_text
            or "timed out" in error_text
            or "timeout" in error_text
        ):
            return "工具执行超时"
        if result.get("parse_failed") is True or result.get("parsed") is False or result.get("parse_error"):
            return f"解析失败: {result.get('parse_error') or '工具标记解析失败'}"
        return None

    def ingest_tool_result(
        self,
        run_id: str,
        tool: str,
        target: str,
        result: Optional[Any],
    ) -> Dict[str, Any]:
        tool = str(tool or "unknown").strip().lower() or "unknown"
        artifact_suffix = ""
        if tool == "nikto" and isinstance(result, dict):
            result_target = str(result.get("target") or target)
            if ":" in result_target:
                artifact_suffix = "_" + re.sub(
                    r"[^0-9A-Za-z._-]+", "_", result_target.rsplit(":", 1)[-1]
                )
        if result is not None:
            self.store_raw(run_id, tool, f"{tool}{artifact_suffix}_result.json", result)
        if result is None:
            return {"accepted": 0, "rejected": [f"{tool}: rejected: 无结果"], "assets": 0}
        if not isinstance(result, dict):
            return {"accepted": 0, "rejected": [f"{tool}: rejected: 顶层结果必须是对象"], "assets": 0}

        rejection = self._tool_rejection_reason(result)
        if rejection:
            return {"accepted": 0, "rejected": [f"{tool}: rejected: {rejection}"], "assets": 0}
        if tool in {"masscan", "nikto"} and ("output" in result or "stderr" in result):
            structured_key = "ports" if tool == "masscan" else "vulnerabilities"
            structured_value = result.get(structured_key)
            if "structured_output" not in result and structured_value in (None, []):
                return {
                    "accepted": 0,
                    "rejected": [f"{tool}: rejected: 解析失败: 未产出结构化结果"],
                    "assets": 0,
                }

        base_attributes: Dict[str, Any] = {
            "target": target,
            "tool": tool,
            "return_code": result.get("return_code"),
            "error": result.get("error") or result.get("stderr"),
        }
        observed_at = result.get("timestamp") or utc_now()
        events: List[Dict[str, Any]] = []

        try:
            if tool == "nmap":
                parsed = result.get("open_ports")
                hosts = result.get("hosts")
                if hosts is None and isinstance(parsed, dict) and "hosts" in parsed:
                    hosts = parsed.get("hosts")
                if hosts is not None:
                    if not isinstance(hosts, list):
                        raise ValueError("hosts 必须是数组")
                    for index, host in enumerate(hosts, start=1):
                        if not isinstance(host, dict):
                            raise ValueError(f"hosts[{index}] 必须是对象")
                        open_ports = host.get("open_ports")
                        host_payload = open_ports if isinstance(open_ports, dict) else host
                        if "ports" not in host_payload:
                            raise ValueError(f"hosts[{index}] 缺少 ports 数组")
                        ports = self._validate_tool_ports(
                            host_payload.get("ports"), f"hosts[{index}].ports"
                        )
                        hostnames = self._normalized_hostnames(
                            host_payload.get("hostnames", host.get("hostnames", []))
                        )
                        host_ip = self._nmap_host_ip(host)
                        identity = ("ip", host_ip) if host_ip else None
                        if not identity and hostnames:
                            identity = ("domain", hostnames[0])
                        if not identity:
                            raise ValueError(f"hosts[{index}] 缺少有效 IP 或主机名")
                        attributes = {
                            **base_attributes,
                            "ip": host_ip,
                            "hostname": hostnames[0] if hostnames else None,
                            "hostnames": hostnames,
                            "os": host_payload.get("os", host.get("os")),
                            "ports": ports,
                            "services": ports,
                        }
                        events.append({
                            "schema_version": SCHEMA_VERSION,
                            "run_id": run_id,
                            "source": "tool.nmap",
                            "kind": "host_observation",
                            "observed_at": observed_at,
                            "identity": {"type": identity[0], "value": identity[1]},
                            "attributes": attributes,
                            "evidence": {"raw_output_available": True, "host_index": index},
                        })
                else:
                    if isinstance(parsed, dict):
                        if "ports" not in parsed:
                            raise ValueError("open_ports 缺少 ports 数组")
                        ports = self._validate_tool_ports(parsed.get("ports"), "open_ports.ports")
                        hostnames = self._normalized_hostnames(parsed.get("hostnames", []))
                        host_ip = self._nmap_host_ip(parsed)
                        identity = ("ip", host_ip) if host_ip else self._target_identity(target)
                        os_value = parsed.get("os")
                    elif isinstance(parsed, list):
                        ports = self._validate_tool_ports(parsed, "open_ports")
                        hostnames = []
                        identity = self._target_identity(target)
                        host_ip = identity[1] if identity and identity[0] == "ip" else None
                        os_value = None
                    else:
                        raise ValueError("open_ports 必须是对象或数组")
                    if not identity:
                        raise ValueError("旧版单主机结果缺少有效扫描目标")
                    events.append({
                        "schema_version": SCHEMA_VERSION,
                        "run_id": run_id,
                        "source": "tool.nmap",
                        "kind": "host_observation",
                        "observed_at": observed_at,
                        "identity": {"type": identity[0], "value": identity[1]},
                        "attributes": {
                            **base_attributes,
                            "ip": host_ip,
                            "hostname": hostnames[0] if hostnames else None,
                            "hostnames": hostnames,
                            "os": os_value,
                            "ports": ports,
                            "services": ports,
                        },
                        "evidence": {"raw_output_available": True},
                    })
            elif tool == "masscan":
                raw_ports = result.get("ports") if "ports" in result else result.get("open_ports")
                if raw_ports is None:
                    raw_ports = result.get("structured_output")
                if not isinstance(raw_ports, list):
                    raise ValueError("ports/open_ports 必须是数组")
                grouped: Dict[str, List[Dict[str, Any]]] = {}
                target_identity = self._target_identity(target, allow_domain=False)
                target_ip = target_identity[1] if target_identity else None
                for index, item in enumerate(raw_ports, start=1):
                    if not isinstance(item, dict):
                        raise ValueError(f"ports[{index}] 必须是对象")
                    host_ip = self._normalized_ip(item.get("ip")) or target_ip
                    host_ports = item.get("ports") if "ports" in item else [item]
                    if not host_ip:
                        raise ValueError(f"ports[{index}] 缺少有效 ip；CIDR 目标不能作为资产")
                    ports = self._validate_tool_ports(host_ports, f"ports[{index}].ports")
                    grouped.setdefault(host_ip, []).extend(ports)
                for host_ip, ports in grouped.items():
                    events.append({
                        "schema_version": SCHEMA_VERSION,
                        "run_id": run_id,
                        "source": "tool.masscan",
                        "kind": "host_observation",
                        "observed_at": observed_at,
                        "identity": {"type": "ip", "value": host_ip},
                        "attributes": {
                            **base_attributes, "ip": host_ip,
                            "ports": ports, "services": ports,
                        },
                        "evidence": {"raw_output_available": True},
                    })
            elif tool == "nikto":
                vulnerabilities = result.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError("vulnerabilities 必须是数组")
                for index, vuln in enumerate(vulnerabilities, start=1):
                    if not isinstance(vuln, dict):
                        raise ValueError(f"vulnerabilities[{index}] 必须是对象")
                    for field in ("severity", "msg", "description"):
                        field_value = vuln.get(field)
                        if field_value is not None and not isinstance(field_value, str):
                            raise ValueError(f"vulnerabilities[{index}].{field} 必须是字符串")
                vuln_count = result.get("vuln_count", len(vulnerabilities))
                if isinstance(vuln_count, bool) or not isinstance(vuln_count, int) or vuln_count < 0:
                    raise ValueError("vuln_count 必须是非负整数")
                identity = self._target_identity(result.get("target") or target)
                if not identity:
                    raise ValueError("Nikto 结果缺少有效目标")
                if not vulnerabilities:
                    events.append({
                        "schema_version": SCHEMA_VERSION,
                        "run_id": run_id,
                        "source": "tool.nikto",
                        "kind": "web_scan_observation",
                        "observed_at": observed_at,
                        "identity": {"type": identity[0], "value": identity[1]},
                        "attributes": {**base_attributes, "vulnerability_count": vuln_count},
                        "evidence": {"raw_output_available": True},
                    })
                for vuln in vulnerabilities:
                    severity = str(vuln.get("severity") or "unknown").strip().lower() or "unknown"
                    events.append({
                        "schema_version": SCHEMA_VERSION,
                        "run_id": run_id,
                        "source": "tool.nikto",
                        "kind": "vulnerability_observation",
                        "observed_at": observed_at,
                        "identity": {"type": identity[0], "value": identity[1]},
                        "attributes": {
                            **base_attributes,
                            "severity": severity,
                            "vulnerability": vuln,
                        },
                        "evidence": {"raw_output_available": True},
                    })
            elif tool == "theharvester":
                identity = self._target_identity(result.get("domain") or target)
                if not identity or identity[0] != "domain":
                    raise ValueError("TheHarvester 结果缺少有效域名")
                events.append({
                    "schema_version": SCHEMA_VERSION,
                    "run_id": run_id,
                    "source": "tool.theharvester",
                    "kind": "osint_observation",
                    "observed_at": observed_at,
                    "identity": {"type": "domain", "value": identity[1]},
                    "attributes": base_attributes,
                    "evidence": {"raw_output_available": True},
                })
            else:
                identity = self._target_identity(target)
                if not identity:
                    raise ValueError("工具结果缺少有效目标")
                events.append({
                    "schema_version": SCHEMA_VERSION,
                    "run_id": run_id,
                    "source": f"tool.{tool}",
                    "kind": "tool_observation",
                    "observed_at": observed_at,
                    "identity": {"type": identity[0], "value": identity[1]},
                    "attributes": base_attributes,
                })
        except (TypeError, ValueError) as exc:
            return {"accepted": 0, "rejected": [f"{tool}: rejected: 解析失败: {exc}"], "assets": 0}

        ingestion = self.ingest_events(events)
        if ingestion["rejected"]:
            ingestion["rejected"] = [f"{tool}: rejected: {message}" for message in ingestion["rejected"]]
        return ingestion

    def set_baseline(self, run_id: str) -> None:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"未知扫描批次: {run_id}")
        if run["status"] not in {"complete", "partial"}:
            raise ValueError("只有 complete/partial 批次可以设为基线")
        with self.connect() as conn:
            conn.execute(
                """INSERT INTO baselines(scope_key, run_id, set_at) VALUES (?, ?, ?)
                   ON CONFLICT(scope_key) DO UPDATE SET run_id = excluded.run_id, set_at = excluded.set_at""",
                (run["scope_key"], run_id, utc_now()),
            )

    def comparable_baseline(self, run_id: str) -> Optional[str]:
        run = self.get_run(run_id)
        if not run:
            return None
        with self.connect() as conn:
            fixed = conn.execute(
                """SELECT r.id FROM baselines b
                   JOIN scan_runs r ON r.id = b.run_id
                   WHERE b.scope_key = ? AND r.scope_key = ? AND r.id != ?
                     AND r.started_at < ? AND r.status IN ('complete', 'partial')""",
                (run["scope_key"], run["scope_key"], run_id, run["started_at"]),
            ).fetchone()
            if fixed:
                return str(fixed["id"])
            previous = conn.execute(
                """SELECT id FROM scan_runs
                   WHERE scope_key = ? AND id != ? AND started_at < ?
                     AND status IN ('complete', 'partial')
                   ORDER BY started_at DESC LIMIT 1""",
                (run["scope_key"], run_id, run["started_at"]),
            ).fetchone()
        return str(previous["id"]) if previous else None

    def _run_assets(self, conn: sqlite3.Connection, run_id: str) -> Dict[int, Dict[str, Any]]:
        rows = conn.execute(
            """SELECT DISTINCT a.id, a.identity_type, a.identity_value, a.label,
                              a.first_seen, a.last_seen, a.attributes_json
               FROM assets a JOIN observations o ON o.asset_id = a.id
               WHERE o.run_id = ?""",
            (run_id,),
        ).fetchall()
        return {
            int(row["id"]): {
                **dict(row),
                "attributes": parse_json(row["attributes_json"], {}),
            }
            for row in rows
        }

    def _run_services(self, conn: sqlite3.Connection, run_id: str) -> set[Tuple[int, str, int]]:
        rows = conn.execute(
            "SELECT asset_id, protocol, port FROM services WHERE run_id = ? AND state = 'open'",
            (run_id,),
        ).fetchall()
        return {(int(row["asset_id"]), row["protocol"], int(row["port"])) for row in rows}

    def compare_runs(self, run_id: str, baseline_id: Optional[str] = None) -> Dict[str, Any]:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"未知扫描批次: {run_id}")
        if baseline_id is not None:
            baseline = self.get_run(baseline_id)
            if not baseline:
                raise ValueError(f"未知基线批次: {baseline_id}")
            if baseline_id == run_id:
                raise ValueError("基线批次不能与当前批次相同")
            if baseline["scope_key"] != run["scope_key"]:
                raise ValueError("基线批次与当前批次 scope 不一致")
            if baseline["status"] not in {"complete", "partial"}:
                raise ValueError("基线批次状态必须为 complete/partial")
            if baseline["started_at"] >= run["started_at"]:
                raise ValueError("基线批次必须早于当前批次")
        else:
            baseline_id = self.comparable_baseline(run_id)
        if not baseline_id:
            return {
                "run_id": run_id,
                "baseline_id": None,
                "new_assets": [],
                "missing_assets": [],
                "opened_ports": [],
                "closed_ports": [],
            }
        with self.connect() as conn:
            current_assets = self._run_assets(conn, run_id)
            baseline_assets = self._run_assets(conn, baseline_id)
            current_services = self._run_services(conn, run_id)
            baseline_services = self._run_services(conn, baseline_id)

        new_ids = sorted(set(current_assets) - set(baseline_assets))
        missing_ids = sorted(set(baseline_assets) - set(current_assets))
        opened = sorted(current_services - baseline_services)
        closed = sorted(baseline_services - current_services)

        def port_items(items: Iterable[Tuple[int, str, int]], assets: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
            result = []
            for asset_id, protocol, port in items:
                asset = assets.get(asset_id) or current_assets.get(asset_id) or baseline_assets.get(asset_id) or {}
                result.append({
                    "asset_id": asset_id,
                    "identity_type": asset.get("identity_type"),
                    "identity_value": asset.get("identity_value"),
                    "protocol": protocol,
                    "port": port,
                })
            return result

        return {
            "run_id": run_id,
            "baseline_id": baseline_id,
            "new_assets": [current_assets[item] for item in new_ids],
            "missing_assets": [baseline_assets[item] for item in missing_ids],
            "opened_ports": port_items(opened, current_assets),
            "closed_ports": port_items(closed, baseline_assets),
        }

    def analyze_run(self, run_id: str, baseline_id: Optional[str] = None) -> Dict[str, Any]:
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"未知扫描批次: {run_id}")
        changes = self.compare_runs(run_id, baseline_id)
        new_asset_ids = {int(item["id"]) for item in changes["new_assets"]}
        newly_opened = {(int(item["asset_id"]), int(item["port"])) for item in changes["opened_ports"]}

        with self.connect() as conn:
            assets = self._run_assets(conn, run_id)
            conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM threat_scores WHERE run_id = ?", (run_id,))

            scored_assets = []
            for asset_id, asset in assets.items():
                services = conn.execute(
                    "SELECT * FROM services WHERE run_id = ? AND asset_id = ? AND state = 'open'",
                    (run_id, asset_id),
                ).fetchall()
                observations = conn.execute(
                    "SELECT * FROM observations WHERE run_id = ? AND asset_id = ?",
                    (run_id, asset_id),
                ).fetchall()
                prior_run_filter = """
                    JOIN scan_runs historical_run ON historical_run.id = historical.run_id
                    WHERE historical.asset_id = ?
                      AND historical_run.scope_key = ?
                      AND historical_run.started_at < ?
                      AND historical_run.status IN ('complete', 'partial')
                """
                prior_history = int(conn.execute(
                    f"""SELECT COUNT(DISTINCT historical.run_id) AS count
                        FROM observations historical {prior_run_filter}""",
                    (asset_id, run["scope_key"], run["started_at"]),
                ).fetchone()["count"])
                history = prior_history

                factors: List[Dict[str, Any]] = []
                source_names = {row["source"] for row in observations}
                source_channels = {
                    "local_network" if source in {"audit.network", "spy.network"}
                    else "active_network_scanner" if source in {"tool.nmap", "tool.masscan"}
                    else "web_vulnerability_scanner" if source == "tool.nikto"
                    else "wireless" if source in {"spy.wifi", "spy.bluetooth"}
                    else "osint" if source == "tool.theharvester"
                    else source
                    for source in source_names
                }

                persistent_risky_ports: List[int] = []
                for service in services:
                    port = int(service["port"])
                    rule = PORT_RISK_RULES.get(port)
                    if not rule:
                        continue
                    weight = float(rule["weight"])
                    factors.append({
                        "rule_id": rule["rule"],
                        "score": weight,
                        "title": rule["title"],
                        "description": rule["description"],
                        "evidence": {
                            "fact": "open_port",
                            "protocol": service["protocol"],
                            "port": port,
                            "service": service["service"],
                            "inference": "potential_exposure_not_confirmed_vulnerability",
                        },
                    })
                    prior_occurrence = conn.execute(
                        """SELECT COUNT(DISTINCT historical_service.run_id) AS count
                           FROM services historical_service
                           JOIN scan_runs historical_run ON historical_run.id = historical_service.run_id
                           WHERE historical_service.asset_id = ? AND historical_service.port = ?
                             AND historical_service.protocol = ? AND historical_service.state = 'open'
                             AND historical_run.scope_key = ? AND historical_run.started_at < ?
                             AND historical_run.status IN ('complete', 'partial')""",
                        (
                            asset_id, port, service["protocol"],
                            run["scope_key"], run["started_at"],
                        ),
                    ).fetchone()["count"]
                    if int(prior_occurrence) > 0:
                        persistent_risky_ports.append(port)
                    if (asset_id, port) in newly_opened:
                        factors.append({
                            "rule_id": "new_risky_port",
                            "score": min(1.3, weight * 0.4),
                            "title": "新开放的敏感端口",
                            "description": f"相较基线，本次新发现 {service['protocol']}/{port}。",
                            "evidence": {"fact": "baseline_change", "port": port},
                        })

                for observation in observations:
                    attributes = parse_json(observation["attributes_json"], {})
                    if attributes.get("suspicious") or attributes.get("note"):
                        factors.append({
                            "rule_id": "collector_suspicion",
                            "score": 1.2,
                            "title": "采集器标记为可疑",
                            "description": "设备名称、厂商或信号特征触发了采集器规则，需要人工确认。",
                            "evidence": {
                                "fact": "collector_flag",
                                "source": observation["source"],
                                "note": attributes.get("note"),
                            },
                        })
                    if observation["kind"] == "vulnerability_observation":
                        severity = str(attributes.get("severity") or "unknown").lower()
                        vuln = attributes.get("vulnerability") or {}
                        if not isinstance(vuln, dict):
                            vuln = {}
                        factors.append({
                            "rule_id": "scanner_vulnerability",
                            "severity": severity if severity in VULNERABILITY_WEIGHTS else "unknown",
                            "score": VULNERABILITY_WEIGHTS.get(severity, VULNERABILITY_WEIGHTS["unknown"]),
                            "title": f"漏洞扫描发现（{severity}）",
                            "description": vuln.get("msg") or vuln.get("description") or "外部扫描器报告了潜在漏洞。",
                            "evidence": {"fact": "tool_finding", "source": observation["source"], "record": vuln},
                        })

                if asset_id in new_asset_ids:
                    factors.append({
                        "rule_id": "new_asset",
                        "score": 0.9,
                        "title": "新出现的资产",
                        "description": "该身份未出现在最近可比基线中；新出现不等同于恶意。",
                        "evidence": {"fact": "baseline_change", "baseline_id": changes["baseline_id"]},
                    })

                if persistent_risky_ports:
                    persistence_score = min(1.0, 0.35 + max(0, int(history) - 1) * 0.15)
                    factors.append({
                        "rule_id": "persistent_risk_exposure",
                        "score": round(persistence_score, 2),
                        "title": "敏感端口持续暴露",
                        "description": "同一敏感端口在历史批次与本批次中均处于开放状态。",
                        "evidence": {
                            "fact": "historical_persistence",
                            "history_runs": int(history),
                            "ports": sorted(set(persistent_risky_ports)),
                        },
                    })

                raw_score = sum(float(item["score"]) for item in factors)
                evidence_categories = len({item["evidence"].get("fact") for item in factors})
                confidence = 0.35
                confidence += min(0.25, evidence_categories * 0.08)
                confidence += 0.12 if len(source_channels) >= 2 else 0.0
                confidence += 0.08 if int(history) >= 2 else 0.0
                confidence += 0.08 if any(row["kind"] == "vulnerability_observation" for row in observations) else 0.0
                confidence = min(confidence, 0.95)

                adjusted_score = min(10.0, raw_score * (0.85 + confidence * 0.30))
                adjusted_score = round(adjusted_score, 2)
                level = severity_for_score(adjusted_score)

                for factor in factors:
                    factor_score = round(float(factor["score"]), 2)
                    conn.execute(
                        """INSERT INTO findings
                           (run_id, asset_id, rule_id, severity, score, confidence,
                            title, description, evidence_json)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            run_id, asset_id, factor["rule_id"],
                            factor.get("severity") or severity_for_score(factor_score),
                            factor_score, confidence, factor["title"], factor["description"],
                            json_text(factor["evidence"]),
                        ),
                    )
                conn.execute(
                    """INSERT INTO threat_scores
                       (run_id, asset_id, score, level, confidence, factors_json)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (run_id, asset_id, adjusted_score, level, confidence, json_text(factors)),
                )
                scored_assets.append({
                    "asset_id": asset_id,
                    "identity_type": asset["identity_type"],
                    "identity_value": asset["identity_value"],
                    "label": asset.get("label"),
                    "score": adjusted_score,
                    "level": level,
                    "confidence": round(confidence, 2),
                    "sources": sorted(source_names),
                    "source_channels": sorted(source_channels),
                    "history_runs": int(history),
                    "factors": factors,
                })

        with self.connect() as conn:
            source_counts = {
                str(row["source"]): int(row["count"])
                for row in conn.execute(
                    "SELECT source, COUNT(*) AS count FROM observations WHERE run_id = ? GROUP BY source",
                    (run_id,),
                ).fetchall()
            }
            service_count = int(conn.execute(
                "SELECT COUNT(*) AS count FROM services WHERE run_id = ? AND state = 'open'",
                (run_id,),
            ).fetchone()["count"])

        requested_collectors = list(parse_json(run.get("collectors_json"), []))
        collector_sources = {
            "audit": {"audit.network"},
            "spy.network": {"spy.network"},
            "spy.wifi": {"spy.wifi"},
            "spy.bluetooth": {"spy.bluetooth"},
            "nmap": {"tool.nmap"},
            "masscan": {"tool.masscan"},
            "nikto": {"tool.nikto"},
            "theharvester": {"tool.theharvester"},
        }
        observed_sources = set(source_counts)
        collectors_with_observations = [
            collector for collector in requested_collectors
            if collector_sources.get(collector, {collector}) & observed_sources
        ]
        collectors_without_observations = sorted(set(requested_collectors) - set(collectors_with_observations))
        observation_coverage_ratio = round(
            len(collectors_with_observations) / len(requested_collectors), 2
        ) if requested_collectors else 0.0

        collector_result_items = self.get_collector_results(run_id)
        collector_status = {
            item["collector"]: item for item in collector_result_items
        }
        successful_collectors = sorted(
            collector for collector in requested_collectors
            if collector_status.get(collector, {}).get("status") == "success"
        )
        zero_object_collectors = sorted(
            collector for collector in successful_collectors
            if collector_status[collector].get("zero_objects")
        )
        skipped_collectors = sorted(
            collector for collector in requested_collectors
            if collector_status.get(collector, {}).get("status") == "skipped"
        )
        failed_collectors = sorted(
            collector for collector in requested_collectors
            if collector in collector_status
            and collector_status[collector].get("status") not in {"success", "skipped"}
        )
        collectors_without_status = sorted(
            set(requested_collectors) - set(collector_status)
        )
        coverage_ratio = (
            round(len(successful_collectors) / len(requested_collectors), 2)
            if requested_collectors and collector_result_items
            else observation_coverage_ratio
        )

        quality_warnings = []
        for collector in collectors_without_observations:
            if collector in zero_object_collectors:
                quality_warnings.append(
                    f"采集通道 {collector} 已成功完成但没有发现对象；零对象不等同于已证明安全。"
                )
            elif collector in failed_collectors:
                result_error = collector_status[collector].get("error") or "未提供错误详情"
                quality_warnings.append(
                    f"采集通道 {collector} 执行失败（{result_error}）；缺失数据不能解释为安全。"
                )
            elif collector in skipped_collectors:
                quality_warnings.append(
                    f"采集通道 {collector} 未执行；该通道不计为有效数据覆盖。"
                )
            else:
                quality_warnings.append(
                    f"采集通道 {collector} 没有产生结构化观测；这可能表示旧批次未记录状态、未发现对象或采集失败。"
                )
        for collector in collectors_without_status:
            if collector not in collectors_without_observations:
                quality_warnings.append(f"采集通道 {collector} 缺少完成状态记录。")
        if run.get("status") in {"partial", "failed"} and run.get("error"):
            quality_warnings.append(f"批次未完整成功：{run['error']}")
        if service_count == 0:
            quality_warnings.append("本批次未记录开放端口；0 分不等同于已证明安全，可能受网络隔离、防火墙或探测超时影响。")

        scored_assets.sort(key=lambda item: (-item["score"], item["identity_value"]))
        high_count = sum(1 for item in scored_assets if item["level"] in {"high", "critical"})
        overall_score = max((item["score"] for item in scored_assets), default=0.0)
        if high_count > 1:
            overall_score = min(10.0, overall_score + min(1.0, (high_count - 1) * 0.25))
        overall_score = round(overall_score, 2)
        return {
            "run_id": run_id,
            "baseline_id": changes["baseline_id"],
            "overall_score": overall_score,
            "overall_level": severity_for_score(overall_score),
            "asset_count": len(scored_assets),
            "high_or_critical_assets": high_count,
            "new_asset_count": len(changes["new_assets"]),
            "missing_asset_count": len(changes["missing_assets"]),
            "new_port_count": len(changes["opened_ports"]),
            "assets": scored_assets,
            "changes": changes,
            "data_quality": {
                "requested_collectors": requested_collectors,
                "observed_sources": source_counts,
                "collector_status": collector_status,
                "successful_collectors": successful_collectors,
                "zero_object_collectors": zero_object_collectors,
                "failed_collectors": failed_collectors,
                "skipped_collectors": skipped_collectors,
                "collectors_without_status": collectors_without_status,
                "collectors_with_observations": sorted(collectors_with_observations),
                "collectors_without_observations": collectors_without_observations,
                "coverage_ratio": coverage_ratio,
                "observation_coverage_ratio": observation_coverage_ratio,
                "open_service_records": service_count,
                "warnings": quality_warnings,
            },
            "methodology": {
                "score_range": "0-10",
                "facts": ["开放端口", "扫描器发现", "采集器标记", "跨批次变化"],
                "confidence_inputs": ["证据类型数量", "独立证据通道佐证", "历史重复", "结构化漏洞记录"],
                "warning": "威胁分用于排查优先级，不等同于已确认入侵或漏洞。",
            },
        }

    def persist_final_analysis_assets(self, run_id: str, assets: Sequence[Dict[str, Any]]) -> None:
        """持久化最终报告中的资产评分，使 SQLite 与外部分析返回结果一致。"""
        if not isinstance(assets, (list, tuple)):
            raise ValueError("最终资产评分必须是数组")
        with self.connect() as conn:
            valid_asset_ids = set(self._run_assets(conn, run_id))
            provided_asset_ids = set()
            for index, asset in enumerate(assets, start=1):
                if not isinstance(asset, dict):
                    raise ValueError(f"assets[{index}] 必须是对象")
                asset_id = asset.get("asset_id")
                if isinstance(asset_id, bool) or not isinstance(asset_id, int):
                    raise ValueError(f"assets[{index}].asset_id 必须是整数")
                if asset_id not in valid_asset_ids:
                    raise ValueError(f"assets[{index}].asset_id 不属于当前批次")
                if asset_id in provided_asset_ids:
                    raise ValueError(f"assets[{index}].asset_id 重复")
                provided_asset_ids.add(asset_id)
                score = asset.get("score")
                confidence = asset.get("confidence")
                level = asset.get("level")
                factors = asset.get("factors")
                if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= float(score) <= 10:
                    raise ValueError(f"assets[{index}].score 必须是 0 到 10 的数字")
                if not isinstance(level, str) or level != severity_for_score(float(score)):
                    raise ValueError(f"assets[{index}].level 与 score 不一致")
                if (
                    isinstance(confidence, bool)
                    or not isinstance(confidence, (int, float))
                    or not 0 <= float(confidence) <= 1
                ):
                    raise ValueError(f"assets[{index}].confidence 必须是 0 到 1 的数字")
                if not isinstance(factors, list):
                    raise ValueError(f"assets[{index}].factors 必须是数组")
                conn.execute(
                    """INSERT INTO threat_scores
                       (run_id, asset_id, score, level, confidence, factors_json)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(run_id, asset_id) DO UPDATE SET
                           score = excluded.score,
                           level = excluded.level,
                           confidence = excluded.confidence,
                           factors_json = excluded.factors_json""",
                    (
                        run_id, asset_id, round(float(score), 2), level,
                        round(float(confidence), 2), json_text(factors),
                    ),
                )

    def analysis_snapshot(self, run_id: str, built_in_analysis: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """导出与实现语言无关的分析输入，可交给 Java/C/C++ 可执行分析器。"""
        run = self.get_run(run_id)
        if not run:
            raise ValueError(f"未知扫描批次: {run_id}")
        with self.connect() as conn:
            assets = self._run_assets(conn, run_id)
            payload_assets = []
            for asset_id, asset in assets.items():
                observations = [
                    {
                        **dict(row),
                        "attributes": parse_json(row["attributes_json"], {}),
                        "evidence": parse_json(row["evidence_json"], {}),
                    }
                    for row in conn.execute(
                        "SELECT * FROM observations WHERE run_id = ? AND asset_id = ?",
                        (run_id, asset_id),
                    ).fetchall()
                ]
                services = [
                    {**dict(row), "attributes": parse_json(row["attributes_json"], {})}
                    for row in conn.execute(
                        "SELECT * FROM services WHERE run_id = ? AND asset_id = ?",
                        (run_id, asset_id),
                    ).fetchall()
                ]
                payload_assets.append({**asset, "observations": observations, "services": services})
        return {
            "contract_version": 1,
            "run": {**run, "collectors": parse_json(run.get("collectors_json"), [])},
            "changes": self.compare_runs(run_id),
            "assets": payload_assets,
            "built_in_analysis": built_in_analysis,
        }

    def analyze(self, run_id: str) -> Dict[str, Any]:
        """通过已配置的 Python 或外部 Java/C/C++ 后端分析批次。"""
        if __package__:
            from .analyzer_backend import analyze_with_backend
        else:
            import sys
            project_root = str(PROJECT_ROOT)
            if project_root not in sys.path:
                sys.path.insert(0, project_root)
            from source.analyzer_backend import analyze_with_backend
        return analyze_with_backend(self, run_id)

    def report(self, run_id: Optional[str] = None) -> Dict[str, Any]:
        run = self.get_run(run_id) if run_id else self.latest_run()
        if not run:
            raise ValueError("暂无扫描历史")
        analysis = self.analyze(run["id"])
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": utc_now(),
            "run": {
                **run,
                "collectors": parse_json(run.get("collectors_json"), []),
            },
            "analysis": analysis,
        }
