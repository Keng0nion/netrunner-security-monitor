#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETRUNNER 数据分析入口。

统一协调本地设备、WiFi、蓝牙、Nmap、Masscan、Nikto 和 TheHarvester，
把结果沉淀到 SQLite，再根据历史基线生成可解释的威胁优先级。
"""

from __future__ import annotations

import argparse
import contextlib
import json
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

if __package__:
    from .audit_engine import NetworkScanner
    from .data_platform import DataStore
    from .penetration_test import PenTestFramework, classify_target, collect_nmap_ports
else:
    project_root = str(Path(__file__).resolve().parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from source.audit_engine import NetworkScanner
    from source.data_platform import DataStore
    from source.penetration_test import PenTestFramework, classify_target, collect_nmap_ports

SOURCE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SOURCE_DIR.parent
SPY_SCRIPT = PROJECT_ROOT / "源码" / "spy_detector.js"

COLORS = {
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "cyan": "\x1b[36m",
    "bold": "\x1b[1m",
    "reset": "\x1b[0m",
}


def color(name: str, text: Any) -> str:
    return f"{COLORS.get(name, '')}{text}{COLORS['reset']}"


def info(message: str) -> None:
    print(f"  {color('green', '[*]')} {message}")


def warn(message: str) -> None:
    print(f"  {color('yellow', '[!]')} {message}", file=sys.stderr)


def validate_profile_target(profile: str, target: Optional[str]) -> Optional[str]:
    """验证统一入口的目标语义，避免把域名/CIDR 送进不兼容采集器。"""
    if profile == "home":
        if target is not None:
            raise ValueError("home 档位不接受 --target；它只分析本地网络")
        return None
    if profile not in {"quick", "full"}:
        raise ValueError(f"未知采集档位: {profile}")
    if not target:
        raise ValueError("quick/full 档位需要 --target")
    target_type = classify_target(target, allow_cidr=False)
    if profile == "full" and target_type != "ip":
        raise ValueError("full 档位仅接受单个授权 IPv4；域名可使用 quick 或独立 OSINT 入口")
    return target_type


def profile_collectors(profile: str, target: Optional[str]) -> List[str]:
    collectors = ["audit", "spy.network", "spy.wifi", "spy.bluetooth"]
    if profile in {"quick", "full"} and target:
        collectors.append("nmap")
    if profile == "full" and target:
        collectors.extend(["masscan", "nikto"])
    return collectors


def render_analysis(analysis: Dict[str, Any], limit: int = 15) -> None:
    level_colors = {
        "critical": "red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "none": "green",
    }
    level = analysis["overall_level"]
    print()
    print(color("bold", color("cyan", "数据威胁分析")))
    print(f"  综合威胁度: {color(level_colors.get(level, 'yellow'), f'{analysis['overall_score']}/10 {level.upper()}')}")
    print(f"  资产总数: {analysis['asset_count']}  高/严重资产: {analysis['high_or_critical_assets']}")
    print(
        f"  历史变化: 新资产 {analysis['new_asset_count']} / "
        f"消失 {analysis['missing_asset_count']} / 新端口 {analysis['new_port_count']}"
    )
    if analysis.get("baseline_id"):
        print(f"  对比基线: {analysis['baseline_id']}")
    else:
        print("  对比基线: 首次可比扫描，尚无历史基线")

    data_quality = analysis.get("data_quality") or {}
    if data_quality:
        print(f"  数据覆盖: {data_quality.get('coverage_ratio', 0):.0%}")
        for warning_message in data_quality.get("warnings") or []:
            print(color("yellow", f"  数据提示: {warning_message}"))

    assets = analysis.get("assets") or []
    prioritized_assets = [asset for asset in assets if float(asset.get("score", 0)) > 0]
    if not assets:
        print("  暂无可分析资产。")
        return
    if not prioritized_assets:
        print("  当前没有触发风险因素的资产；请结合上方数据覆盖提示判断结论强度。")
        print()
        print(color("yellow", "  注意：威胁度用于排查排序，不等同于已确认入侵或漏洞。"))
        return

    print()
    print(color("bold", "  高优先级资产:"))
    for asset in prioritized_assets[:limit]:
        asset_level = asset["level"]
        identity = f"{asset['identity_type']}:{asset['identity_value']}"
        print(
            f"  - {color(level_colors.get(asset_level, 'yellow'), f'{asset['score']:>4}/10')} "
            f"{identity}  置信度:{asset['confidence']:.0%}  历史:{asset['history_runs']}次"
        )
        for factor in asset.get("factors", [])[:3]:
            print(f"      · +{factor['score']}: {factor['title']}")
    print()
    print(color("yellow", "  注意：威胁度用于排查排序，不等同于已确认入侵或漏洞。"))


SPY_COLLECTORS = ("spy.network", "spy.wifi", "spy.bluetooth")
SPY_COMPLETION_STATUSES = {"success", "command_failed", "parse_failed"}


def _spy_failure_result(store: DataStore, run_id: str, message: str) -> Dict[str, Any]:
    for collector in SPY_COLLECTORS:
        store.record_collector_result(run_id, collector, "protocol_failed", error=message)
    return {
        "ok": False,
        "accepted": 0,
        "assets": 0,
        "errors": [message],
        "rejected": [message],
        "return_code": None,
        "collector_results": {},
        "successful_collectors": [],
    }


def run_spy_collector(
    store: DataStore,
    run: Dict[str, Any],
    timeout_seconds: float = 60,
) -> Dict[str, Any]:
    """流式读取 Node JSONL，并严格区分观测事件和采集器状态事件。"""
    node = shutil.which("node")
    if not node or not SPY_SCRIPT.is_file():
        return _spy_failure_result(store, run["id"], "spy: Node.js 或 spy_detector.js 不可用")

    command = [node, str(SPY_SCRIPT), "--jsonl", "--run-id", run["id"]]
    stdout_chunks: List[str] = []
    stderr_chunks: List[str] = []
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        return _spy_failure_result(store, run["id"], f"spy: 无法启动 Node 采集器: {exc}")

    def drain(stream: Any, destination: List[str]) -> None:
        if stream is None:
            return
        for chunk in iter(stream.readline, ""):
            destination.append(chunk)
        stream.close()

    stdout_thread = threading.Thread(
        target=drain, args=(process.stdout, stdout_chunks), daemon=True
    )
    stderr_thread = threading.Thread(
        target=drain, args=(process.stderr, stderr_chunks), daemon=True
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        return_code = process.wait()
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks)
    store.store_raw(run["id"], "spy", "spy_events.jsonl", stdout, "application/x-ndjson")
    store.store_raw(run["id"], "spy", "spy_diagnostics.txt", stderr, "text/plain")

    protocol_errors: List[str] = []
    collector_errors: Dict[str, List[str]] = {collector: [] for collector in SPY_COLLECTORS}
    started_collectors = set()
    completions: Dict[str, Dict[str, Any]] = {}
    observations: List[tuple[int, Dict[str, Any]]] = []
    observation_counts = {collector: 0 for collector in SPY_COLLECTORS}

    for line_number, line in enumerate(stdout.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            protocol_errors.append(f"spy JSONL line {line_number}: 非法 JSON: {exc}")
            continue
        if not isinstance(event, dict):
            protocol_errors.append(f"spy JSONL line {line_number}: 顶层必须是对象")
            continue
        if event.get("run_id") != run["id"]:
            protocol_errors.append(
                f"spy JSONL line {line_number}: run_id 不匹配，已拒绝该事件"
            )
            continue

        event_type = event.get("event_type")
        if event_type == "collector_status":
            collector = event.get("collector")
            if collector not in SPY_COLLECTORS:
                protocol_errors.append(
                    f"spy JSONL line {line_number}: 未知采集通道 {collector!r}"
                )
                continue
            if event.get("status") != "running":
                collector_errors[collector].append("collector_status 必须为 running")
            if collector in started_collectors:
                collector_errors[collector].append("重复 collector_status")
            started_collectors.add(collector)
            continue

        if event_type == "collector_complete":
            collector = event.get("collector")
            if collector not in SPY_COLLECTORS:
                protocol_errors.append(
                    f"spy JSONL line {line_number}: 未知完成通道 {collector!r}"
                )
                continue
            if collector in completions:
                collector_errors[collector].append("重复 collector_complete")
                continue
            status = event.get("status")
            object_count = event.get("object_count")
            zero_objects = event.get("zero_objects")
            if status not in SPY_COMPLETION_STATUSES:
                collector_errors[collector].append(f"非法完成状态 {status!r}")
            if isinstance(object_count, bool) or not isinstance(object_count, int) or object_count < 0:
                collector_errors[collector].append("object_count 必须是非负整数")
            if not isinstance(zero_objects, bool):
                collector_errors[collector].append("zero_objects 必须是布尔值")
            elif isinstance(object_count, int) and not isinstance(object_count, bool):
                expected_zero = status == "success" and object_count == 0
                if zero_objects != expected_zero:
                    collector_errors[collector].append("zero_objects 与状态/对象数不一致")
            if collector not in started_collectors:
                collector_errors[collector].append("缺少先行 collector_status")
            completions[collector] = event
            continue

        if event_type is not None:
            protocol_errors.append(
                f"spy JSONL line {line_number}: 未知 event_type {event_type!r}"
            )
            continue

        source = event.get("source")
        if source not in SPY_COLLECTORS:
            protocol_errors.append(
                f"spy JSONL line {line_number}: 观测 source 非法 {source!r}"
            )
            continue
        if source in completions:
            collector_errors[source].append("collector_complete 之后仍收到观测")
        observation_counts[source] += 1
        observations.append((line_number, event))

    for collector in SPY_COLLECTORS:
        completion = completions.get(collector)
        if completion is None:
            collector_errors[collector].append("缺少 collector_complete")
            continue
        object_count = completion.get("object_count")
        if isinstance(object_count, int) and not isinstance(object_count, bool):
            if object_count != observation_counts[collector]:
                collector_errors[collector].append(
                    f"object_count={object_count} 与实际观测数 {observation_counts[collector]} 不一致"
                )

    accepted = 0
    asset_ids = set()
    for line_number, event in observations:
        source = str(event.get("source"))
        try:
            asset_ids.add(store.ingest_event(event))
            accepted += 1
        except Exception as exc:
            collector_errors[source].append(f"line {line_number} 观测入库失败: {exc}")

    collector_results: Dict[str, Dict[str, Any]] = {}
    successful_collectors: List[str] = []
    for collector in SPY_COLLECTORS:
        completion = completions.get(collector) or {}
        completion_status = str(completion.get("status") or "protocol_failed")
        errors = collector_errors[collector]
        status = "protocol_failed" if errors else completion_status
        error = "; ".join(errors) or completion.get("error")
        object_count = observation_counts[collector]
        store.record_collector_result(
            run["id"], collector, status, object_count, error, details=completion
        )
        collector_results[collector] = {
            "status": status,
            "object_count": object_count,
            "zero_objects": status == "success" and object_count == 0,
            "error": error,
        }
        if status == "success":
            successful_collectors.append(collector)
        else:
            protocol_errors.append(f"{collector}: {error or status}")

    if timed_out:
        protocol_errors.append(
            f"spy: Node 采集器在 {timeout_seconds:g} 秒后超时；已保留超时前 JSONL"
        )
    if return_code != 0:
        protocol_errors.append(f"spy: Node 采集器退出码 {return_code}")
    protocol_errors = list(dict.fromkeys(protocol_errors))

    if stderr.strip():
        print(stderr.rstrip(), file=sys.stderr)
    return {
        "ok": not timed_out and return_code == 0 and not protocol_errors,
        "accepted": accepted,
        "assets": len(asset_ids),
        "errors": protocol_errors,
        "rejected": protocol_errors,
        "return_code": return_code,
        "timed_out": timed_out,
        "collector_results": collector_results,
        "successful_collectors": successful_collectors,
    }


def _tool_collection_outcome(
    store: DataStore,
    run_id: str,
    collector: str,
    result: Any,
    ingestion: Dict[str, Any],
) -> tuple[str, Optional[str]]:
    rejected = [str(item) for item in ingestion.get("rejected") or []]
    result_error = None
    details: Dict[str, Any]
    if isinstance(result, dict):
        return_code = result.get("return_code")
        timed_out = result.get("timed_out") is True or result.get("timeout") is True
        explicit_error = result.get("parse_error") or result.get("error")
        result_error = explicit_error or (
            result.get("stderr") if return_code not in {None, 0} else None
        )
        details = {
            key: result.get(key)
            for key in (
                "tool", "target", "domain", "return_code", "timestamp",
                "timed_out", "timeout", "parse_error", "error",
            )
            if result.get(key) is not None
        }
    else:
        return_code = None
        timed_out = False
        details = {"result_type": type(result).__name__}
    error_items = rejected + ([str(result_error)] if result_error else [])
    error = "; ".join(dict.fromkeys(item for item in error_items if item)) or None

    success = (
        isinstance(result, dict)
        and return_code == 0
        and not timed_out
        and not result.get("parse_error")
        and not result.get("error")
        and not rejected
    )
    if success:
        status = "success"
    elif timed_out:
        status = "timed_out"
    elif isinstance(result, dict) and result.get("parse_error"):
        status = "parse_failed"
    elif any("解析失败" in item for item in rejected):
        status = "parse_failed"
    else:
        status = "command_failed"
    store.record_collector_result(
        run_id,
        collector,
        status,
        int(ingestion.get("accepted", 0)),
        error,
        details=details,
    )
    return status, error


def collect_profile(
    store: DataStore,
    profile: str,
    target: Optional[str],
) -> Dict[str, Any]:
    validate_profile_target(profile, target)
    collectors = profile_collectors(profile, target)
    run = store.start_run(
        command="collect",
        mode=profile,
        target=target,
        collectors=collectors,
    )
    info(f"扫描批次: {run['id']}")
    info(f"原始证据目录: {run['raw_directory']}")

    errors: List[str] = []
    collector_states: Dict[str, str] = {}
    try:
        info("采集本地局域网设备、端口与服务...")
        scanner = NetworkScanner()
        devices = scanner.scan_network(target_ip=None)
        store.store_raw(run["id"], "audit", "audit_devices.json", devices)
        audit_devices: List[Dict[str, Any]] = [dict(device) for device in devices]
        audit_ingestion = store.ingest_audit_devices(run["id"], audit_devices)
        audit_errors = list(scanner.scan_errors) + list(audit_ingestion["rejected"])
        if not devices and not audit_errors:
            audit_errors.append("未产生任何设备扫描证据")
        if audit_errors:
            audit_status = "partial" if audit_ingestion["accepted"] else "command_failed"
            errors.extend(f"audit: {message}" for message in audit_errors)
        else:
            audit_status = "success"
        collector_states["audit"] = audit_status
        store.record_collector_result(
            run["id"], "audit", audit_status, int(audit_ingestion["accepted"]),
            "; ".join(audit_errors) or None,
            details={"scan_errors": list(scanner.scan_errors), "device_count": len(devices)},
        )

        info("采集周边网络、WiFi 与蓝牙观测...")
        spy_result = run_spy_collector(store, run)
        errors.extend(spy_result.get("errors") or [])
        for collector in SPY_COLLECTORS:
            state = (spy_result.get("collector_results") or {}).get(collector, {}).get("status")
            collector_states[collector] = str(state or "protocol_failed")

        if profile in {"quick", "full"} and target:
            framework = PenTestFramework()
            info("运行 Nmap 结构化端口与服务采集...")
            nmap_result = framework.nmap_scan(target, quick=(profile == "quick"))
            ingestion = store.ingest_tool_result(run["id"], "nmap", target, nmap_result)
            nmap_status, nmap_error = _tool_collection_outcome(
                store, run["id"], "nmap", nmap_result, ingestion
            )
            collector_states["nmap"] = nmap_status
            if nmap_status != "success":
                errors.append(f"nmap: {nmap_error or nmap_status}")

            if profile == "full":
                info("运行 Masscan 扩展端口采集...")
                masscan_result = framework.masscan_scan(target)
                ingestion = store.ingest_tool_result(run["id"], "masscan", target, masscan_result)
                masscan_status, masscan_error = _tool_collection_outcome(
                    store, run["id"], "masscan", masscan_result, ingestion
                )
                collector_states["masscan"] = masscan_status
                if masscan_status != "success":
                    errors.append(f"masscan: {masscan_error or masscan_status}")

                parsed_nmap = nmap_result.get("open_ports") if isinstance(nmap_result, dict) else None
                web_ports = sorted({
                    int(item["port"])
                    for item in collect_nmap_ports(parsed_nmap)
                    if str(item.get("port", "")).isdigit()
                    and int(str(item["port"])) in {80, 443, 8000, 8080, 8443}
                })
                if not web_ports:
                    collector_states["nikto"] = "skipped"
                    store.record_collector_result(
                        run["id"], "nikto", "skipped", 0,
                        "Nmap 未发现受支持的开放 Web 端口",
                        details={"supported_web_ports": [80, 443, 8000, 8080, 8443]},
                    )
                else:
                    nikto_successes = 0
                    nikto_objects = 0
                    nikto_errors: List[str] = []
                    for port in web_ports:
                        info(f"运行 Nikto Web 分析: {target}:{port}...")
                        nikto_result = framework.nikto_scan(target, port)
                        ingestion = store.ingest_tool_result(run["id"], "nikto", target, nikto_result)
                        nikto_objects += int(ingestion.get("accepted", 0))
                        rejected = [str(item) for item in ingestion.get("rejected") or []]
                        result_error = "结果类型无效"
                        if isinstance(nikto_result, dict):
                            return_code = nikto_result.get("return_code")
                            result_error = (
                                nikto_result.get("parse_error")
                                or nikto_result.get("error")
                                or (nikto_result.get("stderr") if return_code not in {None, 0} else None)
                            )
                        if (
                            isinstance(nikto_result, dict)
                            and nikto_result.get("return_code") == 0
                            and not result_error
                            and not rejected
                        ):
                            nikto_successes += 1
                        else:
                            nikto_errors.append(
                                f"端口 {port}: " + "; ".join(
                                    dict.fromkeys(rejected + ([str(result_error)] if result_error else []))
                                )
                            )
                    if nikto_successes == len(web_ports):
                        nikto_status = "success"
                    elif nikto_successes:
                        nikto_status = "partial"
                    elif any("解析失败" in item for item in nikto_errors):
                        nikto_status = "parse_failed"
                    else:
                        nikto_status = "command_failed"
                    collector_states["nikto"] = nikto_status
                    nikto_error = "; ".join(nikto_errors) or None
                    store.record_collector_result(
                        run["id"], "nikto", nikto_status, nikto_objects,
                        nikto_error, details={"ports": web_ports, "successful_ports": nikto_successes},
                    )
                    if nikto_status != "success":
                        errors.append(f"nikto: {nikto_error or nikto_status}")

        errors = list(dict.fromkeys(errors))
        requested_states = [collector_states.get(item, "not_completed") for item in collectors]
        if not errors and all(state in {"success", "skipped"} for state in requested_states):
            status = "complete"
        elif any(state == "success" for state in requested_states):
            status = "partial"
        else:
            status = "failed"
        store.finish_run(run["id"], status, "\n".join(errors) if errors else None)
        analysis = store.analyze(run["id"])
        return {
            "run": {
                **run,
                "status": status,
                "errors": errors,
                "collector_states": collector_states,
            },
            "analysis": analysis,
        }
    except KeyboardInterrupt:
        status = "partial" if any(value == "success" for value in collector_states.values()) else "failed"
        store.finish_run(run["id"], status, "用户中断")
        raise
    except Exception as exc:
        status = "partial" if any(value == "success" for value in collector_states.values()) else "failed"
        store.finish_run(run["id"], status, str(exc))
        raise


def command_collect(args: argparse.Namespace) -> int:
    try:
        validate_profile_target(args.profile, args.target)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    temporary = tempfile.TemporaryDirectory(prefix="netrunner-") if args.no_store else None
    try:
        store = DataStore(data_dir=Path(temporary.name)) if temporary else DataStore()
        output_context = contextlib.redirect_stdout(sys.stderr) if args.json else contextlib.nullcontext()
        with output_context:
            result = collect_profile(store, args.profile, args.target)
        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            render_analysis(result["analysis"])
            print(f"\n  批次状态: {result['run']['status']}")
            if args.no_store:
                print("  此次使用 --no-store，数据仅存在于临时隔离目录。")
            else:
                print(f"  数据库: {store.db_path}")
        return 0 if result["run"]["status"] != "failed" else 1
    finally:
        if temporary:
            temporary.cleanup()


def command_history(args: argparse.Namespace) -> int:
    store = DataStore()
    runs = store.list_runs(args.limit)
    if args.json:
        print(json.dumps(runs, ensure_ascii=False, indent=2))
        return 0
    if not runs:
        print("暂无扫描历史。")
        return 0
    print(color("bold", "扫描历史"))
    for run in runs:
        target = run.get("target") or "本地网络"
        print(f"  {run['started_at']}  {run['status']:<8} {run['mode']:<6} {target:<24} {run['id']}")
    return 0


def command_report(args: argparse.Namespace) -> int:
    store = DataStore()
    report = store.report(args.run_id)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"扫描批次: {report['run']['id']}  状态: {report['run']['status']}")
        render_analysis(report["analysis"], args.limit)
    return 0


def command_changes(args: argparse.Namespace) -> int:
    store = DataStore()
    run = store.get_run(args.run_id) if args.run_id else store.latest_run()
    if not run:
        raise SystemExit("暂无扫描历史")
    changes = store.compare_runs(run["id"], args.baseline)
    if args.json:
        print(json.dumps(changes, ensure_ascii=False, indent=2))
        return 0
    print(f"当前批次: {run['id']}")
    print(f"对比基线: {changes['baseline_id'] or '无'}")
    print(f"新增资产: {len(changes['new_assets'])}")
    for item in changes["new_assets"]:
        print(f"  + {item['identity_type']}:{item['identity_value']}")
    print(f"消失资产: {len(changes['missing_assets'])}")
    for item in changes["missing_assets"]:
        print(f"  - {item['identity_type']}:{item['identity_value']}")
    print(f"新开放端口: {len(changes['opened_ports'])}")
    for item in changes["opened_ports"]:
        print(f"  + {item['identity_value']} {item['protocol']}/{item['port']}")
    print(f"关闭端口: {len(changes['closed_ports'])}")
    for item in changes["closed_ports"]:
        print(f"  - {item['identity_value']} {item['protocol']}/{item['port']}")
    return 0


def command_baseline(args: argparse.Namespace) -> int:
    store = DataStore()
    store.set_baseline(args.run_id)
    print(f"已将 {args.run_id} 设置为同范围扫描的固定基线。")
    return 0


def command_alias(args: argparse.Namespace) -> int:
    store = DataStore()
    store.add_alias(args.asset_id, args.identity_type, args.identity_value)
    print(
        f"已将 {args.identity_type}:{args.identity_value} 关联到资产 {args.asset_id}。"
        "该关系可通过数据库管理进行修正，不会修改原始证据。"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NETRUNNER 本地历史数据与威胁分析",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 source/netrunner.py collect --profile home
  python3 source/netrunner.py collect --profile quick --target scanner.example.com
  python3 source/netrunner.py collect --profile full --target 192.168.1.20
  python3 source/netrunner.py report
  python3 source/netrunner.py changes
""",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    collect = subparsers.add_parser("collect", help="采集、入库并立即分析")
    collect.add_argument("--profile", choices=["home", "quick", "full"], default="home")
    collect.add_argument("--target", help="quick 支持单个 IPv4/FQDN；full 仅支持单个授权 IPv4")
    collect.add_argument("--no-store", action="store_true", help="只做本次分析，不保留历史")
    collect.add_argument("--json", action="store_true", help="输出 JSON 结果")
    collect.set_defaults(handler=command_collect)

    history = subparsers.add_parser("history", help="查看扫描历史")
    history.add_argument("--limit", type=int, default=20)
    history.add_argument("--json", action="store_true")
    history.set_defaults(handler=command_history)

    report = subparsers.add_parser("report", help="重新分析某个历史批次")
    report.add_argument("--run-id", help="默认使用最近批次")
    report.add_argument("--limit", type=int, default=15, help="显示前 N 个高优先级资产")
    report.add_argument("--json", action="store_true")
    report.set_defaults(handler=command_report)

    changes = subparsers.add_parser("changes", help="查看新增、消失与端口变化")
    changes.add_argument("--run-id", help="默认使用最近批次")
    changes.add_argument("--baseline", help="指定对比批次")
    changes.add_argument("--json", action="store_true")
    changes.set_defaults(handler=command_changes)

    baseline = subparsers.add_parser("baseline", help="设置固定安全基线")
    baseline.add_argument("run_id")
    baseline.set_defaults(handler=command_baseline)

    alias = subparsers.add_parser("alias", help="为长期资产添加受控身份别名")
    alias.add_argument("asset_id", type=int)
    alias.add_argument("identity_type", choices=["ip", "mac", "bssid", "bluetooth", "domain", "hostname", "ssid", "name"])
    alias.add_argument("identity_value")
    alias.set_defaults(handler=command_alias)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
