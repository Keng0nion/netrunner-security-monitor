#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可插拔威胁分析后端。

默认使用 Python 内置可解释规则分析器。设置 NETRUNNER_ANALYZER_CMD 后，
会把语言无关的 JSON 快照写入外部进程 stdin，允许 Java、C/C++ 或其它
本地可执行程序接管复杂评分。外部分析失败时始终回退到内置结果。
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from typing import Any, Dict, List

DEFAULT_TIMEOUT_SECONDS = 120.0
VALID_LEVELS = {"none", "low", "medium", "high", "critical"}


def _timeout_seconds() -> float:
    raw_value = os.environ.get("NETRUNNER_ANALYZER_TIMEOUT", "").strip()
    if not raw_value:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw_value)
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS
    return value if value > 0 else DEFAULT_TIMEOUT_SECONDS


def _level_for_score(score: float) -> str:
    if score >= 8.5:
        return "critical"
    if score >= 6.0:
        return "high"
    if score >= 3.0:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} 必须是 {minimum:g} 到 {maximum:g} 的数字")
    number = float(value)
    if not minimum <= number <= maximum:
        raise ValueError(f"{label} 必须位于 {minimum:g} 到 {maximum:g}")
    return number


def _validate_factors(value: Any, label: str) -> List[Dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError(f"{label} 必须是数组")
    factors: List[Dict[str, Any]] = []
    for index, factor in enumerate(value, start=1):
        if not isinstance(factor, dict):
            raise ValueError(f"{label}[{index}] 必须是对象")
        score = _number(factor.get("score"), f"{label}[{index}].score", 0, 10)
        title = factor.get("title")
        if not isinstance(title, str) or not title.strip():
            raise ValueError(f"{label}[{index}].title 必须是非空字符串")
        normalized = dict(factor)
        normalized["score"] = round(score, 2)
        normalized["title"] = title.strip()
        if not isinstance(normalized.get("rule_id"), str) or not normalized.get("rule_id", "").strip():
            normalized["rule_id"] = "external_analysis"
        if not isinstance(normalized.get("description"), str):
            normalized["description"] = "外部分析器提供的风险因素。"
        if not isinstance(normalized.get("evidence"), dict):
            normalized["evidence"] = {"fact": "external_analysis"}
        factors.append(normalized)
    return factors


def _validate_external_analysis(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("外部分析器 stdout 必须是 JSON 对象")

    missing = [key for key in ("overall_score", "overall_level", "assets") if key not in value]
    if missing:
        raise ValueError(f"外部分析结果缺少字段: {', '.join(missing)}")

    score = round(_number(value["overall_score"], "overall_score", 0, 10), 2)
    level_value = value["overall_level"]
    if not isinstance(level_value, str):
        raise ValueError("overall_level 必须是字符串")
    level = level_value.strip().lower()
    if level not in VALID_LEVELS:
        raise ValueError("overall_level 仅允许 none/low/medium/high/critical")
    if level != _level_for_score(score):
        raise ValueError("overall_level 与 overall_score 阈值不一致")

    raw_assets = value["assets"]
    if not isinstance(raw_assets, list):
        raise ValueError("assets 必须是数组")
    assets: List[Dict[str, Any]] = []
    seen_asset_ids = set()
    for index, asset in enumerate(raw_assets, start=1):
        label = f"assets[{index}]"
        if not isinstance(asset, dict):
            raise ValueError(f"{label} 必须是对象")
        asset_id = asset.get("asset_id")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id <= 0:
            raise ValueError(f"{label}.asset_id 必须是正整数")
        if asset_id in seen_asset_ids:
            raise ValueError(f"{label}.asset_id 重复")
        seen_asset_ids.add(asset_id)

        normalized: Dict[str, Any] = {"asset_id": asset_id}
        if "score" in asset:
            normalized["score"] = round(_number(asset["score"], f"{label}.score", 0, 10), 2)
        if "level" in asset:
            level_value = asset["level"]
            if not isinstance(level_value, str) or level_value.strip().lower() not in VALID_LEVELS:
                raise ValueError(f"{label}.level 仅允许 none/low/medium/high/critical")
            normalized["level"] = level_value.strip().lower()
        if "confidence" in asset:
            normalized["confidence"] = round(
                _number(asset["confidence"], f"{label}.confidence", 0, 1), 2
            )
        if "factors" in asset:
            normalized["factors"] = _validate_factors(asset["factors"], f"{label}.factors")
        if "label" in asset:
            if asset["label"] is not None and not isinstance(asset["label"], str):
                raise ValueError(f"{label}.label 必须是字符串或 null")
            normalized["label"] = asset["label"]
        assets.append(normalized)

    return {
        "overall_score": score,
        "overall_level": level,
        "assets": assets,
    }


def _merge_external_assets(
    built_in_assets: Any,
    external_assets: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not isinstance(built_in_assets, list):
        raise ValueError("内置分析 assets 结构无效")

    assets_by_id: Dict[int, Dict[str, Any]] = {}
    ordered_ids: List[int] = []
    for index, asset in enumerate(built_in_assets, start=1):
        if not isinstance(asset, dict):
            raise ValueError(f"内置分析 assets[{index}] 结构无效")
        asset_id = asset.get("asset_id")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int):
            raise ValueError(f"内置分析 assets[{index}].asset_id 结构无效")
        normalized = dict(asset)
        normalized.setdefault("identity_type", "unknown")
        normalized.setdefault("identity_value", str(asset_id))
        normalized.setdefault("label", None)
        normalized.setdefault("score", 0.0)
        normalized.setdefault("level", _level_for_score(float(normalized["score"])))
        normalized.setdefault("confidence", 0.0)
        normalized.setdefault("sources", [])
        normalized.setdefault("source_channels", [])
        normalized.setdefault("history_runs", 1)
        normalized.setdefault("factors", [])
        assets_by_id[asset_id] = normalized
        ordered_ids.append(asset_id)

    for patch in external_assets:
        asset_id = patch["asset_id"]
        if asset_id not in assets_by_id:
            raise ValueError(f"外部 assets 中的 asset_id {asset_id} 不属于当前批次")
        merged = {**assets_by_id[asset_id], **patch}
        score = round(_number(merged.get("score"), f"asset {asset_id}.score", 0, 10), 2)
        expected_level = _level_for_score(score)
        if "level" in patch and patch["level"] != expected_level:
            raise ValueError(f"asset {asset_id}.level 与 score 阈值不一致")
        merged["score"] = score
        merged["level"] = expected_level
        merged["confidence"] = round(
            _number(merged.get("confidence"), f"asset {asset_id}.confidence", 0, 1), 2
        )
        if not isinstance(merged.get("factors"), list):
            raise ValueError(f"asset {asset_id}.factors 必须是数组")
        assets_by_id[asset_id] = merged

    assets = [assets_by_id[asset_id] for asset_id in ordered_ids]
    assets.sort(key=lambda item: (-float(item["score"]), str(item["identity_value"])))
    return assets


def _fallback(built_in: Dict[str, Any], warning: str, command: str) -> Dict[str, Any]:
    result = dict(built_in)
    result["analysis_backend"] = {
        "type": "built_in",
        "fallback": True,
        "requested_command": command,
    }
    result["backend_warning"] = warning
    return result


def analyze_with_backend(store: Any, run_id: str) -> Dict[str, Any]:
    """分析指定批次；外部后端不可用时返回内置分析，不中断报告。"""
    built_in = store.analyze_run(run_id)
    command_text = os.environ.get("NETRUNNER_ANALYZER_CMD", "").strip()
    if not command_text:
        result = dict(built_in)
        result["analysis_backend"] = {"type": "built_in", "fallback": False}
        return result

    try:
        command = shlex.split(command_text)
        if not command:
            raise ValueError("NETRUNNER_ANALYZER_CMD 解析后为空")
        snapshot = store.analysis_snapshot(run_id, built_in)
        completed = subprocess.run(
            command,
            input=json.dumps(snapshot, ensure_ascii=False),
            capture_output=True,
            text=True,
            timeout=_timeout_seconds(),
            check=False,
        )
        if completed.returncode != 0:
            details = completed.stderr.strip() or completed.stdout.strip() or "无错误输出"
            raise RuntimeError(f"退出码 {completed.returncode}: {details}")
        external = _validate_external_analysis(json.loads(completed.stdout))
        assets = _merge_external_assets(built_in.get("assets"), external["assets"])

        result = dict(built_in)
        result["overall_score"] = external["overall_score"]
        result["overall_level"] = external["overall_level"]
        result["assets"] = assets
        result["asset_count"] = len(assets)
        result["high_or_critical_assets"] = sum(
            1 for asset in assets if asset["level"] in {"high", "critical"}
        )
        store.persist_final_analysis_assets(run_id, assets)
    except subprocess.TimeoutExpired:
        return _fallback(built_in, "外部分析器执行超时，已回退到内置分析。", command_text)
    except (OSError, ValueError, RuntimeError, TypeError, json.JSONDecodeError) as exc:
        return _fallback(built_in, f"外部分析器失败，已回退到内置分析: {exc}", command_text)

    result["analysis_backend"] = {
        "type": "external_process",
        "fallback": False,
        "command": command_text,
        "stderr": completed.stderr.strip() or None,
    }
    return result
