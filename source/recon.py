#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网络侦察兼容入口。

公开接口保持不变，实际工具执行统一复用 penetration_test.PenTestFramework，
避免 Nmap/Masscan/Nikto/TheHarvester 出现两套解析和数据格式。
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

if __package__ in {None, ''}:
    project_root = str(Path(__file__).resolve().parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

from source.data_platform import DataStore
from source.penetration_test import PenTestFramework, classify_target, failed_tool_result

COLORS = {
    'red': '\x1b[31m', 'green': '\x1b[32m', 'yellow': '\x1b[33m',
    'blue': '\x1b[34m', 'magenta': '\x1b[35m', 'cyan': '\x1b[36m',
    'bold': '\x1b[1m', 'reset': '\x1b[0m',
}


def color(name, text):
    return f"{COLORS.get(name, '')}{text}{COLORS['reset']}"


class ReconModule:
    """兼容原 ReconModule API，底层复用统一工具采集器。"""

    def __init__(self):
        self.framework = PenTestFramework()
        self.tools = self.framework.tools

    def get_tool_path(self, tool):
        return self.tools.get(tool)

    def nmap_scan(self, target, scan_type='sV', ports='1-10000'):
        return self.framework.nmap_scan(
            target,
            quick=True,
            ports=ports,
            scan_type=scan_type,
        )

    def parse_nmap_ports(self, output):
        return self.framework.parse_nmap_output(output).get('ports', [])

    def masscan_scan(self, target, ports='1-65535', rate='1000'):
        result = self.framework.masscan_scan(target, ports=ports, rate=rate)
        if result and 'open_ports' not in result:
            result['open_ports'] = result.get('ports', [])
        return result

    def theharvester_scan(self, domain, sources='google'):
        return self.framework.theharvester_scan(domain, sources=sources)

    def nikto_scan(self, target, port=80):
        return self.framework.nikto_scan(target, port)


def persist_results(target, scan_type, results):
    collectors = sorted(results) or ['recon']
    store = DataStore()
    run = store.start_run(
        command='legacy-recon',
        mode=f'recon-{scan_type}',
        target=target,
        collectors=collectors,
    )
    errors = []
    accepted = 0
    successful = 0
    attempted = 0
    for tool, result in results.items():
        attempted += 1
        if not isinstance(result, dict):
            errors.append(f'{tool}: 结果必须是对象')
            continue
        result_target = str(result.get('domain') or result.get('target') or target)
        if tool == 'nikto' and ':' in result_target:
            result_target = result_target.rsplit(':', 1)[0]
        ingestion = store.ingest_tool_result(run['id'], tool, result_target, result)
        accepted += ingestion['accepted']
        errors.extend(ingestion['rejected'])
        return_code = result.get('return_code')
        if return_code == 0 and not result.get('error') and not result.get('parse_error'):
            successful += 1
        else:
            errors.append(f"{tool}: {result.get('error') or result.get('parse_error') or f'退出码 {return_code}'}")
    if attempted and successful == attempted and accepted and not errors:
        status = 'complete'
    elif successful:
        status = 'partial'
    else:
        status = 'failed'
    error_text = '\n'.join(dict.fromkeys(errors)) if errors else None
    store.finish_run(run['id'], status, error_text)
    analysis = store.analyze(run['id'])
    analysis['run_status'] = status
    analysis['run_error'] = error_text
    return analysis


def main(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(description='网络侦察模块')
    parser.add_argument('target', help='目标 IP 或域名')
    parser.add_argument(
        '--type', '-t',
        choices=['nmap', 'masscan', 'nikto', 'theharvester', 'all'],
        default='all',
        help='扫描类型',
    )
    parser.add_argument('--domain', '-d', help='域名（用于 OSINT）')
    parser.add_argument('--no-store', action='store_true', help='不写入本地历史数据库')
    parser.add_argument('--json', action='store_true', help='仅输出结构化 JSON')
    args = parser.parse_args(argv)
    try:
        classify_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if args.domain is not None:
        try:
            if classify_target(args.domain, allow_cidr=False) != 'domain':
                raise ValueError('必须提供 FQDN 域名')
        except ValueError as exc:
            parser.error(f'--domain 无效: {exc}')
    if args.type == 'theharvester' and not args.domain:
        parser.error('--type theharvester 必须同时提供 --domain')
    if args.type not in {'all', 'theharvester'} and args.domain:
        parser.error(f'--domain 不能与 --type {args.type} 组合')

    recon = ReconModule()
    results = {}
    output_context = contextlib.redirect_stdout(sys.stderr) if args.json else contextlib.nullcontext()
    with output_context:
        if args.type in ['nmap', 'all']:
            results['nmap'] = recon.nmap_scan(args.target)
        if args.type in ['masscan', 'all']:
            results['masscan'] = recon.masscan_scan(args.target)
        if args.type in ['nikto', 'all']:
            results['nikto'] = recon.nikto_scan(args.target)
        if args.type in ['theharvester', 'all']:
            if args.domain:
                results['theharvester'] = recon.theharvester_scan(args.domain)
            else:
                results['theharvester'] = failed_tool_result(
                    'theharvester', args.target,
                    '未执行 TheHarvester：请使用 --domain 提供 FQDN 域名',
                    domain=args.target, structured_output={},
                )

    analysis = None
    if not args.no_store:
        analysis = persist_results(args.target, args.type, results)

    payload = {'target': args.target, 'domain': args.domain, 'results': results, 'analysis': analysis}
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for tool, result in results.items():
            print(f"\n{color('bold', f'{tool} 结果:')}")
            print(json.dumps(result, indent=2, ensure_ascii=False))
        if analysis:
            print(
                f"\n{color('cyan', '[数据分析]')} 综合威胁度: "
                f"{analysis['overall_score']}/10 ({analysis['overall_level']})"
            )
            print(f"历史批次已保存到: {Path(DataStore().db_path)}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
