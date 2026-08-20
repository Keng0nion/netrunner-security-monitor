#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整渗透测试框架 — 集成 nmap/masscan/nikto/theharvester
用于：授权的安全测试、教学实验、靶场练习

用法:
    python3 penetration_test.py <目标IP>              # 完整扫描
    python3 penetration_test.py <目标IP> --quick      # 快速扫描
    python3 penetration_test.py <目标IP> --nmap-only  # 仅 nmap
    python3 penetration_test.py <目标IP> --nikto-only # 仅 Web 扫描
    python3 penetration_test.py <域名> --osint        # OSINT 信息收集
"""

import sys
import argparse
import contextlib
import hashlib
import json
import subprocess
import re
import os
import shlex
import shutil
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from datetime import datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Optional

# 颜色定义
COLORS = {
    'red': '\x1b[31m', 'green': '\x1b[32m', 'yellow': '\x1b[33m',
    'blue': '\x1b[34m', 'magenta': '\x1b[35m', 'cyan': '\x1b[36m',
    'bold': '\x1b[1m', 'reset': '\x1b[0m',
}

def color(c, t):
    return f"{COLORS.get(c, '')}{t}{COLORS.get('reset', '')}"

def section(title):
    w = 60
    box_top = color("cyan", "╔" + "═"*(w-2) + "╗")
    box_mid = color("cyan", "║" + title.center(w-2) + "║")
    box_bot = color("cyan", "╚" + "═"*(w-2) + "╗")
    print(f'\n{box_top}\n{box_mid}\n{box_bot}\n')

def info(msg):   print(f"  {color('green', '[*]')} {msg}")
def warn(msg):   print(f"  {color('yellow', '[!]')} {msg}")
def alert(msg):  print(f"  {color('red', '[?]')} {msg}")
def ok(msg):     print(f"  {color('bold', '[✓]')} {msg}")

def run_cmd(
    cmd: Sequence[str | os.PathLike[str]], timeout: float = 60
) -> tuple[str, str, int]:
    """仅使用参数序列运行命令，拒绝 shell 字符串入口。"""
    if isinstance(cmd, (str, bytes)) or not isinstance(cmd, Sequence):
        raise TypeError('cmd 必须是非字符串参数序列')
    if not cmd:
        raise ValueError('cmd 参数序列不能为空')
    if any(not isinstance(arg, (str, os.PathLike)) for arg in cmd):
        raise TypeError('cmd 中的每个参数都必须是字符串或路径')
    try:
        result = subprocess.run(
            list(cmd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return '', '超时', 124
    except Exception as e:
        return '', str(e), 1

def check_tool(tool):
    """检查工具是否可用"""
    return shutil.which(tool) is not None

def get_tool_path(tool):
    """获取工具路径"""
    return shutil.which(tool)


_FQDN_LABEL = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


def classify_target(target, *, allow_domain=True, allow_cidr=True):
    """严格验证并分类 IPv4、IPv4 CIDR 或 FQDN。"""
    if not isinstance(target, str):
        raise ValueError('目标必须是字符串')
    if not target or target != target.strip():
        raise ValueError('目标不能为空或包含首尾空白')
    if target.startswith('-'):
        raise ValueError('目标不能以 - 开头')
    if any(ord(char) < 32 or ord(char) == 127 for char in target):
        raise ValueError('目标不能包含控制字符')
    if any(char.isspace() for char in target):
        raise ValueError('目标不能包含空白字符')
    if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', target):
        raise ValueError('目标不能包含 URL scheme')

    if '/' in target:
        if not allow_cidr:
            raise ValueError('此扫描不接受 CIDR 目标')
        try:
            network = ip_network(target, strict=False)
        except ValueError as exc:
            raise ValueError('非法 IP/CIDR') from exc
        if network.version != 4:
            raise ValueError('仅支持 IPv4 CIDR')
        return 'cidr'

    try:
        address = ip_address(target)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise ValueError('仅支持 IPv4 地址')
        return 'ip'

    if not allow_domain:
        raise ValueError('此扫描仅接受 IPv4 或 IPv4 CIDR，不能使用域名')
    if re.fullmatch(r'[0-9.]+', target):
        raise ValueError('非法 IPv4 地址')
    candidate = target[:-1] if target.endswith('.') else target
    if not candidate or len(candidate) > 253 or '.' not in candidate:
        raise ValueError('非法 FQDN')
    labels = candidate.split('.')
    if any(not _FQDN_LABEL.fullmatch(label) for label in labels):
        raise ValueError('非法 FQDN')
    return 'domain'


def safe_target_component(target):
    """把任意已验证目标转换为不含路径语义的短文件名片段。"""
    value = str(target)
    safe = re.sub(r'[^A-Za-z0-9._-]+', '_', value)
    while '..' in safe:
        safe = safe.replace('..', '_')
    safe = re.sub(r'_+', '_', safe).strip('._-')[:80] or 'target'
    if safe != value:
        digest = hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]
        safe = f'{safe}_{digest}'
    return safe


def empty_nmap_result():
    return {'hosts': [], 'ports': [], 'os': None, 'hostnames': [], 'addresses': []}


def failed_tool_result(tool, target, error, return_code=2, **extra):
    """建立所有外部工具共用的结构化失败契约。"""
    result = {
        'tool': tool,
        'target': target,
        'return_code': return_code if return_code else 1,
        'error': str(error),
        'output': '',
        'stderr': str(error),
        'timestamp': datetime.now().isoformat(),
    }
    result.update(extra)
    return result


def collect_nmap_ports(parsed):
    """从单主机兼容顶层或 hosts[] 汇总端口。"""
    if not isinstance(parsed, dict):
        return []
    hosts = parsed.get('hosts')
    if isinstance(hosts, list) and hosts:
        return [
            port
            for host in hosts
            if isinstance(host, dict)
            for port in host.get('ports', [])
            if isinstance(port, dict)
        ]
    return [port for port in parsed.get('ports', []) if isinstance(port, dict)]


class PenTestFramework:
    """渗透测试框架"""

    def __init__(self):
        self.results: dict[str, dict[str, Any]] = {}
        self.tools = {
            'nmap': get_tool_path('nmap'),
            'masscan': get_tool_path('masscan'),
            'nikto': get_tool_path('nikto'),
            'theharvester': get_tool_path('theharvester'),
        }

    def nmap_scan(self, target, quick=False, ports=None, scan_type=None):
        """
        Nmap 扫描
        - 快速模式：SYN 扫描 + 服务版本 + OS 指纹
        - 完整模式：深度扫描
        """
        try:
            classify_target(target)
        except ValueError as exc:
            result = failed_tool_result('nmap', target, f'无效目标: {exc}', open_ports=empty_nmap_result())
            self.results['nmap'] = result
            return result
        if not self.tools['nmap']:
            warn("nmap 未安装")
            result = failed_tool_result('nmap', target, 'nmap 未安装', return_code=127, open_ports=empty_nmap_result())
            self.results['nmap'] = result
            return result

        default_quick_ports = '21,22,23,25,53,80,110,139,143,443,445,993,995,554,1433,3306,3389,5432,5900,6379,8080,8443,27017'
        selected_ports = ports or (default_quick_ports if quick else '1-65535')
        cmd = [self.tools['nmap'], '-sT', '-sV', '-T4', '-p', selected_ports]
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            cmd.append('-O')
        if not quick:
            cmd.append('--script=vuln')
        if scan_type and scan_type not in {'sT', 'sV'}:
            warn(f"扫描类型 {scan_type} 由统一采集器按非特权安全模式执行")
        cmd.extend(['-oX', '-', target])
        info("快速 Nmap XML 采集" if quick else "完整 Nmap XML 采集（全端口 + 漏洞脚本）")
        info(f"目标: {target}")
        info(f"命令: {shlex.join(cmd)}")

        stdout, stderr, rc = run_cmd(cmd, timeout=300)

        result: dict[str, Any] = {
            'tool': 'nmap',
            'target': target,
            'return_code': rc,
            'output': stdout,
            'stderr': stderr,
            'timestamp': datetime.now().isoformat(),
        }
        if rc != 0:
            result['error'] = stderr.strip() or f'nmap 退出码 {rc}'

        # 解析端口；文本回退没有地址信息时，用已验证扫描目标补足主机身份。
        parsed = self.parse_nmap_output(stdout)
        if len(parsed.get('hosts', [])) == 1:
            host = parsed['hosts'][0]
            if not host.get('addresses') and not host.get('hostnames'):
                target_type = classify_target(target)
                if target_type == 'ip':
                    host['addresses'] = [{'address': target, 'type': 'ipv4', 'vendor': None}]
                elif target_type == 'domain':
                    host['hostnames'] = [target.rstrip('.')]
        result['open_ports'] = parsed

        self.results['nmap'] = result
        return result

    def parse_nmap_output(self, output):
        """优先按主机解析 Nmap XML，兼容旧的人类可读文本。"""
        if not isinstance(output, str):
            return {**empty_nmap_result(), 'parse_error': 'Nmap 输出必须是字符串'}
        try:
            root = ET.fromstring(output)
            hosts = []
            for host_node in root.findall('host'):
                addresses = []
                hostnames = []
                ports = []
                os_info = None
                for address in host_node.findall('address'):
                    if address.get('addr'):
                        addresses.append({
                            'address': address.get('addr'),
                            'type': address.get('addrtype'),
                            'vendor': address.get('vendor'),
                        })
                for hostname in host_node.findall('./hostnames/hostname'):
                    if hostname.get('name'):
                        hostnames.append(hostname.get('name'))
                os_match = host_node.find('./os/osmatch')
                if os_match is not None:
                    os_info = os_match.get('name')
                for port_node in host_node.findall('./ports/port'):
                    state = port_node.find('state')
                    if state is None or state.get('state') != 'open':
                        continue
                    port_id = port_node.get('portid')
                    if not port_id or not port_id.isdigit():
                        continue
                    service = port_node.find('service')
                    product = service.get('product', '') if service is not None else ''
                    version = service.get('version', '') if service is not None else ''
                    extra = service.get('extrainfo', '') if service is not None else ''
                    ports.append({
                        'port': int(port_id),
                        'protocol': port_node.get('protocol', 'tcp'),
                        'state': 'open',
                        'service': service.get('name', 'unknown') if service is not None else 'unknown',
                        'product': product,
                        'version': ' '.join(part for part in [product, version, extra] if part),
                    })
                hosts.append({
                    'addresses': addresses,
                    'hostnames': hostnames,
                    'os': os_info,
                    'ports': ports,
                })
            result = {**empty_nmap_result(), 'hosts': hosts}
            if len(hosts) == 1:
                result.update({
                    'ports': hosts[0]['ports'],
                    'os': hosts[0]['os'],
                    'hostnames': hosts[0]['hostnames'],
                    'addresses': hosts[0]['addresses'],
                })
            elif hosts:
                result['ports'] = collect_nmap_ports(result)
            return result
        except (ET.ParseError, TypeError, ValueError):
            pass

        ports = []
        os_info = None
        for line in output.splitlines():
            match = re.match(r'^\s*(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*\S))?\s*$', line, re.IGNORECASE)
            if match:
                ports.append({
                    'port': int(match.group(1)),
                    'protocol': match.group(2).lower(),
                    'state': 'open',
                    'service': match.group(3),
                    'version': match.group(4) or '',
                })
            stripped = line.strip()
            lower_line = stripped.lower()
            if lower_line.startswith(('os details:', 'running:', 'aggressive os guesses:')):
                os_info = stripped.split(':', 1)[1].strip() if ':' in stripped else stripped
        host = {'ports': ports, 'os': os_info, 'hostnames': [], 'addresses': []}
        return {'hosts': [host] if ports or os_info else [], **host}

    def parse_masscan_output(self, data):
        """解析 Masscan JSON；顶层和字段类型不合法时抛出明确错误。"""
        if not isinstance(data, list):
            raise ValueError('Masscan JSON 顶层必须是数组')
        parsed_ports = []
        for host_index, host in enumerate(data):
            if not isinstance(host, dict):
                raise ValueError(f'Masscan host[{host_index}] 必须是对象')
            host_ip = host.get('ip')
            host_ports = host.get('ports', [])
            if host.get('port') is not None:
                host_ports = [host]
            if not isinstance(host_ports, list):
                raise ValueError(f'Masscan host[{host_index}].ports 必须是数组')
            for port_index, port_info in enumerate(host_ports):
                if not isinstance(port_info, dict):
                    raise ValueError(f'Masscan host[{host_index}].ports[{port_index}] 必须是对象')
                port_value = port_info.get('port')
                if isinstance(port_value, bool) or not str(port_value).isdigit():
                    raise ValueError(f'Masscan host[{host_index}].ports[{port_index}].port 非法')
                service_value = port_info.get('service', 'unknown')
                if isinstance(service_value, dict):
                    service_name = service_value.get('name', 'unknown')
                elif isinstance(service_value, str):
                    service_name = service_value
                else:
                    raise ValueError(f'Masscan host[{host_index}].ports[{port_index}].service 类型非法')
                parsed_ports.append({
                    'port': int(str(port_value)),
                    'protocol': str(port_info.get('proto', 'tcp')).lower(),
                    'state': str(port_info.get('status', 'open')).lower(),
                    'service': service_name,
                    'ip': host_ip,
                })
        return parsed_ports

    def masscan_scan(self, target, ports='1-10000', rate='1000'):
        """Masscan 高速扫描；仅接受 IPv4 或 IPv4 CIDR。"""
        try:
            classify_target(target, allow_domain=False)
        except ValueError as exc:
            result = failed_tool_result('masscan', target, f'无效 Masscan 目标: {exc}', ports=[])
            self.results['masscan'] = result
            return result
        if not self.tools['masscan']:
            warn("masscan 未安装")
            result = failed_tool_result('masscan', target, 'masscan 未安装', return_code=127, ports=[])
            self.results['masscan'] = result
            return result

        with tempfile.TemporaryDirectory(prefix='netrunner-masscan-') as temp_dir:
            output_path = os.path.join(temp_dir, 'masscan.json')
            cmd = [self.tools['masscan'], '-p', ports, '--rate', str(rate), target, '-oJ', output_path]
            info(f"Masscan 高速扫描: {target}")
            info(f"命令: {shlex.join(cmd)}")
            stdout, stderr, rc = run_cmd(cmd, timeout=60)

            result: dict[str, Any] = {
                'tool': 'masscan',
                'target': target,
                'return_code': rc,
                'output': stdout,
                'stderr': stderr,
                'timestamp': datetime.now().isoformat(),
                'ports': [],
            }
            try:
                with open(output_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                result['ports'] = self.parse_masscan_output(data)
                result['structured_output'] = data
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                result['parse_error'] = f'Masscan 输出解析失败: {exc}'
                result['error'] = result.get('error') or result['parse_error']
                if result['return_code'] == 0:
                    result['return_code'] = 2
            if rc != 0:
                result['error'] = stderr.strip() or f'masscan 退出码 {rc}'

        self.results['masscan'] = result
        return result

    def nikto_scan(self, target, port=80):
        """Nikto Web 漏洞扫描"""
        try:
            classify_target(target, allow_cidr=False)
        except ValueError as exc:
            result = failed_tool_result(
                'nikto', f'{target}:{port}', f'无效 Nikto 目标: {exc}',
                vulnerabilities=[], vuln_count=0,
            )
            self.results[f'nikto_{port}'] = result
            self.results['nikto'] = result
            return result
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            result = failed_tool_result(
                'nikto', f'{target}:{port}', 'Nikto 端口必须是 1-65535 的整数',
                vulnerabilities=[], vuln_count=0,
            )
            self.results[f'nikto_{port}'] = result
            self.results['nikto'] = result
            return result
        if not self.tools['nikto']:
            warn("nikto 未安装")
            result = failed_tool_result(
                'nikto', f'{target}:{port}', 'nikto 未安装', return_code=127,
                vulnerabilities=[], vuln_count=0,
            )
            self.results[f'nikto_{port}'] = result
            self.results['nikto'] = result
            return result

        with tempfile.TemporaryDirectory(prefix='netrunner-nikto-') as temp_dir:
            output_path = os.path.join(temp_dir, f'nikto_{port}.json')
            cmd = [self.tools['nikto'], '-h', target, '-p', str(port), '-Format', 'json', '-output', output_path]
            info(f"Nikto Web 扫描: {target}:{port}")
            info(f"命令: {shlex.join(cmd)}")
            stdout, stderr, rc = run_cmd(cmd, timeout=180)

            result: dict[str, Any] = {
                'tool': 'nikto',
                'target': f"{target}:{port}",
                'return_code': rc,
                'output': stdout,
                'stderr': stderr,
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': [],
                'vuln_count': 0,
            }
            try:
                with open(output_path, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                if not isinstance(data, dict):
                    raise ValueError('Nikto JSON 顶层必须是对象')
                vulnerabilities = data.get('test') or data.get('vulnerabilities') or []
                if not isinstance(vulnerabilities, list):
                    raise ValueError('Nikto vulnerabilities/test 必须是数组')
                invalid_items = [index for index, item in enumerate(vulnerabilities) if not isinstance(item, dict)]
                if invalid_items:
                    raise ValueError(f'Nikto 漏洞项必须是对象，非法索引: {invalid_items}')
                result['vulnerabilities'] = vulnerabilities
                result['vuln_count'] = len(vulnerabilities)
                counts = {'high': 0, 'medium': 0, 'low': 0}
                for vulnerability in vulnerabilities:
                    severity = str(vulnerability.get('severity', '')).lower()
                    if severity in counts:
                        counts[severity] += 1
                result['vuln_summary'] = counts
                result['structured_output'] = data
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                result['parse_error'] = f'Nikto 输出解析失败: {exc}'
                result['error'] = result.get('error') or result['parse_error']
                if result['return_code'] == 0:
                    result['return_code'] = 2
            if rc != 0:
                result['error'] = stderr.strip() or f'nikto 退出码 {rc}'

        # BUG FIX: 原来无条件覆盖 self.results['nikto']。
        # 完整扫描时会对多个 Web 端口依次调用 nikto_scan()，
        # 每次都会把上一个端口的结果覆盖掉，最终只保留最后一个端口的结果。
        # 改成按 "nikto_端口号" 存放，同时保留 self.results['nikto']
        # 指向最近一次结果，兼容其它读取 self.results['nikto'] 的代码。
        self.results[f'nikto_{port}'] = result
        self.results['nikto'] = result
        return result

    def theharvester_scan(self, domain, sources='google,bing'):
        """TheHarvester OSINT 扫描"""
        try:
            target_type = classify_target(domain, allow_cidr=False)
            if target_type != 'domain':
                raise ValueError('TheHarvester 需要 FQDN 域名')
        except ValueError as exc:
            result = failed_tool_result('theharvester', domain, f'无效域名: {exc}', domain=domain, structured_output={})
            self.results['theharvester'] = result
            return result
        if not self.tools['theharvester']:
            warn("theharvester 未安装")
            result = failed_tool_result(
                'theharvester', domain, 'theharvester 未安装', return_code=127,
                domain=domain, structured_output={},
            )
            self.results['theharvester'] = result
            return result

        with tempfile.TemporaryDirectory(prefix='netrunner-harvester-') as temp_dir:
            output_base = os.path.join(temp_dir, 'theharvester')
            cmd = [self.tools['theharvester'], '-d', domain, '-b', sources, '-f', output_base]
            info(f"OSINT 扫描: {domain}")
            info(f"命令: {shlex.join(cmd)}")
            stdout, stderr, rc = run_cmd(cmd, timeout=60)

            structured = {}
            for candidate in [output_base, f'{output_base}.json']:
                try:
                    with open(candidate, 'r', encoding='utf-8') as file:
                        structured = json.load(file)
                    break
                except (OSError, json.JSONDecodeError):
                    continue
            result: dict[str, Any] = {
                'tool': 'theharvester',
                'target': domain,
                'domain': domain,
                'return_code': rc,
                'output': stdout,
                'stderr': stderr,
                'structured_output': structured,
                'timestamp': datetime.now().isoformat(),
            }
            if rc != 0:
                result['error'] = stderr.strip() or f'theharvester 退出码 {rc}'

        self.results['theharvester'] = result
        return result

    def generate_report(self, target):
        """生成综合报告"""
        report: dict[str, Any] = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_ports': 0,
                'open_ports': 0,
                'vulnerabilities': 0,
                'risk_level': '未知',
            },
            'data': self.results,
        }

        # 汇总统计
        nmap_ports = []
        masscan_ports = []
        if 'nmap' in self.results:
            nmap = self.results['nmap']
            nmap_ports = collect_nmap_ports(nmap.get('open_ports'))
        if 'masscan' in self.results and isinstance(self.results['masscan'], dict):
            masscan_ports = [
                port for port in self.results['masscan'].get('ports', [])
                if isinstance(port, dict) and port.get('state', 'open') == 'open'
            ]
        observed_ports = nmap_ports + masscan_ports
        unique_ports = {
            (str(port.get('ip') or ''), str(port.get('protocol') or 'tcp'), port.get('port'))
            for port in observed_ports
            if port.get('port') is not None
        }
        report['summary']['total_ports'] = len(unique_ports)
        report['summary']['open_ports'] = report['summary']['total_ports']

        # BUG FIX: 之前只看 self.results['nikto']（被多端口扫描覆盖后只剩最后一个）。
        # 现在把所有 nikto_<port> 的结果加总，避免漏掉前面端口的漏洞数。
        nikto_keys = [k for k in self.results if k == 'nikto' or k.startswith('nikto_')]
        seen = set()
        total_vulns = 0
        for k in nikto_keys:
            r = self.results[k]
            marker = r.get('target')
            if marker in seen:
                continue
            seen.add(marker)
            total_vulns += r.get('vuln_count', 0)
        report['summary']['vulnerabilities'] = total_vulns

        # 计算风险等级
        vulns = report['summary']['vulnerabilities']
        open_ports = report['summary']['open_ports']

        sensitive_ports = {21, 22, 23, 445, 554, 3306, 3389, 5900, 6379, 27017}
        exposed_sensitive = sorted({
            int(str(port.get('port'))) for port in observed_ports
            if str(port.get('port')).isdigit() and int(str(port.get('port'))) in sensitive_ports
        })
        report['summary']['sensitive_ports'] = exposed_sensitive
        successful_evidence = any(
            isinstance(result, dict) and result.get('return_code') == 0
            for result in self.results.values()
        )

        if vulns > 5 or 23 in exposed_sensitive:
            report['summary']['risk_level'] = '高风险'
        elif vulns > 0 or exposed_sensitive:
            report['summary']['risk_level'] = '中风险'
        elif open_ports > 10:
            report['summary']['risk_level'] = '低风险'
        else:
            report['summary']['risk_level'] = '未发现已知风险'
            if not successful_evidence:
                report['summary']['evidence_status'] = '不足'

        # 保存报告
        report_file = f"report_{safe_target_component(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        info(f"报告已保存: {report_file}")
        return report

    def print_summary(self, target):
        """打印扫描摘要"""
        section(f'渗透测试报告 — {target}')

        print(f"\n{color('bold', '扫描摘要:')}")
        print(f"  目标: {target}")
        print(f"  时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if 'nmap' in self.results:
            nmap = self.results['nmap']
            ports = collect_nmap_ports(nmap.get('open_ports'))
            print(f"\n{color('bold', '开放端口:')}")
            for p in ports[:20]:  # 只显示前 20 个
                version = f" ({p.get('version', '')})" if p.get('version') else ''
                port_num = p.get('port')
                svc = p.get('service', 'unknown')
                print(f"  {color('green', f'端口 {port_num}/tcp')}: {svc}{version}")

            os_info = nmap.get('open_ports', {}).get('os')
            if os_info:
                print(f"\n{color('bold', '操作系统:')} {os_info}")

        nikto_keys = [k for k in self.results if k == 'nikto' or k.startswith('nikto_')]
        if nikto_keys:
            # BUG FIX: 原来只读 self.results['nikto']，多端口扫描时只能看到
            # 最后一个端口的结果。现在把每个端口分别列出来。
            seen = set()
            print(f"\n{color('bold', 'Web 漏洞:')}")
            for k in nikto_keys:
                nikto = self.results[k]
                marker = nikto.get('target')
                if marker in seen:
                    continue
                seen.add(marker)
                vuln_count = nikto.get('vuln_count', 0)
                vuln_summary = nikto.get('vuln_summary', {})
                print(f"  [{marker}] 总数: {vuln_count}", end='')
                if vuln_summary:
                    print(f"  严重:{color('red', str(vuln_summary.get('high', 0)))} "
                          f"中等:{color('yellow', str(vuln_summary.get('medium', 0)))} "
                          f"低危:{color('blue', str(vuln_summary.get('low', 0)))}")
                else:
                    print()

        if 'masscan' in self.results:
            masscan = self.results['masscan']
            ports = masscan.get('ports', [])
            if ports:
                print(f"\n{color('bold', 'Masscan 发现端口:')} {len(ports)} 个")
                for p in ports[:10]:
                    print(f"  端口 {p.get('port')}: {p.get('service', 'unknown')}")

        if 'theharvester' in self.results:
            print(f"\n{color('bold', 'OSINT 信息:')}")
            print(f"  域名: {target if not re.match(r'\d+\.\d+\.\d+\.\d+', target) else 'N/A'}")

        # 风险评估
        report = self.generate_report(target)
        risk = report['summary']['risk_level']
        risk_color = {
            '高风险': 'red', '中风险': 'yellow', '低风险': 'blue',
            '未发现已知风险': 'green', '证据不足': 'yellow',
        }.get(risk, 'white')
        print(f"\n{color('bold', '风险等级:')} {color(risk_color, risk)}")


def persist_results(target, mode, results):
    """把旧 CLI 的采集结果写入统一历史库并返回数据威胁分析。"""
    if __package__:
        from .data_platform import DataStore
    else:
        project_root = str(Path(__file__).resolve().parent.parent)
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from source.data_platform import DataStore

    store = DataStore()
    collectors = sorted({key.split('_', 1)[0] for key, value in results.items() if value})
    run = store.start_run(
        command='legacy-pentest',
        mode=mode,
        target=target,
        collectors=collectors or ['pentest'],
    )
    run_id = run.get('id')
    if not isinstance(run_id, str) or not run_id:
        raise RuntimeError('数据存储未返回有效的运行 ID')
    accepted = 0
    errors = []
    successful = 0
    attempted = 0
    seen_results = set()
    for key, result in results.items():
        if not result or id(result) in seen_results:
            continue
        seen_results.add(id(result))
        attempted += 1
        if not isinstance(result, dict):
            errors.append(f'{key}: 结果必须是对象')
            continue
        tool = str(result.get('tool') or key.split('_', 1)[0])
        result_target = str(result.get('domain') or result.get('target') or target)
        if tool == 'nikto' and ':' in result_target:
            result_target = result_target.rsplit(':', 1)[0]
        ingestion = store.ingest_tool_result(run_id, tool, result_target, result)
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
    store.finish_run(run_id, status, error_text)
    run = {**run, 'id': run_id, 'status': status, 'error': error_text}
    return store, run, store.analyze(run_id)


def main(argv: Optional[Sequence[str]] = None):
    parser = argparse.ArgumentParser(
        description='渗透测试框架 — 授权的安全测试工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 penetration_test.py 192.168.1.100              # 完整扫描
  python3 penetration_test.py 192.168.1.100 --quick      # 快速扫描
  python3 penetration_test.py 192.168.1.100 --nmap-only  # 仅 nmap
  python3 penetration_test.py example.com --osint        # OSINT 扫描
        """
    )
    parser.add_argument('target', help='目标 IPv4、IPv4 CIDR 或 FQDN')
    parser.add_argument('--quick', '-q', action='store_true', help='快速扫描模式')
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--nmap-only', action='store_true', help='仅 nmap 扫描')
    mode_group.add_argument('--masscan-only', action='store_true', help='仅 masscan 扫描')
    mode_group.add_argument('--nikto-only', action='store_true', help='仅 nikto 扫描')
    mode_group.add_argument('--osint', action='store_true', help='OSINT 信息收集')
    parser.add_argument('--port', '-p', type=int, choices=range(1, 65536), default=80, metavar='PORT', help='Web 扫描端口 (默认: 80)')
    parser.add_argument('--no-store', action='store_true', help='不写入本地历史数据库')
    parser.add_argument('--json', action='store_true', help='stdout 仅输出结构化 JSON')
    args = parser.parse_args(argv)

    output_context = contextlib.redirect_stdout(sys.stderr) if args.json else contextlib.nullcontext()
    with output_context:
        print(color('bold', color('cyan', '''
╔══════════════════════════════════════════════════════╗
║         渗透测试框架 — 授权安全测试工具               ║
║              适用于：靶场练习、教学实验               ║
╚══════════════════════════════════════════════════════╝
'''))
        )

        # 检查目标
        target = args.target
        try:
            target_type = classify_target(target)
        except ValueError as exc:
            parser.error(str(exc))
        is_domain = target_type == 'domain'

        if is_domain and not args.osint:
            warn(f"检测到域名: {target}，将按所选扫描模式执行；Masscan 不支持域名")

        framework = PenTestFramework()

        # 执行扫描
        if args.nmap_only:
            framework.nmap_scan(target, quick=args.quick)
        elif args.masscan_only:
            framework.masscan_scan(target)
        elif args.nikto_only:
            framework.nikto_scan(target, args.port)
        elif args.osint:
            if is_domain:
                framework.theharvester_scan(target)
            else:
                warn("OSINT 扫描需要域名，请提供域名地址")
                return 2
        else:
            section('开始渗透测试')
            framework.nmap_scan(target, quick=args.quick)
            if not args.quick:
                framework.masscan_scan(target)
            if 'nmap' in framework.results and framework.results['nmap']:
                ports = collect_nmap_ports(framework.results['nmap'].get('open_ports'))
                web_ports = [p for p in ports if p.get('port') in [80, 443, 8080, 8443, 8000]]
                for web_port in web_ports:
                    framework.nikto_scan(target, web_port['port'])
            if is_domain:
                framework.theharvester_scan(target)

    analysis = None
    store = None
    run = None
    if not args.no_store:
        mode = 'quick' if args.quick else 'full'
        if args.nmap_only:
            mode = 'nmap-only'
        elif args.masscan_only:
            mode = 'masscan-only'
        elif args.nikto_only:
            mode = 'nikto-only'
        elif args.osint:
            mode = 'osint'
        store, run, analysis = persist_results(target, f'pentest-{mode}', framework.results)

    if args.json:
        print(json.dumps({
            'target': target,
            'run_id': run['id'] if run else None,
            'results': framework.results,
            'analysis': analysis,
        }, ensure_ascii=False, indent=2))
        return 0

    framework.print_summary(target)
    print(f"\n{color('green', '扫描流程结束。')}")
    print(f"报告文件: report_{safe_target_component(target)}_*.json")
    if analysis and store is not None:
        print(f"数据威胁度: {analysis['overall_score']}/10 ({analysis['overall_level']})")
        print(f"历史数据库: {store.db_path}")
    else:
        print("此次使用 --no-store，未写入历史数据库。")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
