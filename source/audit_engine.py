#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
网络审计引擎 v4 — 设备识别 + 漏洞检测 + 安全报告
================================================
功能说明：
  1. 扫描局域网所有设备（通过 ARP 表）
  2. 识别设备类型（手机/电脑/摄像头/IoT 等）
  3. 探测开放端口和运行服务
  4. 评估安全风险（高危端口、弱密码服务等）
  5. 生成 JSON 格式的安全报告

使用方法：
  python3 audit_engine.py                    # 扫描全部设备
  python3 audit_engine.py --target 192.168.1.100  # 扫描指定设备
  python3 audit_engine.py --quiet            # 静默模式（仅输出 JSON）
  python3 audit_engine.py --help             # 显示帮助
"""

import argparse
import contextlib
import json
import re
import socket
import subprocess
import sys
import tempfile
from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

RiskSeverity = Literal['critical', 'high', 'medium', 'low']
DisplayRiskLevel = Literal['未发现已知风险', '严重', '高风险', '中风险', '低风险']
RecommendationKind = Literal['critical', 'high', 'medium', 'info']


class RiskCheck(TypedDict):
    port: int
    risk: RiskSeverity
    desc: str


class ArpDevice(TypedDict):
    ip: str
    mac: str


class DeviceInfo(TypedDict):
    ip: str
    mac: str
    vendor: str
    device_type: str
    confidence: float
    ports: list[int]
    services: list[str]
    risk_score: int


class Finding(TypedDict):
    name: str
    port: int
    risk: RiskSeverity
    description: str
    port_open: bool


class DeviceReport(DeviceInfo):
    findings: list[Finding]
    risk_level: DisplayRiskLevel


class AuditSummary(TypedDict):
    total_devices: int
    critical: int
    high: int
    medium: int
    low: int
    devices_with_risks: int
    clean_devices: int


Recommendation = tuple[RecommendationKind, str]


class AuditReportRuntimeFields(TypedDict, total=False):
    run_id: str
    run_status: str
    run_error: str | None
    data_analysis: dict[str, Any]


class AuditReport(AuditReportRuntimeFields):
    timestamp: str
    total_devices: int
    summary: AuditSummary
    devices: list[DeviceReport]
    recommendations: list[Recommendation]


# ══════════════════════════════════════════════════════════
# 颜色输出配置
# 用于在终端中显示彩色文本，让输出更易读
# ══════════════════════════════════════════════════════════
COLORS = {
    'red': '\x1b[31m',      # 红色 - 用于警告和错误
    'green': '\x1b[32m',    # 绿色 - 用于信息和成功
    'yellow': '\x1b[33m',   # 黄色 - 用于警告
    'blue': '\x1b[34m',     # 蓝色 - 用于普通信息
    'magenta': '\x1b[35m',  # 紫色
    'cyan': '\x1b[36m',     # 青色 - 用于标题
    'bold': '\x1b[1m',      # 加粗
    'reset': '\x1b[0m',     # 重置颜色
}
is_win = sys.platform == 'win32'

def color(c: str, t: object) -> str:
    """给文本添加颜色"""
    return f"{COLORS.get(c, '')}{t}{COLORS.get('reset', '')}"

def section(title: str) -> None:
    """打印带边框的标题"""
    w = 60
    box_top = color("cyan", "╔" + "═"*(w-2) + "╗")
    box_mid = color("cyan", "║" + title.center(w-2) + "║")
    box_bot = color("cyan", "╚" + "═"*(w-2) + "╗")
    print(f'\n{box_top}\n{box_mid}\n{box_bot}\n')

def info(msg: object) -> None:   print(f"  {color('green', '[*]')} {msg}")
def warn(msg: object) -> None:   print(f"  {color('yellow', '[!]')} {msg}")
def alert(msg: object) -> None:  print(f"  {color('red', '[?]')} {msg}")
def ok(msg: object) -> None:     print(f"  {color('bold', '[✓]')} {msg}")

# ══════════════════════════════════════════════════════════
# 设备指纹数据库
# 用于识别设备类型和厂商
# 格式：品牌名 -> MAC 地址前缀列表
# ══════════════════════════════════════════════════════════
DEVICE_DATABASE = {
    # 手机品牌
    'apple': ['001a2b', '001b44', '001c42', '001d09', '002401', '002402',
              '002403', '002404', '002405', '002406', '002407', '002408'],
    'samsung': ['001a7d', '001f20', '002320'],
    'xiaomi': ['40a32b', '486272', '4c7982', '50728a', '54ef44', '58c21a'],
    'huawei': ['001e10', '00224b', '002389'],
    # BUG FIX: 原来 'google' 用的是和 'apple' 完全相同的 3 个前缀，
    # 这样 google 分支永远匹配不到（apple 排在前面，遍历时先命中），
    # 而且这几个前缀本来就不是 Google 的 OUI，是复制粘贴错误，已移除。
    # 如需识别 Google/Nest 设备，请替换为真实的 Google OUI 前缀。
    # 摄像头品牌
    'hikvision': ['001421', '001652', '00233c', '043743', '080c23'],
    'dahua': ['183f38', '1cb6bc', '20a1cc', '240832'],
    'xiaomi_cam': ['40a32b', '486272', '4c7982', '50728a'],
    'tp_link': ['9cb6d0', 'a0010c', 'a4cf12', 'b05a28'],
    'reolink': ['00153c', '001a2b'],
    'tapo': ['54aa63', '54b04e'],
    # 通用设备
    'raspberry': ['b827eb', 'dc:a6:32', '30:85:57'],
    'vmware': ['000c29', '005056'],
    'intel': ['001c42', '001d09'],
    'dell': ['00145e', '001517'],
    'hp': ['001635', '001731'],
}

# 端口特征库
# 不同设备类型通常会打开不同的端口
# 用于辅助判断设备类型
PORT_SIGNATURES = {
    'camera': [554, 8080, 8088, 8899, 5544, 10554, 8000],  # 摄像头常用端口
    'printer': [9100, 631, 515],  # 打印机常用端口
    'router': [22, 23, 80, 443, 8443],  # 路由器常用端口
    'nas': [2049, 445, 139, 8080],  # 网络存储常用端口
    'smart_tv': [8002, 9191, 5223, 5224],  # 智能电视常用端口
    'smart_speaker': [80, 443, 8080],  # 智能音箱常用端口
    'phone': [22, 23, 80, 443, 5222, 5223, 5228, 5229],  # 手机常用端口
    'laptop': [22, 445, 3389, 5900, 80, 443],  # 笔记本常用端口
    'desktop': [22, 445, 3389, 5900, 80, 443],  # 台式机常用端口
}

# 风险检查项
# 每个项目定义了：端口、风险等级、问题描述
RISK_CHECKS: dict[str, RiskCheck] = {
    'telnet': {'port': 23, 'risk': 'high', 'desc': 'Telnet 未加密远程登录（安全风险高）'},
    'ftp': {'port': 21, 'risk': 'medium', 'desc': 'FTP 明文传输文件（可能被窃取）'},
    'smb_vuln': {'port': 445, 'risk': 'high', 'desc': 'SMB 可能存在的漏洞（如 EternalBlue）'},
    'rdp_exposed': {'port': 3389, 'risk': 'high', 'desc': 'RDP 远程桌面暴露（可能被暴力破解）'},
    'vnc_exposed': {'port': 5900, 'risk': 'medium', 'desc': 'VNC 远程桌面暴露'},
    'ssh_weak': {'port': 22, 'risk': 'medium', 'desc': 'SSH 可能存在弱密码'},
    'rtsp_no_auth': {'port': 554, 'risk': 'high', 'desc': 'RTSP 摄像头无认证（可能被窥视）'},
    'http_default': {'port': 80, 'risk': 'low', 'desc': 'HTTP 未加密 Web 服务'},
    'redis_exposed': {'port': 6379, 'risk': 'high', 'desc': 'Redis 未授权访问'},
    'mysql_exposed': {'port': 3306, 'risk': 'medium', 'desc': 'MySQL 数据库暴露'},
    'mongodb_exposed': {'port': 27017, 'risk': 'high', 'desc': 'MongoDB 未授权访问'},
}


# ══════════════════════════════════════════════════════════
# 设备识别引擎
# 根据 MAC 地址、开放端口、服务信息判断设备类型
# ══════════════════════════════════════════════════════════
class DeviceFingerprint:
    """设备指纹识别引擎"""

    def __init__(self) -> None:
        self.mac_oui: dict[str, str] = {}
        self.port_profile: defaultdict[str, set[int]] = defaultdict(set)
        self.service_profile: dict[str, str] = {}

    def get_vendor(self, mac: str) -> str:
        """
        根据 MAC 地址识别厂商
        参数:
            mac: MAC 地址（如 "CC:1A:FA:C1:62:7C"）
        返回:
            厂商名称（如 "hikvision" 或 "未知厂商"）
        """
        # 清理 MAC 地址，转为小写
        clean = mac.replace(':', '').replace('-', '').lower()
        prefix6 = clean[:6]  # 取前 6 位（OUI 前缀）

        # 遍历设备数据库
        for brand, prefixes in DEVICE_DATABASE.items():
            for p in prefixes:
                # 匹配前缀
                if prefix6 == p.replace(':', '').replace('-', '').lower():
                    return brand

        return '未知厂商'

    def get_device_type(
        self, mac: str, ports: Iterable[int], services: Sequence[str]
    ) -> tuple[str, float]:
        """
        推断设备类型
        使用多维度评分：
        1. MAC 厂商信息（权重高）
        2. 开放端口特征（权重中）
        3. 运行服务特征（权重中）

        参数:
            mac: MAC 地址
            ports: 开放端口列表
            services: 识别出的服务列表
        返回:
            (设备类型, 置信度)
        """
        scores: defaultdict[str, float] = defaultdict(float)
        vendor = self.get_vendor(mac).lower()

        # 1. MAC 厂商得分
        if 'camera' in vendor or 'hikvision' in vendor or 'dahua' in vendor:
            scores['camera'] += 5
        if 'xiaomi' in vendor:
            scores['phone'] += 3
            scores['camera'] += 2
            scores['iot'] += 2
        if 'apple' in vendor:
            scores['phone'] += 3
            scores['laptop'] += 2
        if 'samsung' in vendor:
            scores['phone'] += 3
            scores['tv'] += 2
        if 'raspberry' in vendor:
            scores['iot'] += 4

        # 2. 端口特征得分
        for port in ports:
            for device_type, sig_ports in PORT_SIGNATURES.items():
                if port in sig_ports:
                    scores[device_type] += 2

        # 3. 服务指纹得分
        for svc in services:
            if 'rtsp' in svc.lower():
                scores['camera'] += 3
            if 'http' in svc.lower() or 'https' in svc.lower():
                scores['phone'] += 1
                scores['laptop'] += 1
                scores['camera'] += 1
            if 'ssh' in svc.lower():
                scores['computer'] += 2
            if 'telnet' in svc.lower():
                scores['iot'] += 2

        # 如果没有匹配到任何特征，返回未知
        if not scores:
            return '未知设备', 0.3

        # 计算置信度
        max_score = max(scores.values())
        top_type = max(scores, key=scores.__getitem__)

        # 类型映射表
        type_map: dict[str, tuple[str, float]] = {
            'camera': ('网络摄像头', 0.85),
            'phone': ('智能手机', 0.80),
            'laptop': ('笔记本电脑', 0.75),
            'desktop': ('台式电脑', 0.75),
            'computer': ('计算机', 0.70),
            'iot': ('智能家居设备', 0.65),
            'printer': ('打印机', 0.70),
            'router': ('路由器/网关', 0.75),
            'nas': ('网络存储', 0.70),
            'tv': ('智能电视', 0.65),
            'smart_speaker': ('智能音箱', 0.60),
        }

        device_type, conf = type_map.get(top_type, ('未知设备', 0.50))
        return device_type, min(conf + (max_score * 0.05), 1.0)

    def analyze(
        self, ip: str, mac: str, ports: set[int], services: list[str]
    ) -> DeviceInfo:
        """
        完整设备分析
        返回包含所有分析结果的字典
        """
        vendor = self.get_vendor(mac)
        device_type, confidence = self.get_device_type(mac, ports, services)

        return {
            'ip': ip,
            'mac': mac.upper(),
            'vendor': vendor,
            'device_type': device_type,
            'confidence': confidence,
            'ports': sorted(ports),
            'services': services,
            'risk_score': self.calc_risk(ports, services),
        }

    def calc_risk(self, ports: set[int], services: Sequence[str]) -> int:
        """
        计算风险分数（0-10）
        分数越高表示风险越大
        """
        risk = 0
        high_risk_ports = {23, 445, 3389, 5900, 22}
        risk += len(ports & high_risk_ports) * 2

        # BUG FIX: 原代码是 `ports & high_risk_services`，
        # ports 是端口号(int)集合，high_risk_services 是服务名(str)集合，
        # 两者永远没有交集，这部分风险分永远算不出来，且 services 参数完全没用上。
        # 改为：把 services 转成小写集合，再与高危服务名匹配。
        high_risk_services = {'telnet', 'ftp', 'rdp', 'vnc'}
        service_names = {s.lower() for s in services}
        risk += len(service_names & high_risk_services) * 1

        if 554 in ports or any('rtsp' in s.lower() for s in services):
            risk += 3

        return min(risk, 10)


# ══════════════════════════════════════════════════════════
# 网络扫描器
# 负责扫描局域网设备，探测端口和服务
# ══════════════════════════════════════════════════════════
class NetworkScanner:
    """网络扫描器"""

    def __init__(self) -> None:
        self.devices: dict[str, DeviceInfo] = {}
        self.fingerprint: DeviceFingerprint = DeviceFingerprint()
        self.arp_error: str | None = None
        self.scan_errors: list[str] = []

    def get_local_ip(self) -> str:
        """获取本机 IP 地址。UDP connect 仅选择路由，不发送应用数据。"""
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            return cast(str, sock.getsockname()[0])
        except OSError:
            return '127.0.0.1'
        finally:
            if sock is not None:
                sock.close()

    def get_mac_address(self) -> str:
        """获取本机 MAC 地址"""
        try:
            import uuid
            mac = uuid.getnode()
            return ':'.join(('%02X' % (mac >> 8 * i & 0xff)) for i in range(5, -1, -1))
        except (OSError, ValueError):
            return 'N/A'

    @staticmethod
    def normalize_mac(mac: str | None) -> str:
        """把 macOS ARP 中 0:1a:eb:... 这类短格式补齐为标准 MAC。"""
        parts = re.split(r'[:-]', (mac or '').strip())
        if len(parts) == 6 and all(re.fullmatch(r'[0-9A-Fa-f]{1,2}', part) for part in parts):
            return ':'.join(part.zfill(2).upper() for part in parts)
        return (mac or '').replace('-', ':').upper()

    @staticmethod
    def is_scannable_ip(value: str) -> bool:
        """ARP 中的组播、回环、保留和无效地址不作为长期设备资产。"""
        try:
            address = ip_address(value)
        except ValueError:
            return False
        return address.version == 4 and not (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
            or address.is_reserved
        )

    @staticmethod
    def validate_target_ip(value: object) -> str:
        """显式目标必须是无修饰的单个 IPv4 地址。"""
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError('目标必须是单个 IPv4，且不能包含首尾空白')
        if value.startswith('-'):
            raise ValueError('目标不能以 - 开头')
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError('目标不能包含控制字符')
        if re.match(r'^[A-Za-z][A-Za-z0-9+.-]*://', value):
            raise ValueError('目标不能包含 URL scheme')
        if '/' in value:
            raise ValueError('审计 --target 不接受 CIDR')
        try:
            address = ip_address(value)
        except ValueError as exc:
            raise ValueError('目标必须是合法 IPv4 地址') from exc
        if address.version != 4:
            raise ValueError('目标必须是 IPv4 地址')
        return str(address)

    def scan_arp(self) -> list[ArpDevice]:
        """
        扫描 ARP 表获取局域网设备
        原理：ARP 协议用于 IP 地址到 MAC 地址的映射
        返回：设备列表，每个设备包含 IP 和 MAC 地址
        """
        devices: list[ArpDevice] = []
        self.arp_error = None
        try:
            if sys.platform == 'win32':
                # Windows 命令
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or f'arp 退出码 {result.returncode}')
                for line in result.stdout.split('\n'):
                    m = re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})', line)
                    if m and self.is_scannable_ip(m.group(1)):
                        devices.append({
                            'ip': m.group(1),
                            'mac': self.normalize_mac(m.group(2))
                        })
            else:
                # macOS/Linux 命令
                result = subprocess.run(['arp', '-an'], capture_output=True, text=True, check=False)
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or f'arp 退出码 {result.returncode}')
                for line in result.stdout.split('\n'):
                    m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
                    if m and self.is_scannable_ip(m.group(1)):
                        devices.append({
                            'ip': m.group(1),
                            'mac': self.normalize_mac(m.group(2))
                        })
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            self.arp_error = f"ARP 扫描失败: {exc}"
            warn(self.arp_error)

        unique_devices: dict[tuple[str, str], ArpDevice] = {}
        for device in devices:
            unique_devices[(device['ip'], device['mac'])] = device
        return list(unique_devices.values())

    def probe_ports(
        self, ip: str, ports: Iterable[int], timeout: float = 0.1
    ) -> tuple[set[int], list[str]]:
        """
        探测目标 IP 的端口是否开放
        参数:
            ip: 目标 IP 地址
            ports: 要探测的端口列表
            timeout: 每个端口的超时时间（秒）
        返回:
            (开放端口集合, 服务列表)
        """
        open_ports: set[int] = set()
        services_by_port: dict[int, str] = {}

        for port in ports:
            sock: socket.socket | None = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                # connect_ex 返回 0 表示端口开放
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.add(port)
                    # 探测服务类型
                    svc = self.probe_service(ip, port)
                    services_by_port[port] = svc or f'Port-{port}'
            except OSError:
                continue
            finally:
                if sock is not None:
                    sock.close()
        ordered_ports = sorted(open_ports)
        services = [services_by_port[port] for port in ordered_ports]
        return set(ordered_ports), services

    def probe_service(self, ip: str, port: int) -> str | None:
        """
        探测端口上运行的服务类型
        通过读取服务 banner 或根据端口号推断
        """
        service_map = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 554: 'RTSP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt', 27017: 'MongoDB',
        }
        sock: socket.socket | None = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((ip, port))

            try:
                # 尝试读取服务 banner
                banner = sock.recv(1024)
                banner_str = banner.decode('utf-8', errors='ignore')[:100]

                # 根据 banner 内容识别服务
                if b'RTSP' in banner or 'RTSP' in banner_str:
                    return 'RTSP'
                if b'HTTP' in banner or 'HTTP' in banner_str:
                    return 'HTTPS' if port == 443 else 'HTTP'
                if b'SSH' in banner:
                    return 'SSH'
                if b'Telnet' in banner or 'Telnet' in banner_str:
                    return 'Telnet'
                if b'SMB' in banner or 'SMB' in banner_str:
                    return 'SMB'
            except OSError:
                pass

            return service_map.get(port, f'Port-{port}')
        except OSError:
            return None
        finally:
            if sock is not None:
                sock.close()

    def scan_network(self, target_ip: str | None = None) -> list[DeviceInfo]:
        """
        扫描整个网络或指定目标
        参数:
            target_ip: 如果指定，只扫描该 IP；否则扫描所有设备
        """
        self.scan_errors = []
        normalized_target = None
        if target_ip is not None:
            normalized_target = self.validate_target_ip(target_ip)

        local_ip = self.get_local_ip()
        info(f"本机 IP: {color('bold', local_ip)}  MAC: {self.get_mac_address()}")

        # 获取局域网设备；显式目标即使不在 ARP 中也继续扫描。
        arp_devices = self.scan_arp()
        if self.arp_error:
            self.scan_errors.append(self.arp_error)
        if not arp_devices and normalized_target is None:
            warn("无法获取局域网设备列表")
            if not self.scan_errors:
                self.scan_errors.append('ARP 未返回任何可扫描设备')
            return []

        info(f"发现 {len(arp_devices)} 个 ARP 设备")

        # 要探测的端口列表（常用端口）
        all_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445,
                     993, 995, 554, 1433, 3306, 3389, 5432, 5900, 6379,
                     8080, 8088, 8443, 8899, 9000, 10554, 27017]

        # 确定要扫描的设备列表
        devices_to_scan: list[ArpDevice]
        if normalized_target:
            matched = [d for d in arp_devices if d['ip'] == normalized_target]
            if matched:
                devices_to_scan = matched
            else:
                warn(f"目标 {normalized_target} 不在 ARP 表中，将使用 MAC=N/A 继续扫描")
                devices_to_scan = [{'ip': normalized_target, 'mac': 'N/A'}]
        else:
            devices_to_scan = arp_devices

        results: list[DeviceInfo] = []
        for dev in devices_to_scan:
            ip = dev['ip']
            mac = dev['mac']

            # 局域网批量扫描跳过本机；显式指定本机时尊重用户目标。
            if not normalized_target and ip == local_ip:
                continue

            info(f"扫描 {ip}...")
            ports, services = self.probe_ports(ip, all_ports)
            ordered_ports = sorted(ports)

            # 设备分析；services 与排序后的 ports 保持同一索引语义。
            analysis = self.fingerprint.analyze(ip, mac, set(ordered_ports), services)
            results.append(analysis)

            # 输出结果
            risk_score = analysis['risk_score']
            if ports or risk_score > 0:
                tag = color('red', f' [风险:{risk_score}/10]') if risk_score > 0 else ''
                alert(f"{ip:<16} {mac:<18} {analysis['device_type']:<15} ({analysis['confidence']:.0%}){tag}")
                alert(f"  端口: {sorted(ports)}  服务: {services}")
            else:
                info(f"{ip:<16} {mac:<18} {analysis['device_type']:<15} ({analysis['confidence']:.0%})")

        return results


# ══════════════════════════════════════════════════════════
# 安全审计引擎
# 负责生成安全报告和修复建议
# ══════════════════════════════════════════════════════════
class SecurityAudit:
    """安全审计引擎"""

    def audit_device(self, device_info: DeviceInfo) -> list[Finding]:
        """
        审计单个设备的安全风险
        检查开放端口是否匹配已知风险项
        """
        findings: list[Finding] = []
        ports: set[int] = set(device_info.get('ports', []))

        for check_name, check in RISK_CHECKS.items():
            if check['port'] in ports:
                findings.append({
                    'name': check_name,
                    'port': check['port'],
                    'risk': check['risk'],
                    'description': check['desc'],
                    'port_open': True,
                })

        return findings

    def generate_report(
        self, devices: Sequence[DeviceInfo], output_format: str = 'text'
    ) -> AuditReport:
        """
        生成综合安全报告
        包含：设备列表、风险统计、修复建议
        """
        summary: AuditSummary = {
            'total_devices': len(devices),
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0,
            'devices_with_risks': 0, 'clean_devices': 0,
        }
        report: AuditReport = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_devices': len(devices),
            'summary': summary,
            'devices': [],
            'recommendations': [],
        }

        for dev in devices:
            findings = self.audit_device(dev)
            dev_report: DeviceReport = {
                **dev,
                'findings': findings,
                'risk_level': self.calc_risk_level(findings),
            }
            report['devices'].append(dev_report)

            # 统计风险
            for f in findings:
                if f['risk'] == 'critical':
                    summary['critical'] += 1
                elif f['risk'] == 'high':
                    summary['high'] += 1
                elif f['risk'] == 'medium':
                    summary['medium'] += 1
                elif f['risk'] == 'low':
                    summary['low'] += 1

            if findings:
                summary['devices_with_risks'] += 1
            else:
                summary['clean_devices'] += 1

        # 生成修复建议
        report['recommendations'] = self.gen_recommendations(summary, devices)
        return report

    def calc_risk_level(self, findings: Sequence[Finding]) -> DisplayRiskLevel:
        """根据发现计算风险等级"""
        if not findings:
            return '未发现已知风险'
        risks = [f['risk'] for f in findings]
        if 'critical' in risks:
            return '严重'
        if 'high' in risks:
            return '高风险'
        if 'medium' in risks:
            return '中风险'
        return '低风险'

    def gen_recommendations(
        self, summary: AuditSummary, devices: Sequence[DeviceInfo]
    ) -> list[Recommendation]:
        """生成修复建议"""
        recs: list[Recommendation] = []

        if summary['critical'] > 0:
            recs.append(('critical', '立即修复：存在严重安全风险的设备'))
        if summary['high'] > 0:
            recs.append(('high', '优先处理：存在高风险漏洞的设备'))
        if summary['medium'] > 0:
            recs.append(('medium', '建议修复：存在中等风险的设备'))

        # 针对摄像头的建议
        cameras = [d for d in devices if d['device_type'] == '网络摄像头']
        if cameras:
            for cam in cameras:
                if 554 in cam['ports']:
                    recs.append(('info', f"检查摄像头 {cam['ip']} 的 RTSP 认证设置"))

        return recs


# ══════════════════════════════════════════════════════════
# 主程序入口
# ══════════════════════════════════════════════════════════
def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description='网络审计引擎 — 设备识别 + 历史威胁分析')
    parser.add_argument('--target', '-t', help='指定目标 IP 地址')
    parser.add_argument('--json', '-j', action='store_true', help='输出 JSON 报告')
    parser.add_argument('--quiet', '-q', action='store_true', help='静默模式（stdout 仅输出 JSON）')
    parser.add_argument('--no-store', action='store_true', help='不保留本次历史数据')
    args = parser.parse_args(argv)
    if args.target is not None:
        try:
            args.target = NetworkScanner.validate_target_ip(args.target)
        except ValueError as exc:
            parser.error(str(exc))

    if not __package__:
        project_root = str(Path(__file__).resolve().parents[1])
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
    from source.data_platform import DataStore

    temporary = tempfile.TemporaryDirectory(prefix='netrunner-audit-') if args.no_store else None
    store = DataStore(data_dir=Path(temporary.name)) if temporary else DataStore()
    run = store.start_run(
        command='legacy-audit',
        mode='audit-target' if args.target else 'audit-lan',
        target=args.target,
        collectors=['audit'],
    )

    if not args.quiet:
        print(color('bold', color('cyan', '''
╔══════════════════════════════════════════════════════╗
║        网络审计引擎 v5 — 设备历史 + 威胁分析          ║
║              适用于：安全研究/教学/授权测试           ║
╚══════════════════════════════════════════════════════╝
''')))

    scanner = NetworkScanner()
    auditor = SecurityAudit()
    scan_output = contextlib.redirect_stdout(sys.stderr) if args.quiet else contextlib.nullcontext()
    try:
        with scan_output:
            section('网络扫描')
            devices = scanner.scan_network(target_ip=args.target)
            section('安全审计')
        report = auditor.generate_report(devices, output_format='json')
        run_id = cast(str, run['id'])
        store.store_raw(run_id, 'audit', 'audit_devices.json', devices)
        ingestion = store.ingest_audit_devices(
            run_id, cast(Sequence[dict[str, Any]], devices)
        )
        run_errors: list[str] = list(cast(Sequence[str], ingestion['rejected'])) + list(scanner.scan_errors)
        if not devices:
            run_errors.append('未产生任何设备扫描证据')
        accepted = cast(int, ingestion['accepted'])
        if accepted and not run_errors:
            status = 'complete'
        elif accepted:
            status = 'partial'
        else:
            status = 'failed'
        error_text = '\n'.join(dict.fromkeys(run_errors)) or None
        store.finish_run(run_id, status, error_text)
        analysis: dict[str, Any] = store.analyze(run_id)
        report['run_id'] = run_id
        report['run_status'] = status
        report['run_error'] = error_text
        report['data_analysis'] = analysis
        store.store_raw(run_id, 'audit', 'audit_report.json', report)
    except Exception as exc:
        store.finish_run(cast(str, run['id']), 'failed', str(exc))
        if temporary:
            temporary.cleanup()
        raise

    if args.quiet or args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if temporary:
            temporary.cleanup()
        return

    summary = report['summary']
    report_devices = report['devices']
    print(f"\n{color('bold', '扫描摘要:')}")
    print(f"  总设备数: {summary['total_devices']}")
    print(f"  安全风险: 严重:{summary['critical']} 高:{summary['high']} "
          f"中:{summary['medium']} 低:{summary['low']}")
    print(f"  干净设备: {summary['clean_devices']}")
    print(f"  数据威胁度: {analysis['overall_score']}/10 ({analysis['overall_level']})")
    print(f"  历史变化: 新资产 {analysis['new_asset_count']} / 新端口 {analysis['new_port_count']}")

    print(f"\n{color('bold', '设备详情:')}")
    print(f"  {'IP 地址':<16} {'MAC 地址':<18} {'设备类型':<15} {'风险等级':<10} {'厂商'}")
    print(f"  {'─'*15} {'─'*17} {'─'*14} {'─'*9} {'─'*20}")
    risk_colors = {'未发现已知风险': 'green', '低风险': 'blue', '中风险': 'yellow',
                   '高风险': 'red', '严重': 'red'}
    for dev in report_devices:
        risk = dev['risk_level']
        print(f"  {dev['ip']:<16} {dev['mac']:<18} {dev['device_type']:<15} "
              f"{color(risk_colors.get(risk, 'white'), risk):<10} {dev['vendor']}")
        for finding in dev['findings']:
            print(f"    {color('red', '⚠')} {finding['description']} (端口 {finding['port']})")

    print(f"\n{color('bold', '数据分析优先级:')}")
    for asset in analysis['assets'][:10]:
        print(
            f"  {asset['score']:>4}/10 {asset['identity_type']}:{asset['identity_value']} "
            f"置信度:{asset['confidence']:.0%}"
        )
        for factor in asset['factors'][:3]:
            print(f"    · +{factor['score']} {factor['title']}")

    report_file = f"audit_report_{datetime.now().astimezone().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w', encoding='utf-8') as file:
        json.dump(report, file, ensure_ascii=False, indent=2)
    print(f"\n{color('green', f'[✓] 报告已保存: {report_file}')}")
    if not args.no_store:
        print(f"{color('green', '[✓]')} 历史数据库: {store.db_path}")
    if temporary:
        temporary.cleanup()


if __name__ == '__main__':
    main()
