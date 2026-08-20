#!/usr/bin/env node
// 家庭监控探测工具 — 跨平台（Windows / macOS / Linux）
'use strict';

const { spawnSync } = require('child_process');
const { randomUUID } = require('crypto');
const os = require('os');
const net = require('net');

const COLORS = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
  reset: '\x1b[0m',
};

const isWin = process.platform === 'win32';
const DEFAULT_COMMAND_TIMEOUT_MS = 15000;
const DEVICE_CONCURRENCY = 8;
const MAC_SOURCE = '(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}';
let jsonlMode = false;

class CommandExecutionError extends Error {
  constructor(result) {
    const reason = result.timedOut
      ? `执行超时（${result.timeoutMs}ms）`
      : result.error
        ? result.error.message
        : `退出码 ${result.returnCode}`;
    super(`${result.command} ${reason}`);
    this.name = 'CommandExecutionError';
    this.result = result;
  }
}

class ParseFailure extends Error {
  constructor(message, cause = null) {
    super(message);
    this.name = 'ParseFailure';
    this.cause = cause;
  }
}

class CLIUsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CLIUsageError';
    this.exitCode = 2;
  }
}

function humanLog(...args) {
  if (jsonlMode) console.error(...args);
  else console.log(...args);
}

function color(colorName, text) {
  return `${COLORS[colorName] || ''}${text}${COLORS.reset}`;
}

function section(title) {
  humanLog('');
  humanLog(color('cyan', `╔${'═'.repeat(46)}╗`));
  humanLog(color('cyan', `║${title.padStart(23)}  ║`));
  humanLog(color('cyan', `╚${'═'.repeat(46)}╝`));
  humanLog('');
}

function info(msg)  { humanLog(color('green', '  [*]') + ' ' + msg); }
function warn(msg)  { humanLog(color('yellow', '  [!]') + ' ' + msg); }
function alert(msg) { humanLog(color('red', '  [?]') + ' ' + msg); }

// 使用 shell:false 和参数数组，完整保留 stdout、stderr、退出码与超时信息。
// 非零退出、启动失败和超时都会抛出 CommandExecutionError，调用方不能把失败当成空结果。
function run(cmd, args = [], opts = {}) {
  if (typeof cmd !== 'string' || !cmd) throw new TypeError('命令名必须是非空字符串');
  if (!Array.isArray(args) || args.some(arg => typeof arg !== 'string')) {
    throw new TypeError('命令参数必须是字符串数组');
  }

  const timeoutMs = Number.isFinite(opts.timeout) && opts.timeout > 0
    ? Math.floor(opts.timeout)
    : DEFAULT_COMMAND_TIMEOUT_MS;
  const completed = spawnSync(cmd, args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    shell: false,
    maxBuffer: opts.maxBuffer || 8 * 1024 * 1024,
  });

  const result = {
    command: cmd,
    args: [...args],
    stdout: typeof completed.stdout === 'string' ? completed.stdout : '',
    stderr: typeof completed.stderr === 'string' ? completed.stderr : '',
    returnCode: Number.isInteger(completed.status) ? completed.status : null,
    signal: completed.signal || null,
    timeoutMs,
    timedOut: Boolean(completed.error && completed.error.code === 'ETIMEDOUT'),
    error: completed.error || null,
  };
  result.ok = !result.error && result.returnCode === 0;

  if (!result.ok) throw new CommandExecutionError(result);
  return result;
}

function commandFailureFields(error) {
  if (!(error instanceof CommandExecutionError)) return {};
  const result = error.result;
  return {
    returnCode: result.returnCode,
    timedOut: result.timedOut,
    timeoutMs: result.timeoutMs,
    signal: result.signal,
    stdout: result.stdout.trim().slice(0, 2000) || null,
    stderr: result.stderr.trim().slice(0, 2000) || null,
  };
}

function collectorFailure(collector, error, attempts = []) {
  const status = error instanceof CommandExecutionError ? 'command_failed' : 'parse_failed';
  return {
    collector,
    status,
    items: [],
    error: error.message,
    attempts,
    ...commandFailureFields(error),
  };
}

function collectorSuccess(collector, items, extra = {}) {
  return { collector, status: 'success', items, ...extra };
}

function getIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const address of nets[name] || []) {
      if (address.family === 'IPv4' && !address.internal) return address.address;
    }
  }
  return '127.0.0.1';
}

function getMAC() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const address of nets[name] || []) {
      if (address.family === 'IPv4' && !address.internal) return normalizeMAC(address.mac);
    }
  }
  return 'N/A';
}

const CAMERA_OUI = {
  '001421': 'Hikvision', '001652': 'Hikvision', '00233C': 'Hikvision',
  '043743': 'Hikvision', '080C23': 'Hikvision', '100241': 'Hikvision',
  '14B9E1': 'Hikvision', '840333': 'Hikvision',
  '183F38': 'Dahua', '1CB6BC': 'Dahua', '20A1CC': 'Dahua',
  '240832': 'Dahua', '2CF05D': 'Dahua', '309C23': 'Dahua',
  '348525': 'Dahua', '487B52': 'Dahua',
  '40A32B': 'Xiaomi', '486272': 'Xiaomi', '4C7982': 'Xiaomi',
  '50728A': 'Xiaomi', '54EF44': 'Xiaomi', '58C21A': 'Xiaomi',
  '6012F4': 'Xiaomi', '64BB5A': 'Xiaomi', '6C7257': 'Xiaomi',
  '685FB1': 'Xiaomi', '78C878': 'Xiaomi', '801F02': 'Xiaomi',
  '840D3E': 'Xiaomi', '8C07F4': 'Xiaomi', '904E02': 'Xiaomi',
  '94B84D': 'Xiaomi', '98ED9F': 'Xiaomi', 'A0106A': 'Xiaomi',
  '9CB6D0': 'TP-Link', 'A0010C': 'TP-Link', 'A4CF12': 'TP-Link',
  'B05A28': 'TP-Link', 'B82659': 'TP-Link', 'C0058B': 'TP-Link',
  'D03A98': 'TP-Link', 'D4197C': 'TP-Link', 'DC6D1F': 'TP-Link',
  'E45F01': 'TP-Link', 'E81C9C': 'TP-Link', 'F01257': 'TP-Link',
  'F4F5D4': 'TP-Link',
  '0012FA': 'Anker(Eufy)', '24A39C': 'Anker(Eufy)',
  '001788': 'Argus', '00193B': 'Swann',
  'B0097A': 'Lorex',
};

const CAMERA_BRANDS = [
  'hikvision', 'dahua', 'xiaomi', 'mi home', 'tp-link',
  'imou', 'tapo', 'kasa', 'reolink', 'annke', 'v380', 'ip cam', 'cctv', '监控', '安防', 'argus',
];

function normalizeMAC(value) {
  if (typeof value !== 'string') return value;
  const parts = value.trim().replace(/-/g, ':').split(':');
  if (parts.length === 6 && parts.every(part => /^[0-9A-Fa-f]{1,2}$/.test(part))) {
    return parts.map(part => part.padStart(2, '0').toUpperCase()).join(':');
  }
  return value.trim().replace(/-/g, ':').toUpperCase();
}

function isValidMAC(value) {
  if (typeof value !== 'string') return false;
  const normalized = normalizeMAC(value);
  if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(normalized)) return false;
  const compact = normalized.replace(/:/g, '');
  return compact !== '000000000000' && compact !== 'FFFFFFFFFFFF';
}

function hasAddress(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  return !['N/A', 'UNKNOWN', '未知'].includes(value.trim().toUpperCase());
}

function isScannableIPv4(value) {
  const raw = String(value || '').split('.');
  if (raw.length !== 4 || raw.some(part => !/^\d{1,3}$/.test(part))) return false;
  const parts = raw.map(Number);
  if (parts.some(part => part < 0 || part > 255)) return false;
  if (parts[0] === 0 || parts[0] === 127 || parts[0] >= 224) return false;
  return true;
}

function queryVendor(mac) {
  const clean = normalizeMAC(mac).replace(/:/g, '').toUpperCase().slice(0, 6);
  return CAMERA_OUI[clean] || '未知厂商';
}

function isCameraBrand(vendor) {
  return CAMERA_BRANDS.some(keyword => vendor.toLowerCase().includes(keyword));
}

function uniqueBy(items, keyFn) {
  return [...new Map(items.map(item => [keyFn(item), item])).values()];
}

function parseWindowsArp(output, localIP) {
  const devices = [];
  const rowPattern = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})(?:\s+\S+)?\s*$/;
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(rowPattern);
    if (!match) continue;
    const ip = match[1];
    const mac = normalizeMAC(match[2]);
    if (ip !== localIP && isScannableIPv4(ip) && isValidMAC(mac)) devices.push({ ip, mac });
  }
  return devices;
}

function parseUnixArp(output, localIP) {
  const devices = [];
  const rowPattern = /\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+((?:[0-9A-Fa-f]{1,2}:){5}[0-9A-Fa-f]{1,2})(?:\s|$)/;
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(rowPattern);
    if (!match) continue;
    const ip = match[1];
    const mac = normalizeMAC(match[2]);
    if (ip !== localIP && isScannableIPv4(ip) && isValidMAC(mac)) devices.push({ ip, mac });
  }
  return devices;
}

function parseLinuxNeighbors(output, localIP) {
  const devices = [];
  const rowPattern = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+.*?\blladdr\s+((?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})(?:\s|$)/;
  for (const line of output.split(/\r?\n/)) {
    const match = line.match(rowPattern);
    if (!match) continue;
    const ip = match[1];
    const mac = normalizeMAC(match[2]);
    if (ip !== localIP && isScannableIPv4(ip) && isValidMAC(mac)) devices.push({ ip, mac });
  }
  return devices;
}

async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let nextIndex = 0;

  async function consume() {
    while (true) {
      const index = nextIndex++;
      if (index >= items.length) return;
      results[index] = await worker(items[index], index);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => consume());
  await Promise.all(workers);
  return results;
}

function probePort(ip, port, timeout) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    const finish = open => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };

    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    try {
      socket.connect(port, ip);
    } catch (_) {
      finish(false);
    }
  });
}

async function networkScan(onObservation = () => {}) {
  const collector = 'spy.network';
  section('网络扫描');

  const localIP = getIP();
  info(`本机 IP: ${color('bold', localIP)}  MAC: ${getMAC()}`);

  let devices;
  const attempts = [];
  try {
    if (isWin) {
      const result = run('arp', ['-a']);
      attempts.push({ command: 'arp', return_code: result.returnCode });
      devices = parseWindowsArp(result.stdout, localIP);
    } else if (process.platform === 'linux') {
      try {
        const result = run('ip', ['neigh', 'show']);
        attempts.push({ command: 'ip', return_code: result.returnCode });
        devices = parseLinuxNeighbors(result.stdout, localIP);
      } catch (firstError) {
        attempts.push({ command: 'ip', status: 'command_failed', ...commandFailureFields(firstError) });
        const result = run('arp', ['-an']);
        attempts.push({ command: 'arp', return_code: result.returnCode });
        devices = parseUnixArp(result.stdout, localIP);
      }
    } else {
      const result = run('arp', ['-an']);
      attempts.push({ command: 'arp', return_code: result.returnCode });
      devices = parseUnixArp(result.stdout, localIP);
    }
  } catch (error) {
    warn(`读取邻居表失败：${error.message}`);
    return collectorFailure(collector, error, attempts);
  }

  devices = uniqueBy(devices, device => `${device.ip}|${device.mac}`);
  if (devices.length === 0) {
    info('邻居表读取成功，当前没有可探测的其它 IPv4 设备');
    return collectorSuccess(collector, [], { attempts });
  }

  info(`发现 ${devices.length} 个设备，以最多 ${DEVICE_CONCURRENCY} 个设备并发探测端口...`);
  const suspiciousPorts = [80, 443, 554, 8080, 8088, 8899, 5544, 10554, 81, 8000, 9000, 8008];
  const probeTimeout = 250;

  const results = await mapWithConcurrency(devices, DEVICE_CONCURRENCY, async device => {
    const ports = await Promise.all(
      suspiciousPorts.map(async port => await probePort(device.ip, port, probeTimeout) ? port : null)
    );
    const openPorts = ports.filter(port => port !== null);
    const vendor = queryVendor(device.mac);
    const isCamera = isCameraBrand(vendor);
    const observation = {
      ...device,
      vendor,
      suspicious: openPorts.length > 0 || isCamera,
      openPorts,
    };

    if (observation.suspicious) {
      alert(`${device.ip}  MAC:${device.mac}  ${vendor}${isCamera ? ' [CAMERA]' : ''}  端口:${openPorts.join(',')}`);
    } else {
      info(`${device.ip}  MAC:${device.mac}  ${vendor}`);
    }
    onObservation(observation);
    return observation;
  });

  return collectorSuccess(collector, results, { attempts });
}

function parseWindowsWifi(output) {
  const networks = [];
  let currentSSID = '[隐藏]';
  let authentication = '';
  let encryption = '';
  let pending = null;

  const flush = () => {
    if (!pending) return;
    networks.push({
      ssid: currentSSID || '[隐藏]',
      bssid: normalizeMAC(pending.bssid),
      signal: pending.signal || '',
      encryption: encryption || authentication || '',
    });
    pending = null;
  };

  for (const line of output.split(/\r?\n/)) {
    let match = line.match(/^\s*SSID\s+\d+\s*:\s*(.*)\s*$/i);
    if (match) {
      flush();
      currentSSID = match[1].trim() || '[隐藏]';
      authentication = '';
      encryption = '';
      continue;
    }
    match = line.match(/^\s*(?:Authentication|身份验证)\s*:\s*(.*)\s*$/i);
    if (match) {
      authentication = match[1].trim();
      continue;
    }
    match = line.match(/^\s*(?:Encryption|加密)\s*:\s*(.*)\s*$/i);
    if (match) {
      encryption = match[1].trim();
      continue;
    }
    match = line.match(new RegExp(`^\\s*BSSID\\s+\\d+\\s*:\\s*(${MAC_SOURCE})\\s*$`, 'i'));
    if (match) {
      flush();
      pending = { bssid: match[1], signal: '' };
      continue;
    }
    match = line.match(/^\s*(?:Signal|信号)\s*:\s*(.*)\s*$/i);
    if (match && pending) pending.signal = match[1].trim();
  }
  flush();
  return uniqueBy(networks, network => `${network.bssid}|${network.ssid}`);
}

function parseAirportOutput(output) {
  const networks = [];
  const malformed = [];
  const rowPattern = new RegExp(
    `^\\s*(.*?)\\s+(${MAC_SOURCE})\\s+(-?\\d+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)(?:\\s+(.*?))?\\s*$`,
    'i'
  );

  for (const line of output.split(/\r?\n/)) {
    if (!line.trim() || /\bBSSID\b.*\bRSSI\b/i.test(line)) continue;
    const match = line.match(rowPattern);
    if (!match) {
      malformed.push(line);
      continue;
    }
    networks.push({
      ssid: match[1].trim() || '[隐藏]',
      bssid: normalizeMAC(match[2]),
      signal: `${match[3]} dBm`,
      encryption: (match[7] || '').trim(),
    });
  }

  if (networks.length === 0 && malformed.length > 0) {
    throw new ParseFailure('airport 输出格式无法识别');
  }
  return uniqueBy(networks, network => `${network.bssid}|${network.ssid}`);
}

function canonicalKey(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]/g, '');
}

function pickField(object, candidateNames) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) return undefined;
  const candidates = new Set(candidateNames.map(canonicalKey));
  for (const [key, value] of Object.entries(object)) {
    if (candidates.has(canonicalKey(key)) && value !== null && value !== undefined && value !== '') return value;
  }
  return undefined;
}

function scalarText(value) {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}

function parseSystemProfilerWifi(data) {
  const networks = [];

  function visit(value) {
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    if (!value || typeof value !== 'object') return;

    const rawBSSID = pickField(value, [
      'bssid', 'mac_address', 'airport_bssid', 'spairport_network_bssid',
    ]);
    if (rawBSSID && isValidMAC(scalarText(rawBSSID))) {
      const rawSSID = pickField(value, [
        'ssid', 'network_name', 'spairport_network_name', '_name', 'name',
      ]);
      const rawSignal = pickField(value, [
        'current_signal_strength', 'signal_strength', 'rssi', 'spairport_signal_noise', 'spairport_signal_strength',
      ]);
      const rawSecurity = pickField(value, [
        'security_type', 'security', 'spairport_security_mode', 'authentication',
      ]);
      const signalText = scalarText(rawSignal);
      const signalMatch = signalText.match(/-?\d+/);
      networks.push({
        ssid: scalarText(rawSSID).trim() || '[隐藏]',
        bssid: normalizeMAC(scalarText(rawBSSID)),
        signal: signalMatch ? `${signalMatch[0]} dBm` : signalText,
        encryption: scalarText(rawSecurity),
      });
    }

    Object.values(value).forEach(visit);
  }

  visit(data);
  return uniqueBy(networks, network => `${network.bssid}|${network.ssid}`);
}

function splitNmcliLine(line) {
  const fields = [];
  let current = '';
  let escaping = false;
  for (const char of line) {
    if (escaping) {
      current += char;
      escaping = false;
    } else if (char === '\\') {
      escaping = true;
    } else if (char === ':') {
      fields.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  if (escaping) current += '\\';
  fields.push(current);
  return fields;
}

function parseNmcliWifi(output) {
  const networks = [];
  let nonEmptyLines = 0;
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    nonEmptyLines++;
    const fields = splitNmcliLine(line);
    if (fields.length !== 4) continue;
    const [ssid, security, signal, bssid] = fields;
    networks.push({
      ssid: ssid || '[隐藏]',
      bssid: isValidMAC(bssid) ? normalizeMAC(bssid) : bssid,
      signal: signal ? `${signal}%` : '',
      encryption: security || '',
    });
  }
  if (nonEmptyLines > 0 && networks.length === 0) throw new ParseFailure('nmcli 输出格式无法识别');
  return uniqueBy(networks, network => `${network.bssid}|${network.ssid}`);
}

function presentWifiNetworks(networks, onObservation) {
  if (networks.length === 0) {
    info('WiFi 命令执行成功，当前未返回可见网络');
    return [];
  }

  info(`发现 ${networks.length} 个 WiFi 网络\n`);
  humanLog(color('bold', `  ${'SSID'.padEnd(25)} ${'BSSID'.padEnd(20)} ${'信号'.padEnd(8)} ${'加密'.padEnd(10)} 备注`));
  humanLog('  ' + '─'.repeat(85));

  return networks.map(network => {
    const ssid = String(network.ssid || '[隐藏]');
    const bssid = String(network.bssid || '');
    const signal = String(network.signal || '');
    const encryption = String(network.encryption || '');
    let note = '';
    if (ssid === '[隐藏]') note = 'HIDDEN';
    if (CAMERA_BRANDS.some(keyword => ssid.toLowerCase().includes(keyword))) note = '关键词匹配';

    const observation = { ...network, ssid, bssid, signal, encryption, ...(note ? { note } : {}) };
    const row = `  ${ssid.padEnd(25)} ${bssid.padEnd(20)} ${signal.padEnd(8)} ${encryption.padEnd(10)}`;
    if (note) alert(`${row}  ${color('red', note)}`);
    else info(row);
    onObservation(observation);
    return observation;
  });
}

function wifiScan(onObservation = () => {}) {
  const collector = 'spy.wifi';
  section('WiFi 扫描');
  const attempts = [];

  try {
    let networks;
    if (isWin) {
      const result = run('netsh', ['wlan', 'show', 'networks', 'mode=bssid']);
      attempts.push({ command: 'netsh', return_code: result.returnCode });
      networks = parseWindowsWifi(result.stdout);
    } else if (process.platform === 'darwin') {
      const airportPath = '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';
      try {
        const result = run(airportPath, ['-s'], { timeout: 7000 });
        attempts.push({ command: airportPath, return_code: result.returnCode });
        networks = parseAirportOutput(result.stdout);
      } catch (airportError) {
        attempts.push({
          command: airportPath,
          status: airportError instanceof CommandExecutionError ? 'command_failed' : 'parse_failed',
          error: airportError.message,
          ...commandFailureFields(airportError),
        });
        warn(`airport 不可用或输出无法识别，回退到 system_profiler：${airportError.message}`);
        const result = run('system_profiler', ['SPAirPortDataType', '-json'], { timeout: 15000 });
        attempts.push({ command: 'system_profiler', return_code: result.returnCode });
        let data;
        try {
          data = JSON.parse(result.stdout);
        } catch (error) {
          throw new ParseFailure(`system_profiler WiFi JSON 解析失败：${error.message}`, error);
        }
        networks = parseSystemProfilerWifi(data);
      }
    } else {
      const result = run('nmcli', [
        '-t', '--escape', 'yes', '-f', 'SSID,SECURITY,SIGNAL,BSSID',
        'device', 'wifi', 'list', '--rescan', 'auto',
      ]);
      attempts.push({ command: 'nmcli', return_code: result.returnCode });
      networks = parseNmcliWifi(result.stdout);
    }

    const observations = presentWifiNetworks(networks, onObservation);
    return collectorSuccess(collector, observations, { attempts });
  } catch (error) {
    warn(`WiFi 扫描失败：${error.message}`);
    return collectorFailure(collector, error, attempts);
  }
}

function parseWindowsBluetooth(output) {
  if (!output.trim()) return [];
  let data;
  try {
    data = JSON.parse(output);
  } catch (error) {
    throw new ParseFailure(`PowerShell 蓝牙 JSON 解析失败：${error.message}`, error);
  }
  const items = Array.isArray(data) ? data : data ? [data] : [];
  return items.map(item => {
    const name = item.FriendlyName || item.Name || '未知设备';
    const macMatch = String(item.InstanceId || '').match(/(?:^|[^0-9A-F])([0-9A-F]{12})(?:[^0-9A-F]|$)/i);
    const address = macMatch
      ? normalizeMAC(macMatch[1].match(/.{2}/g).join(':'))
      : 'N/A';
    return { name: String(name), address, state: String(item.Status || '') };
  });
}

function parseSystemProfilerBluetooth(data) {
  const devices = [];
  const structuralKeys = new Set([
    'spbluetoothdatatype', 'deviceconnected', 'devicenotconnected', 'devices',
    'bluetoothledevicelist', 'items',
  ]);

  function visit(value, context = {}) {
    if (Array.isArray(value)) {
      value.forEach(item => visit(item, context));
      return;
    }
    if (!value || typeof value !== 'object') return;

    const rawAddress = pickField(value, ['device_address', 'address', 'bluetooth_address', 'mac_address']);
    if (rawAddress && hasAddress(scalarText(rawAddress))) {
      const rawName = pickField(value, [
        'product_name', 'device_name', 'friendly_name', 'name', '_name', 'Name',
      ]);
      const connected = pickField(value, ['device_isconnected', 'connected', 'is_connected']);
      let state = context.state || '';
      if (!state && connected !== undefined) {
        state = String(connected).toLowerCase() === 'yes' || connected === true ? '已连接' : '未连接';
      }
      devices.push({
        name: scalarText(rawName).trim() || context.nameHint || '未知设备',
        address: isValidMAC(scalarText(rawAddress)) ? normalizeMAC(scalarText(rawAddress)) : scalarText(rawAddress),
        state,
      });
    }

    for (const [key, child] of Object.entries(value)) {
      const canonical = canonicalKey(key);
      const childContext = { ...context };
      if (canonical === 'deviceconnected') childContext.state = '已连接';
      if (canonical === 'devicenotconnected') childContext.state = '未连接';
      if (child && typeof child === 'object' && !Array.isArray(child) && !structuralKeys.has(canonical)) {
        childContext.nameHint = key;
      }
      visit(child, childContext);
    }
  }

  visit(data);
  return uniqueBy(devices, device => `${device.address}|${device.name}`);
}

function parseBluetoothctl(output) {
  const devices = [];
  let nonEmptyLines = 0;
  const rowPattern = new RegExp(`^\\s*Device\\s+(${MAC_SOURCE})\\s+(.+?)\\s*$`, 'i');
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    nonEmptyLines++;
    const match = line.match(rowPattern);
    if (match) devices.push({ name: match[2], address: normalizeMAC(match[1]), state: '' });
  }
  if (nonEmptyLines > 0 && devices.length === 0) throw new ParseFailure('bluetoothctl 输出格式无法识别');
  return devices;
}

function presentBluetoothDevices(devices, onObservation) {
  if (devices.length === 0) {
    info('蓝牙命令执行成功，当前未返回设备');
    return [];
  }

  info(`发现 ${devices.length} 个蓝牙设备\n`);
  humanLog(color('bold', `  ${'设备名'.padEnd(30)} ${'地址'.padEnd(20)} 状态`));
  humanLog('  ' + '─'.repeat(70));
  const suspiciousNames = ['camera', 'spy', 'hidden', 'wireless', 'cctv', 'secur', 'vision'];

  return devices.map(device => {
    const name = String(device.name || '未知设备');
    const address = String(device.address || 'N/A');
    const state = String(device.state || '');
    let note = '';
    if (name === '未知设备' || name === '') note = '名称未知';
    else if (suspiciousNames.some(keyword => name.toLowerCase().includes(keyword))) note = '关键词匹配';

    const observation = { ...device, name, address, state, ...(note ? { note } : {}) };
    const row = `  ${name.padEnd(30)} ${address.padEnd(20)} ${state}`;
    if (note) alert(`${row}  ${color('red', note)}`);
    else info(row);
    onObservation(observation);
    return observation;
  });
}

function bluetoothScan(onObservation = () => {}) {
  const collector = 'spy.bluetooth';
  section('蓝牙扫描');
  const attempts = [];

  try {
    let devices;
    if (isWin) {
      const script = "Get-PnpDevice -Class Bluetooth | Where-Object {$_.Status -ne 'Error'} | Select-Object FriendlyName,InstanceId,Status | ConvertTo-Json -Compress";
      const result = run('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { timeout: 10000 });
      attempts.push({ command: 'powershell', return_code: result.returnCode });
      devices = parseWindowsBluetooth(result.stdout);
    } else if (process.platform === 'darwin') {
      const result = run('system_profiler', ['SPBluetoothDataType', '-json'], { timeout: 15000 });
      attempts.push({ command: 'system_profiler', return_code: result.returnCode });
      let data;
      try {
        data = JSON.parse(result.stdout);
      } catch (error) {
        throw new ParseFailure(`system_profiler 蓝牙 JSON 解析失败：${error.message}`, error);
      }
      devices = parseSystemProfilerBluetooth(data);
    } else {
      const result = run('bluetoothctl', ['devices'], { timeout: 10000 });
      attempts.push({ command: 'bluetoothctl', return_code: result.returnCode });
      devices = parseBluetoothctl(result.stdout);
    }

    const observations = presentBluetoothDevices(devices, onObservation);
    return collectorSuccess(collector, observations, { attempts });
  } catch (error) {
    warn(`蓝牙扫描失败：${error.message}`);
    return collectorFailure(collector, error, attempts);
  }
}

function emitJSON(event) {
  process.stdout.write(JSON.stringify(event) + '\n');
}

function emitCollectorStatus(runId, collector) {
  emitJSON({
    schema_version: 1,
    run_id: runId,
    event_type: 'collector_status',
    collector,
    status: 'running',
    observed_at: new Date().toISOString(),
  });
}

function emitCollectorComplete(runId, result) {
  const event = {
    schema_version: 1,
    run_id: runId,
    event_type: 'collector_complete',
    collector: result.collector,
    status: result.status,
    object_count: result.items.length,
    zero_objects: result.status === 'success' && result.items.length === 0,
    observed_at: new Date().toISOString(),
  };
  if (result.error) event.error = result.error;
  if (result.returnCode !== undefined) event.return_code = result.returnCode;
  if (result.timedOut !== undefined) event.timed_out = result.timedOut;
  if (result.timeoutMs !== undefined) event.timeout_ms = result.timeoutMs;
  if (result.signal) event.signal = result.signal;
  if (result.stdout) event.stdout = result.stdout;
  if (result.stderr) event.stderr = result.stderr;
  if (result.attempts && result.attempts.length > 0) event.attempts = result.attempts;
  emitJSON(event);
}

function observationEvent(runId, source, attributes) {
  let identity;
  if (source === 'spy.network') {
    identity = isValidMAC(attributes.mac)
      ? { type: 'mac', value: normalizeMAC(attributes.mac) }
      : { type: 'ip', value: attributes.ip };
  } else if (source === 'spy.wifi') {
    identity = isValidMAC(attributes.bssid)
      ? { type: 'bssid', value: normalizeMAC(attributes.bssid) }
      : { type: 'ssid', value: attributes.ssid };
  } else {
    identity = hasAddress(attributes.address)
      ? { type: 'bluetooth', value: isValidMAC(attributes.address) ? normalizeMAC(attributes.address) : attributes.address }
      : { type: 'name', value: attributes.name };
  }

  return {
    schema_version: 1,
    run_id: runId,
    source,
    kind: 'observation',
    observed_at: new Date().toISOString(),
    identity,
    attributes,
  };
}

function parseOptions(args) {
  const selected = new Set();
  let runId = null;
  let useJSONL = false;
  let help = false;

  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === '--jsonl') {
      useJSONL = true;
    } else if (arg === '--run-id') {
      const value = args[index + 1];
      if (!value || value.startsWith('-') || /[\r\n\0]/.test(value)) {
        throw new CLIUsageError('--run-id 需要提供不含控制符的非空 ID');
      }
      runId = value;
      index++;
    } else if (arg === '--network' || arg === '-n') {
      selected.add('network');
    } else if (arg === '--wifi' || arg === '-w') {
      selected.add('wifi');
    } else if (arg === '--bluetooth' || arg === '-b') {
      selected.add('bluetooth');
    } else if (arg === '--help' || arg === '-h') {
      help = true;
    } else {
      throw new CLIUsageError(`未知参数: ${arg}`);
    }
  }

  return {
    selected: selected.size > 0 ? selected : new Set(['network', 'wifi', 'bluetooth']),
    runId: runId || randomUUID(),
    useJSONL,
    help,
  };
}

function printUsage() {
  process.stderr.write(`用法: spy_detector [选项]\n\n` +
    `  无参数         运行全部扫描\n` +
    `  --network, -n  仅网络扫描\n` +
    `  --wifi, -w     仅 WiFi 扫描\n` +
    `  --bluetooth,-b 仅蓝牙扫描\n` +
    `  --jsonl        stdout 仅输出 JSON Lines；人类日志写入 stderr\n` +
    `  --run-id <id>  指定 JSONL 运行 ID（默认自动生成）\n` +
    `  --help, -h     显示此帮助（stdout 保持为空）\n`);
}

function printSummary(results) {
  section('探测汇总');
  const byCollector = new Map(results.map(result => [result.collector, result]));
  const network = byCollector.get('spy.network') || collectorSuccess('spy.network', []);
  const wifi = byCollector.get('spy.wifi') || collectorSuccess('spy.wifi', []);
  const bluetooth = byCollector.get('spy.bluetooth') || collectorSuccess('spy.bluetooth', []);
  const failed = results.filter(result => result.status !== 'success');

  const suspiciousNetwork = network.items.filter(item => item.suspicious).length;
  const suspiciousWifi = wifi.items.filter(item => item.note).length;
  const suspiciousBluetooth = bluetooth.items.filter(item => item.note).length;
  const totalSuspicious = suspiciousNetwork + suspiciousWifi + suspiciousBluetooth;

  humanLog(color('bold', `  网络扫描:   ${network.items.length} 个设备  状态:${network.status}`));
  humanLog(color('bold', `  WiFi 扫描:  ${wifi.items.length} 个网络  状态:${wifi.status}`));
  humanLog(color('bold', `  蓝牙扫描:   ${bluetooth.items.length} 个设备  状态:${bluetooth.status}`));

  if (failed.length > 0) {
    warn(`有 ${failed.length} 个采集通道失败；零对象不能解释为“未发现风险”`);
    for (const result of failed) warn(`${result.collector}: ${result.status} — ${result.error || '未知错误'}`);
    return;
  }

  info('所选采集通道均已成功完成');
  if (totalSuspicious === 0) {
    info('未发现明显可疑设备，但该结果仅覆盖本次成功采集到的数据');
    humanLog(color('yellow', `\n  提示: 本脚本只能检测联网/发射信号的设备\n  提示: 离线存储型摄像头（SD 卡录像）无法通过网络检测\n  提示: 建议物理检查烟雾报警器、插座、时钟、充电器等位置\n`));
  } else {
    alert(`发现 ${totalSuspicious} 个可疑项，建议进一步排查！`);
  }
}

async function executeCollector(options, collector, scanner) {
  if (jsonlMode) emitCollectorStatus(options.runId, collector);
  const result = await scanner(observation => {
    if (jsonlMode) emitJSON(observationEvent(options.runId, collector, observation));
  });
  if (jsonlMode) emitCollectorComplete(options.runId, result);
  return result;
}

async function main() {
  const options = parseOptions(process.argv.slice(2));
  jsonlMode = options.useJSONL;

  if (options.help) {
    printUsage();
    return 0;
  }

  humanLog(color('bold', color('cyan', `\n╔══════════════════════════════════════════════════════╗\n║       家庭监控探测工具 — 跨平台独立版                  ║\n║       Windows / macOS / Linux 通用                  ║\n╚══════════════════════════════════════════════════════╝\n`)));
  humanLog(color('cyan', `  系统: ${process.platform} ${process.arch}  Node: ${process.version}`));

  const results = [];
  if (options.selected.has('network')) {
    results.push(await executeCollector(options, 'spy.network', networkScan));
  }
  if (options.selected.has('wifi')) {
    results.push(await executeCollector(options, 'spy.wifi', wifiScan));
  }
  if (options.selected.has('bluetooth')) {
    results.push(await executeCollector(options, 'spy.bluetooth', bluetoothScan));
  }

  printSummary(results);
  return results.some(result => result.status !== 'success') ? 1 : 0;
}

main()
  .then(exitCode => { process.exitCode = exitCode; })
  .catch(error => {
    console.error(color('red', `错误: ${error.message}`));
    if (error instanceof CLIUsageError) printUsage();
    process.exitCode = error.exitCode || 1;
  });
