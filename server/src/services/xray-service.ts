import { spawn } from 'child_process';
import { existsSync } from 'fs';
import { appendFile, mkdir, readFile, rm, writeFile } from 'fs/promises';
import type { ServiceStatus } from '@xray-manager/shared';
import { systemctl, exec } from '../utils/shell.js';
import { CONFIG_FILE, IS_WINDOWS, LOG_DIR, SERVICE_NAME, XRAY_BIN, XRAY_LOG_FILE, XRAY_PID_FILE, BASE_DIR } from '../constants.js';
import { getInstalledVersion } from './xray-download-service.js';

const SUPERVISOR_PROGRAM = 'xray-all:xray';

async function supervisorctl(action: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return exec('supervisorctl', [action, SUPERVISOR_PROGRAM]);
}

async function serviceAction(action: 'start' | 'stop' | 'restart'): Promise<void> {
  if (IS_WINDOWS) {
    if (action === 'start') return startManagedXray();
    if (action === 'stop') return stopManagedXray();
    await stopManagedXray();
    return startManagedXray();
  }

  try {
    const r = await systemctl(action, SERVICE_NAME);
    if (r.code === 0) return;
  } catch {}

  try {
    const r = await supervisorctl(action);
    if (r.code === 0) return;
  } catch {}

  // Cross-platform fallback for development or native non-systemd installs.
  if (action === 'start') return startManagedXray();
  if (action === 'stop') return stopManagedXray();
  await stopManagedXray();
  return startManagedXray();
}

async function getSystemdStatus(): Promise<ServiceStatus | null> {
  if (IS_WINDOWS) return null;
  try {
    const statusResult = await systemctl('is-active', SERVICE_NAME);
    const running = statusResult.stdout === 'active';
    if (!running) return { running: false, listenPorts: [] };

    const showResult = await systemctl('show', SERVICE_NAME);
    const props = parseSystemdProps(showResult.stdout);
    const pid = props.MainPID ? parseInt(props.MainPID) : undefined;
    const uptime = props.ActiveEnterTimestamp
      ? formatUptime(Date.now() - new Date(props.ActiveEnterTimestamp).getTime())
      : undefined;
    return await buildRunningStatus(pid, uptime, 'systemd');
  } catch {
    return null;
  }
}

async function getSupervisorStatus(): Promise<ServiceStatus | null> {
  if (IS_WINDOWS) return null;
  try {
    const r = await supervisorctl('status');
    if (r.code !== 0) return null;
    if (!r.stdout.includes('RUNNING')) return { running: false, listenPorts: [] };
    const pidMatch = r.stdout.match(/pid\s+(\d+)/);
    const uptimeMatch = r.stdout.match(/uptime\s+(.+?)(?:,|$)/);
    const pid = pidMatch ? parseInt(pidMatch[1]) : undefined;
    return await buildRunningStatus(pid, uptimeMatch?.[1], 'supervisor');
  } catch {
    return null;
  }
}

async function getManagedStatus(): Promise<ServiceStatus | null> {
  const pid = await readPid();
  if (!pid) return { running: false, listenPorts: [] };
  if (!(await isPidRunning(pid))) {
    await rm(XRAY_PID_FILE, { force: true }).catch(() => {});
    return { running: false, listenPorts: [] };
  }
  return buildRunningStatus(pid, undefined, 'managed-process');
}

async function buildRunningStatus(pid?: number, uptime?: string, manager?: string): Promise<ServiceStatus> {
  let memory: string | undefined;
  if (pid) {
    try {
      if (IS_WINDOWS) {
        const ps = await exec('powershell.exe', ['-NoProfile', '-Command', `(Get-Process -Id ${pid}).WorkingSet64`]);
        const bytes = parseInt(ps.stdout);
        if (!isNaN(bytes)) memory = formatMemory(bytes);
      } else {
        const memResult = await exec('ps', ['-o', 'rss=', '-p', String(pid)]);
        const rssKb = parseInt(memResult.stdout);
        if (!isNaN(rssKb)) memory = formatMemory(rssKb * 1024);
      }
    } catch {}
  }

  const version = await getVersion();
  const listenPorts = await getListenPorts(pid);
  return { running: true, pid, memory, uptime, version, listenPorts, manager } as ServiceStatus & { manager?: string };
}

export async function getStatus(): Promise<ServiceStatus> {
  const systemdStatus = await getSystemdStatus();
  if (systemdStatus?.running) return systemdStatus;

  const supervisorStatus = await getSupervisorStatus();
  if (supervisorStatus?.running) return supervisorStatus;

  const managedStatus = await getManagedStatus();
  if (managedStatus) return managedStatus;

  return systemdStatus || supervisorStatus || { running: false, listenPorts: [] };
}

export async function getVersion(): Promise<string | undefined> {
  try {
    return await getInstalledVersion();
  } catch {
    return undefined;
  }
}

export async function startXray(): Promise<void> {
  await serviceAction('start');
}

export async function stopXray(): Promise<void> {
  await serviceAction('stop');
}

export async function restartXray(): Promise<void> {
  await serviceAction('restart');
}

async function startManagedXray(): Promise<void> {
  if (!existsSync(XRAY_BIN)) {
    throw new Error(`Xray binary not found: ${XRAY_BIN}. This package should include Xray in bin/. Please download the bundled release ZIP again.`);
  }
  const pid = await readPid();
  if (pid && await isPidRunning(pid)) return;
  if (!existsSync(CONFIG_FILE)) throw new Error(`Xray config file not found: ${CONFIG_FILE}`);

  await mkdir(LOG_DIR, { recursive: true });
  await appendFile(XRAY_LOG_FILE, `\n--- starting xray at ${new Date().toISOString()} ---\n`).catch(() => {});

  const child = spawn(XRAY_BIN, ['run', '-config', CONFIG_FILE], {
    cwd: BASE_DIR,
    detached: !IS_WINDOWS,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });

  child.stdout?.on('data', (d) => appendFile(XRAY_LOG_FILE, d).catch(() => {}));
  child.stderr?.on('data', (d) => appendFile(XRAY_LOG_FILE, d).catch(() => {}));
  child.on('exit', () => rm(XRAY_PID_FILE, { force: true }).catch(() => {}));

  await mkdir(LOG_DIR, { recursive: true });
  await mkdir(await dirnameOf(XRAY_PID_FILE), { recursive: true });
  await writeFile(XRAY_PID_FILE, String(child.pid), 'utf-8');
  child.unref();
}

async function stopManagedXray(): Promise<void> {
  const pid = await readPid();
  if (!pid) return;
  try {
    if (IS_WINDOWS) {
      await exec('taskkill.exe', ['/PID', String(pid), '/T', '/F'], { timeout: 10000 }).catch(() => undefined);
    } else {
      process.kill(pid, 'SIGTERM');
      await new Promise((r) => setTimeout(r, 500));
      if (await isPidRunning(pid)) process.kill(pid, 'SIGKILL');
    }
  } catch {}
  await rm(XRAY_PID_FILE, { force: true }).catch(() => {});
}

async function readPid(): Promise<number | undefined> {
  try {
    const n = parseInt((await readFile(XRAY_PID_FILE, 'utf-8')).trim());
    return isNaN(n) ? undefined : n;
  } catch {
    return undefined;
  }
}

async function isPidRunning(pid: number): Promise<boolean> {
  try {
    if (IS_WINDOWS) {
      const r = await exec('tasklist.exe', ['/FI', `PID eq ${pid}`, '/FO', 'CSV', '/NH'], { timeout: 10000 });
      return r.stdout.includes(String(pid));
    }
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function getListenPorts(pid?: number): Promise<string[]> {
  if (!pid) return [];
  try {
    if (IS_WINDOWS) {
      const result = await exec('netstat.exe', ['-ano', '-p', 'tcp'], { timeout: 15000 });
      const ports: string[] = [];
      for (const line of result.stdout.split('\n')) {
        if (!line.trim().endsWith(String(pid))) continue;
        const parts = line.trim().split(/\s+/);
        const local = parts[1] || '';
        const m = local.match(/:(\d+)$/);
        if (m) ports.push(m[1]);
      }
      return [...new Set(ports)];
    }
    const result = await exec('ss', ['-tlnp']);
    const ports: string[] = [];
    for (const line of result.stdout.split('\n')) {
      if (line.includes(`pid=${pid}`)) {
        const match = line.match(/:(\d+)\s/);
        if (match) ports.push(match[1]);
      }
    }
    return [...new Set(ports)];
  } catch {
    return [];
  }
}

function parseSystemdProps(output: string): Record<string, string> {
  const props: Record<string, string> = {};
  for (const line of output.split('\n')) {
    const [key, ...value] = line.split('=');
    if (key && value.length > 0) props[key] = value.join('=');
  }
  return props;
}

function formatUptime(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  return parts.join(' ') || '< 1m';
}

function formatMemory(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

async function dirnameOf(path: string): Promise<string> {
  const mod = await import('path');
  return mod.dirname(path);
}
