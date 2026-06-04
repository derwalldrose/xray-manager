import type { ServiceStatus } from '@xray-manager/shared';
import { systemctl, exec } from '../utils/shell.js';
import { SERVICE_NAME, XRAY_BIN } from '../constants.js';

const SUPERVISOR_PROGRAM = 'xray-all:xray';

async function supervisorctl(action: string): Promise<{ stdout: string; stderr: string; code: number }> {
  return exec('supervisorctl', [action, SUPERVISOR_PROGRAM]);
}

async function serviceAction(action: 'start' | 'stop' | 'restart'): Promise<void> {
  try {
    const r = await systemctl(action, SERVICE_NAME);
    if (r.code === 0) return;
  } catch {}

  const r = await supervisorctl(action);
  if (r.code !== 0) {
    throw new Error(`Failed to ${action} Xray via systemd and supervisor: ${r.stderr || r.stdout}`);
  }
}

async function getSystemdStatus(): Promise<ServiceStatus | null> {
  try {
    // Check if service is active
    const statusResult = await systemctl('is-active', SERVICE_NAME);
    const running = statusResult.stdout === 'active';
    
    if (!running) {
      return {
        running: false,
        listenPorts: [],
      };
    }
    
    // Get service details
    const showResult = await systemctl('show', SERVICE_NAME);
    const props = parseSystemdProps(showResult.stdout);
    
    const pid = props.MainPID ? parseInt(props.MainPID) : undefined;
    const uptime = props.ActiveEnterTimestamp 
      ? formatUptime(Date.now() - new Date(props.ActiveEnterTimestamp).getTime())
      : undefined;
    
    return await buildRunningStatus(pid, uptime);
  } catch {
    return null;
  }
}

async function getSupervisorStatus(): Promise<ServiceStatus | null> {
  try {
    const r = await supervisorctl('status');
    if (r.code !== 0) return null;
    if (!r.stdout.includes('RUNNING')) return { running: false, listenPorts: [] };
    const pidMatch = r.stdout.match(/pid\s+(\d+)/);
    const uptimeMatch = r.stdout.match(/uptime\s+(.+?)(?:,|$)/);
    const pid = pidMatch ? parseInt(pidMatch[1]) : undefined;
    return await buildRunningStatus(pid, uptimeMatch?.[1]);
  } catch {
    return null;
  }
}

async function buildRunningStatus(pid?: number, uptime?: string): Promise<ServiceStatus> {
  let memory: string | undefined;
  if (pid) {
    try {
      const memResult = await exec('ps', ['-o', 'rss=', '-p', String(pid)]);
      const rssKb = parseInt(memResult.stdout);
      if (!isNaN(rssKb)) {
        memory = formatMemory(rssKb * 1024);
      }
    } catch {}
  }
  
  const version = await getVersion();
  const listenPorts = await getListenPorts(pid);
  
  return {
    running: true,
    pid,
    memory,
    uptime,
    version,
    listenPorts,
  };
}

/**
 * Get Xray service status via systemctl
 */
export async function getStatus(): Promise<ServiceStatus> {
  const systemdStatus = await getSystemdStatus();
  if (systemdStatus) return systemdStatus;

  const supervisorStatus = await getSupervisorStatus();
  if (supervisorStatus) return supervisorStatus;

  return {
    running: false,
    listenPorts: [],
  };
}

/**
 * Get Xray version
 */
export async function getVersion(): Promise<string | undefined> {
  try {
    const result = await exec(XRAY_BIN, ['version']);
    const match = result.stdout.match(/Xray (\S+)/);
    return match ? match[1] : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Start Xray service
 */
export async function startXray(): Promise<void> {
  await serviceAction('start');
}

/**
 * Stop Xray service
 */
export async function stopXray(): Promise<void> {
  await serviceAction('stop');
}

/**
 * Restart Xray service
 */
export async function restartXray(): Promise<void> {
  await serviceAction('restart');
}

/**
 * Get listening ports for a process
 */
async function getListenPorts(pid?: number): Promise<string[]> {
  if (!pid) return [];
  
  try {
    const result = await exec('ss', ['-tlnp']);
    const lines = result.stdout.split('\n');
    const ports: string[] = [];
    
    for (const line of lines) {
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

/**
 * Parse systemd show output into key-value pairs
 */
function parseSystemdProps(output: string): Record<string, string> {
  const props: Record<string, string> = {};
  for (const line of output.split('\n')) {
    const [key, ...value] = line.split('=');
    if (key && value.length > 0) {
      props[key] = value.join('=');
    }
  }
  return props;
}

/**
 * Format uptime from milliseconds
 */
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

/**
 * Format memory from bytes
 */
function formatMemory(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
