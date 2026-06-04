import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { IS_WINDOWS } from '../constants.js';

const RESOLV_CONF = '/etc/resolv.conf';
const BACKUP_PATH = '/etc/resolv.conf.xray-backup';

export function dnsHijackSupported(): boolean {
  return !IS_WINDOWS;
}

export async function isHijacked(): Promise<boolean> {
  if (IS_WINDOWS) return false;
  try {
    const content = await readFile(RESOLV_CONF, 'utf-8');
    return content.includes('nameserver 127.0.0.1');
  } catch {
    return false;
  }
}

export async function applyHijack(): Promise<void> {
  if (IS_WINDOWS) {
    throw new Error('Windows native mode does not support /etc/resolv.conf DNS hijack. Use system proxy/PAC or configure Windows DNS separately.');
  }
  if (!existsSync(BACKUP_PATH)) {
    try {
      const orig = await readFile(RESOLV_CONF, 'utf-8');
      await writeFile(BACKUP_PATH, orig, 'utf-8');
    } catch {}
  }
  await writeFile(RESOLV_CONF, 'nameserver 127.0.0.1\n', 'utf-8');
}

export async function restoreHijack(): Promise<void> {
  if (IS_WINDOWS) return;
  if (existsSync(BACKUP_PATH)) {
    try {
      await writeFile(RESOLV_CONF, await readFile(BACKUP_PATH, 'utf-8'), 'utf-8');
    } catch {}
  } else {
    await writeFile(RESOLV_CONF, 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n', 'utf-8');
  }
}

export async function getResolvConf(): Promise<string> {
  if (IS_WINDOWS) return 'Windows native mode: /etc/resolv.conf is not available. DNS hijack is disabled.';
  try {
    return await readFile(RESOLV_CONF, 'utf-8');
  } catch {
    return '';
  }
}
