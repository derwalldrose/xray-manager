
import { readFile, writeFile, rename } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';

const RESOLV_CONF = '/etc/resolv.conf';
const BACKUP_PATH = '/etc/resolv.conf.xray-backup';

export async function isHijacked(): Promise<boolean> {
  try {
    const content = await readFile(RESOLV_CONF, 'utf-8');
    return content.includes('nameserver 127.0.0.1');
  } catch {
    return false;
  }
}

export async function applyHijack(): Promise<void> {
  // Backup if no backup exists
  if (!existsSync(BACKUP_PATH)) {
    try {
      const orig = await readFile(RESOLV_CONF, 'utf-8');
      await writeFile(BACKUP_PATH, orig, 'utf-8');
    } catch {}
  }
  
  // Write hijacked resolv.conf
  await writeFile(RESOLV_CONF, 'nameserver 127.0.0.1\n', 'utf-8');
}

export async function restoreHijack(): Promise<void> {
  if (existsSync(BACKUP_PATH)) {
    try {
      await writeFile(RESOLV_CONF, await readFile(BACKUP_PATH, 'utf-8'), 'utf-8');
    } catch {}
  } else {
    // Default
    await writeFile(RESOLV_CONF, 'nameserver 8.8.8.8\nnameserver 1.1.1.1\n', 'utf-8');
  }
}

export async function getResolvConf(): Promise<string> {
  try {
    return await readFile(RESOLV_CONF, 'utf-8');
  } catch {
    return '';
  }
}
