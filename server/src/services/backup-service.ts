
import { readdir, copyFile, stat } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';
import { CONFIG_FILE, CONFIG_DIR, DATA_DIR } from '../constants.js';
import { exec } from '../utils/shell.js';

const BACKUP_DIR = join(DATA_DIR, 'backups');

export interface BackupInfo {
  name: string;
  timestamp: string;
  size: number;
}

export async function listBackups(): Promise<BackupInfo[]> {
  try {
    const { mkdirSync } = await import('fs');
    mkdirSync(BACKUP_DIR, { recursive: true });
    const files = await readdir(BACKUP_DIR);
    const backups: BackupInfo[] = [];
    
    for (const f of files) {
      if (f.startsWith('xray-') && f.endsWith('.json')) {
        const s = await stat(join(BACKUP_DIR, f));
        backups.push({ name: f, timestamp: s.mtime.toISOString(), size: s.size });
      }
    }
    
    // Also check .bak files in config dir
    try {
      const configFiles = await readdir(CONFIG_DIR);
      for (const f of configFiles) {
        if (f.endsWith('.bak') || f.endsWith('.connect-backup')) {
          const s = await stat(join(CONFIG_DIR, f));
          backups.push({ name: f, timestamp: s.mtime.toISOString(), size: s.size });
        }
      }
    } catch {}
    
    return backups.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
  } catch {
    return [];
  }
}

export async function createBackup(): Promise<{ ok: boolean; name: string; error?: string }> {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const name = `xray-${ts}.json`;
  const target = join(BACKUP_DIR, name);
  
  try {
    const { mkdirSync } = await import('fs');
    mkdirSync(BACKUP_DIR, { recursive: true });
    await copyFile(CONFIG_FILE, target);
    return { ok: true, name };
  } catch (e: any) {
    return { ok: false, name, error: e.message };
  }
}

export async function restoreBackup(name: string): Promise<{ ok: boolean; error?: string }> {
  // Check both backup locations
  const paths = [join(BACKUP_DIR, name), join(CONFIG_DIR, name)];
  let source: string | null = null;
  
  for (const p of paths) {
    if (existsSync(p)) { source = p; break; }
  }
  
  if (!source) return { ok: false, error: 'Backup not found' };
  
  try {
    await copyFile(source, CONFIG_FILE);
    return { ok: true };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}
