import { readFile, writeFile, rename, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import { dirname, join } from 'path';

/**
 * Read and parse a JSON file. Returns defaultValue if file doesn't exist.
 */
export async function readJson<T>(path: string, defaultValue: T): Promise<T> {
  try {
    const content = await readFile(path, 'utf-8');
    return JSON.parse(content) as T;
  } catch (err: any) {
    if (err.code === 'ENOENT') {
      return defaultValue;
    }
    throw err;
  }
}

/**
 * Atomically write JSON to a file with backup.
 * Writes to a temp file first, then renames (atomic on same filesystem).
 * Keeps a .bak backup of the previous version.
 */
export async function writeJson<T>(path: string, data: T): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true });

  const tmpPath = path + '.tmp';
  const bakPath = path + '.bak';

  // Create backup if file exists
  if (existsSync(path)) {
    try {
      await rename(path, bakPath);
    } catch {
      // Ignore backup failures
    }
  }

  // Write to temp file first
  const content = JSON.stringify(data, null, 2) + '\n';
  await writeFile(tmpPath, content, 'utf-8');

  // Atomic rename
  await rename(tmpPath, path);
}

/**
 * Ensure a directory exists.
 */
export async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true });
}

/**
 * Read a text file, returning defaultValue if not found.
 */
export async function readText(path: string, defaultValue: string = ''): Promise<string> {
  try {
    return await readFile(path, 'utf-8');
  } catch (err: any) {
    if (err.code === 'ENOENT') return defaultValue;
    throw err;
  }
}

/**
 * Write text to a file, creating parent directories if needed.
 */
export async function writeText(path: string, content: string): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true });
  await writeFile(path, content, 'utf-8');
}
