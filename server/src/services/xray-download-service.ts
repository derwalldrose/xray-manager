import { createWriteStream, existsSync } from 'fs';
import { chmod, mkdir, rm } from 'fs/promises';
import { dirname, join } from 'path';
import { pipeline } from 'stream/promises';
import { exec } from '../utils/shell.js';
import { BIN_DIR, IS_WINDOWS, IS_LINUX, IS_MACOS, XRAY_BIN } from '../constants.js';

const DEFAULT_XRAY_VERSION = process.env.XRAY_VERSION || 'latest';
const GITHUB_RELEASE_BASE = 'https://github.com/XTLS/Xray-core/releases/download';
const GITHUB_LATEST_DOWNLOAD_BASE = 'https://github.com/XTLS/Xray-core/releases/latest/download';

type AssetTarget = {
  os: string;
  arch: string;
  zipName: string;
};

export function getXrayAssetTarget(): AssetTarget {
  const arch = process.arch;
  let archName: string;
  if (arch === 'x64') archName = '64';
  else if (arch === 'ia32') archName = '32';
  else if (arch === 'arm64') archName = 'arm64-v8a';
  else if (arch === 'arm') archName = 'arm32-v7a';
  else throw new Error(`Unsupported CPU architecture for Xray: ${arch}`);

  if (IS_WINDOWS) return { os: 'windows', arch: archName, zipName: `Xray-windows-${archName}.zip` };
  if (IS_LINUX) return { os: 'linux', arch: archName, zipName: `Xray-linux-${archName}.zip` };
  if (IS_MACOS) return { os: 'macos', arch: archName, zipName: `Xray-macos-${archName}.zip` };
  throw new Error(`Unsupported platform for Xray: ${process.platform}`);
}

async function fetchWithTimeout(url: string, init: RequestInit = {}, timeoutMs = 15000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function download(url: string, target: string): Promise<void> {
  await mkdir(dirname(target), { recursive: true });
  const res = await fetchWithTimeout(url, { headers: { 'User-Agent': 'xray-manager-v4' } }, 120000);
  if (!res.ok || !res.body) throw new Error(`Download failed: ${url} HTTP ${res.status}`);
  await pipeline(res.body as any, createWriteStream(target));
}

export async function ensureXrayBinary(): Promise<{ installed: boolean; version?: string; path: string; message: string }> {
  if (existsSync(XRAY_BIN)) {
    const version = await getInstalledVersion().catch(() => undefined);
    return { installed: false, version, path: XRAY_BIN, message: 'Xray binary already exists' };
  }

  const target = getXrayAssetTarget();
  const version = DEFAULT_XRAY_VERSION;
  const url = version === 'latest'
    ? `${GITHUB_LATEST_DOWNLOAD_BASE}/${target.zipName}`
    : `${GITHUB_RELEASE_BASE}/${version}/${target.zipName}`;
  const zipPath = join(BIN_DIR, target.zipName);

  await mkdir(BIN_DIR, { recursive: true });
  await download(url, zipPath);

  // Prefer platform tools. Windows installations normally have PowerShell Expand-Archive.
  if (IS_WINDOWS) {
    const ps = await exec('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', `Expand-Archive -Force -LiteralPath '${zipPath.replace(/'/g, "''")}' -DestinationPath '${BIN_DIR.replace(/'/g, "''")}'`], { timeout: 120000 });
    if (ps.code !== 0) throw new Error(`Failed to extract Xray zip with PowerShell: ${ps.stderr || ps.stdout}`);
  } else {
    const unzip = await exec('unzip', ['-o', zipPath, '-d', BIN_DIR], { timeout: 120000 });
    if (unzip.code !== 0) throw new Error(`Failed to extract Xray zip with unzip: ${unzip.stderr || unzip.stdout}`);
    await chmod(XRAY_BIN, 0o755).catch(() => {});
  }

  await rm(zipPath, { force: true }).catch(() => {});
  const installedVersion = await getInstalledVersion().catch(() => version);
  return { installed: true, version: installedVersion, path: XRAY_BIN, message: `Installed Xray ${installedVersion || version} for ${target.os}/${target.arch}` };
}

export async function getInstalledVersion(): Promise<string | undefined> {
  if (!existsSync(XRAY_BIN)) return undefined;
  const result = await exec(XRAY_BIN, ['version'], { timeout: 10000 });
  const match = result.stdout.match(/Xray\s+(\S+)/);
  return match?.[1];
}
