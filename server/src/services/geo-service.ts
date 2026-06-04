import { stat, rename, writeFile } from 'fs/promises';
import { join } from 'path';
import { DATA_DIR, CONFIG_DIR } from '../constants.js';
import { readJson, writeJson } from '../utils/file.js';

const GEO_URLS_FILE = join(DATA_DIR, 'geo-urls.json');
const DEFAULT_URLS = {
  geoip: 'https://github.com/v2fly/geoip/releases/latest/download/geoip.dat',
  geosite: 'https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat',
};

export interface GeoFileInfo {
  name: string;
  size: number;
  lastModified: string;
  exists: boolean;
}

export async function getGeoInfo(): Promise<GeoFileInfo[]> {
  const files = ['geoip.dat', 'geosite.dat', 'geoip-only-cn-private.dat'];
  const result: GeoFileInfo[] = [];
  
  for (const name of files) {
    const paths = [join(DATA_DIR, name), join(CONFIG_DIR, name)];
    let found = false;
    for (const p of paths) {
      try {
        const s = await stat(p);
        result.push({ name, size: s.size, lastModified: s.mtime.toISOString(), exists: true });
        found = true;
        break;
      } catch {}
    }
    if (!found) {
      result.push({ name, size: 0, lastModified: '', exists: false });
    }
  }
  return result;
}

export async function getGeoUrls(): Promise<{ geoip: string; geosite: string }> {
  return await readJson<{ geoip: string; geosite: string }>(GEO_URLS_FILE, DEFAULT_URLS);
}

export async function saveGeoUrls(urls: { geoip?: string; geosite?: string }): Promise<{ geoip: string; geosite: string }> {
  const current = await getGeoUrls();
  const updated = { ...current, ...urls };
  await writeJson(GEO_URLS_FILE, updated);
  return updated;
}

async function downloadFile(url: string, target: string): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 60000);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { 'User-Agent': 'xray-manager-v4' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length === 0) throw new Error('empty response');
    await writeFile(target + '.tmp', buf);
    await rename(target + '.tmp', target);
  } finally {
    clearTimeout(timer);
  }
}

export async function updateGeoFiles(): Promise<{ ok: boolean; results: { name: string; ok: boolean; error?: string }[] }> {
  const urls = await getGeoUrls();
  const results: { name: string; ok: boolean; error?: string }[] = [];
  
  for (const [name, url] of Object.entries(urls)) {
    const target = join(DATA_DIR, name === 'geosite' ? 'geosite.dat' : 'geoip.dat');
    try {
      await downloadFile(url, target);
      results.push({ name, ok: true });
    } catch (e: any) {
      results.push({ name, ok: false, error: e.message });
    }
  }
  return { ok: results.every(r => r.ok), results };
}
