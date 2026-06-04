
import { readdir, stat } from 'fs/promises';
import { join } from 'path';
import { existsSync } from 'fs';
import { DATA_DIR, CONFIG_DIR } from '../constants.js';
import { exec } from '../utils/shell.js';
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

export async function updateGeoFiles(): Promise<{ ok: boolean; results: { name: string; ok: boolean; error?: string }[] }> {
  const urls = await getGeoUrls();
  const results: { name: string; ok: boolean; error?: string }[] = [];
  
  for (const [name, url] of Object.entries(urls)) {
    const target = join(DATA_DIR, name === 'geosite' ? 'geosite.dat' : 'geoip.dat');
    try {
      const r = await exec('curl', ['-fsSL', '-o', target + '.tmp', url], { timeout: 60000 });
      if (r.code !== 0) throw new Error(r.stderr || 'download failed');
      await exec('mv', [target + '.tmp', target]);
      results.push({ name, ok: true });
    } catch (e: any) {
      results.push({ name, ok: false, error: e.message });
    }
  }
  return { ok: results.every(r => r.ok), results };
}
