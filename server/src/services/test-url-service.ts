
import { join } from 'path';
import { DATA_DIR } from '../constants.js';
import { readJson, writeJson } from '../utils/file.js';

const TEST_URLS_FILE = join(DATA_DIR, 'test-urls.json');
export const DEFAULT_LATENCY_URLS = [
  'https://api.ipify.org',
  'https://icanhazip.com',
  'https://ifconfig.me/ip',
  'https://ipinfo.io/json',
  'https://ip.im/info',
];
const DEFAULT_URLS = {
  latency: DEFAULT_LATENCY_URLS[0],
  speed: 'https://speed.cloudflare.com/__down?bytes=10000000',
  latencyOptions: DEFAULT_LATENCY_URLS,
};

export async function getTestUrls(): Promise<{ latency: string; speed: string; latencyOptions: string[] }> {
  const saved: any = await readJson<any>(TEST_URLS_FILE, DEFAULT_URLS);
  if (Array.isArray(saved)) {
    const latencyOptions = Array.from(new Set([...saved.filter(Boolean), ...DEFAULT_LATENCY_URLS]));
    return { latency: saved[0] || DEFAULT_URLS.latency, speed: DEFAULT_URLS.speed, latencyOptions };
  }
  const latencyOptions = Array.from(new Set([...(saved.latencyOptions || []), ...DEFAULT_LATENCY_URLS]));
  return { ...DEFAULT_URLS, ...saved, latencyOptions };
}

export async function saveTestUrls(urls: { latency?: string; speed?: string; latencyOptions?: string[] }) {
  const current = await getTestUrls();
  const latencyOptions = Array.from(new Set([...(urls.latencyOptions || current.latencyOptions), ...DEFAULT_LATENCY_URLS]));
  if (urls.latency && !latencyOptions.includes(urls.latency)) latencyOptions.unshift(urls.latency);
  const updated = { ...current, ...urls, latencyOptions };
  await writeJson(TEST_URLS_FILE, updated);
  return updated;
}
