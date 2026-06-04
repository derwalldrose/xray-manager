import type { Settings } from '@xray-manager/shared';
import { readJson, writeJson } from '../utils/file.js';
import { SETTINGS_FILE } from '../constants.js';

const DEFAULT_SETTINGS: Settings = {
  ports: {
    socks: 1080,
    http: 1081,
    transparent: 12345,
  },
  dns: {
    servers: [
      '119.29.29.29',
      '223.5.5.5',
      '1.1.1.1',
      '8.8.8.8',
      { address: 'https://dns.alidns.com/dns-query', domains: ['geosite:cn'] },
      { address: 'https://1.1.1.1/dns-query', domains: ['geosite:geolocation-!cn'] },
    ],
    hosts: {
      'geosite:category-ads-all': '127.0.0.1',
    },
  },
  routing: {
    domainStrategy: 'IPIfNonMatch',
    rules: [],
  },
  transparent: {
    enabled: false,
    bypassCidrs: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
  },
  logLevel: 'warning',
};

/**
 * Load settings from settings.json
 */
export async function loadSettings(): Promise<Settings> {
  const saved = await readJson<Partial<Settings>>(SETTINGS_FILE, {});
  return { ...DEFAULT_SETTINGS, ...saved };
}

/**
 * Save settings to settings.json
 */
export async function saveSettings(settings: Settings): Promise<void> {
  await writeJson(SETTINGS_FILE, settings);
}

/**
 * Get current settings
 */
export async function getSettings(): Promise<Settings> {
  return await loadSettings();
}

/**
 * Update settings
 */
export async function updateSettings(updates: Partial<Settings>): Promise<Settings> {
  const current = await loadSettings();
  const updated = { ...current, ...updates };
  await saveSettings(updated);
  return updated;
}

/**
 * Update DNS settings
 */
export async function updateDns(dns: Settings['dns']): Promise<Settings> {
  return await updateSettings({ dns });
}

/**
 * Update routing settings
 */
export async function updateRouting(routing: Settings['routing']): Promise<Settings> {
  return await updateSettings({ routing });
}

/**
 * Get default settings
 */
export function getDefaultSettings(): Settings {
  return { ...DEFAULT_SETTINGS };
}
