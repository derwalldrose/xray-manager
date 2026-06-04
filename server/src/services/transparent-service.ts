
import { readFile, writeFile } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { CONFIG_FILE, DATA_DIR, XRAY_BIN } from '../constants.js';
import { setupTransparentProxy, cleanupTransparentProxy, hasIptablesRules, hasQuicBlock } from './iptables-service.js';
import { applyHijack, restoreHijack, isHijacked } from './dns-hijack-service.js';
import { readJson, writeJson } from '../utils/file.js';
import { exec } from '../utils/shell.js';
import { restartXray } from './xray-service.js';

const STATE_FILE = join(DATA_DIR, 'transparent-state.json');
const BYPASS_FILE = join(DATA_DIR, 'transparent-bypass.json');

const DEFAULT_BYPASS = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
];

interface TransparentState {
  active: boolean;
  redirPort: number;
  strategy: string;
  proxyTag?: string;
}

export async function getState(): Promise<TransparentState> {
  return await readJson<TransparentState>(STATE_FILE, { active: false, redirPort: 12345, strategy: 'roundRobin' });
}

export async function saveState(state: TransparentState): Promise<void> {
  await writeJson(STATE_FILE, state);
}

export async function getBypassCidrs(): Promise<string[]> {
  return await readJson<string[]>(BYPASS_FILE, DEFAULT_BYPASS);
}

export async function saveBypassCidrs(cidrs: string[]): Promise<void> {
  await writeJson(BYPASS_FILE, cidrs);

  // If transparent proxy is currently active, rebuild the runtime iptables chains
  // immediately so the saved CIDRs are not just persisted for the next enable.
  const state = await getState();
  if (state.active) {
    await setupTransparentProxy(state.redirPort || 12345, cidrs);
  }
}

export async function enableTransparent(redirPort: number = 12345): Promise<TransparentState> {
  const bypass = await getBypassCidrs();
  
  // Setup iptables
  await setupTransparentProxy(redirPort, bypass);
  
  // Apply DNS hijack
  await applyHijack();
  
  // Save state
  const state: TransparentState = { active: true, redirPort, strategy: 'roundRobin' };
  await saveState(state);
  
  return state;
}

export async function disableTransparent(): Promise<TransparentState> {
  // Cleanup iptables
  await cleanupTransparentProxy();
  
  // Restore DNS
  await restoreHijack();
  
  // Save state
  const state: TransparentState = { active: false, redirPort: 12345, strategy: 'roundRobin' };
  await saveState(state);
  
  return state;
}

export async function getStatus() {
  const state = await getState();
  const hasRules = await hasIptablesRules();
  const quicBlock = await hasQuicBlock();
  const dnsHijacked = await isHijacked();
  const bypass = await getBypassCidrs();
  
  return {
    ...state,
    hasIptables: hasRules,
    hasQuicBlock: quicBlock,
    dnsHijacked,
    bypassCidrs: bypass,
  };
}

export async function toggleDnsHijack(): Promise<{ hijacked: boolean }> {
  const hijacked = await isHijacked();
  if (hijacked) {
    await restoreHijack();
    return { hijacked: false };
  } else {
    await applyHijack();
    return { hijacked: true };
  }
}
