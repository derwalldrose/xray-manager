import type { ConnectionState, Connection } from '@xray-manager/shared';
import { readJson, writeJson } from '../utils/file.js';
import { CONNECTIONS_FILE, CONFIG_FILE, XRAY_BIN } from '../constants.js';
import { getNodes } from './node-service.js';
import { generateConfig } from './config-generator.js';
import { writeJson as writeConfig } from '../utils/file.js';
import { restartXray } from './xray-service.js';
import { exec } from '../utils/shell.js';
import { enableTransparent, disableTransparent, getState as getTransparentState } from './transparent-service.js';
import { copyFile, rm } from 'fs/promises';
import { existsSync } from 'fs';

/**
 * Load connections from connections.json
 */
export async function loadConnections(): Promise<ConnectionState> {
  return await readJson<ConnectionState>(CONNECTIONS_FILE, {
    connected: [],
    active: false,
  });
}

/**
 * Save connections to connections.json
 */
export async function saveConnections(state: ConnectionState): Promise<void> {
  await writeJson(CONNECTIONS_FILE, state);
}

/**
 * Get current connections
 */
export async function getConnections(): Promise<ConnectionState> {
  return await loadConnections();
}

/**
 * Connect multiple nodes with strategy
 * 1. Validate all nodeIds exist
 * 2. Backup current config
 * 3. Build connect config with selected nodes
 * 4. Test config via xray run -test
 * 5. Restart Xray
 * 6. Save connection state
 */
export async function connectNodes(
  nodeIds: string[],
  strategy: string = 'roundRobin',
  transparent: boolean = false
): Promise<ConnectionState> {
  const allNodes = await getNodes();
  const nodeMap = new Map(allNodes.map(n => [n.id, n]));
  
  // Validate all nodeIds exist
  const missing: string[] = [];
  for (const id of nodeIds) {
    if (!nodeMap.has(id)) {
      missing.push(id);
    }
  }
  if (missing.length > 0) {
    throw new Error(`Nodes not found: ${missing.join(', ')}`);
  }
  
  // Load existing state
  const state = await loadConnections();
  
  // Build connection entries
  const newConnections: Connection[] = [];
  for (const id of nodeIds) {
    const node = nodeMap.get(id)!;
    if (!state.connected.some(c => c.nodeId === id)) {
      newConnections.push({ nodeId: id, outbound: node.tag });
    }
  }
  
  // Update state
  state.connected = [...state.connected, ...newConnections];
  state.active = true;
  state.startedAt = Date.now();
  
  // Backup config before generating new one
  try {
    if (existsSync(CONFIG_FILE)) await copyFile(CONFIG_FILE, CONFIG_FILE + '.connect-backup');
  } catch {
    // Config might not exist yet
  }
  
  // Save state before generating config (generateConfig reads connections from file)
  await saveConnections(state);
  
  // Generate new config with selected nodes, preserving dynamic inbounds and default bypass rules
  const config = await generateConfig(strategy);
  
  // Test config before applying - write to temp file and test
  const testConfigPath = CONFIG_FILE + '.test';
  try {
    await writeConfig(testConfigPath, config);
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', testConfigPath]);
    if (test.code !== 0) throw new Error(test.stderr || test.stdout || `xray exited with code ${test.code}`);
    // Clean up test file
    await rm(testConfigPath, { force: true });
  } catch (err: any) {
    // Clean up test file
    try { await rm(testConfigPath, { force: true }); } catch {}
    // Rollback: restore saved state
    state.connected = state.connected.filter(c => !nodeIds.includes(c.nodeId));
    if (state.connected.length === 0) {
      state.active = false;
      state.startedAt = undefined;
    }
    await saveConnections(state);
    throw new Error(`Config validation failed: ${err.stderr || err.message}`);
  }
  
  // Write config and restart
  await writeConfig(CONFIG_FILE, config);
  await restartXray();

  // If requested by the UI, connection mode must enable the real transparent-proxy
  // switches too. The permanent dokodemo-door inbound only makes the config ready;
  // iptables REDIRECT + DNS hijack are what make transparent proxy active.
  if (transparent) {
    await enableTransparent();
  }
  
  return state;
}

/**
 * Connect a single node (legacy support)
 */
export async function connectNode(nodeId: string, outbound?: string): Promise<ConnectionState> {
  return connectNodes([nodeId], 'roundRobin', false);
}

/**
 * Disconnect a node
 */
export async function disconnectNode(nodeId: string): Promise<ConnectionState> {
  const state = await loadConnections();
  
  state.connected = state.connected.filter(c => c.nodeId !== nodeId);
  
  if (state.connected.length === 0) {
    state.active = false;
    state.startedAt = undefined;
  }
  
  await saveConnections(state);
  await regenerateAndRestart();
  
  return state;
}

/**
 * Disconnect all nodes
 */
export async function disconnectAll(): Promise<ConnectionState> {
  const state: ConnectionState = {
    connected: [],
    active: false,
  };
  
  await saveConnections(state);

  // Connection-mode stop mirrors v1/v2 behavior: remove transparent-proxy runtime
  // switches (iptables + DNS hijack) while keeping permanent DNS/dokodemo inbounds.
  const tpState = await getTransparentState();
  if (tpState.active) {
    await disableTransparent();
  }
  
  // Restore backup config if exists. Do not immediately regenerate an empty config over it.
  // The backup is the user's pre-connect live config and should preserve DNS/transparent/default routing.
  let restored = false;
  try {
    const backupPath = CONFIG_FILE + '.connect-backup';
    if (existsSync(backupPath)) {
      await copyFile(backupPath, CONFIG_FILE);
      restored = true;
    }
  } catch {
    // No backup, regenerate a safe baseline from the live config/settings.
  }
  
  if (!restored) {
    await regenerateAndRestart();
  } else {
    await restartXray();
  }
  
  return state;
}

/**
 * Regenerate config and restart Xray
 */
async function regenerateAndRestart(): Promise<void> {
  const config = await generateConfig();
  await writeConfig(CONFIG_FILE, config);
  await restartXray();
}
