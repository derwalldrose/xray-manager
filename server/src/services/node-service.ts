import type { Node } from '@xray-manager/shared';
import { readJson, writeJson } from '../utils/file.js';
import { NODES_FILE } from '../constants.js';
import { parseShareLink, parseShareLinks } from '../parsers/index.js';
import { randomUUID } from 'crypto';

/**
 * Load all nodes from nodes.json
 */
export async function loadNodes(): Promise<Node[]> {
  return await readJson<Node[]>(NODES_FILE, []);
}

/**
 * Save all nodes to nodes.json
 */
export async function saveNodes(nodes: Node[]): Promise<void> {
  await writeJson(NODES_FILE, nodes);
}

/**
 * Get all nodes
 */
export async function getNodes(): Promise<Node[]> {
  return await loadNodes();
}

/**
 * Get a node by ID
 */
export async function getNode(id: string): Promise<Node | null> {
  const nodes = await loadNodes();
  return nodes.find(n => n.id === id) || null;
}

/**
 * Add a node
 */
export async function addNode(node: Omit<Node, 'id' | 'createdAt' | 'updatedAt'>): Promise<Node> {
  const nodes = await loadNodes();
  const newNode: Node = {
    ...node,
    id: randomUUID(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
  };
  nodes.push(newNode);
  await saveNodes(nodes);
  return newNode;
}

/**
 * Update a node
 */
export async function updateNode(id: string, updates: Partial<Node>): Promise<Node | null> {
  const nodes = await loadNodes();
  const index = nodes.findIndex(n => n.id === id);
  if (index === -1) return null;
  
  nodes[index] = {
    ...nodes[index],
    ...updates,
    id, // Prevent ID change
    createdAt: nodes[index].createdAt, // Prevent createdAt change
    updatedAt: Date.now(),
  };
  
  await saveNodes(nodes);
  return nodes[index];
}

/**
 * Delete a node
 */
export async function deleteNode(id: string): Promise<boolean> {
  const nodes = await loadNodes();
  const filtered = nodes.filter(n => n.id !== id);
  if (filtered.length === nodes.length) return false;
  
  await saveNodes(filtered);
  return true;
}

/**
 * Import nodes from share links text with deduplication
 */
export async function importNodes(text: string): Promise<{ imported: number; skipped: number; failed: number; nodes: Node[]; skippedTags: string[]; errors: string[] }> {
  const parsed = parseShareLinks(text);
  const errors: string[] = [];
  
  if (parsed.length === 0) {
    return { imported: 0, skipped: 0, failed: 0, nodes: [], skippedTags: [], errors: ['No valid share links found'] };
  }
  
  // Load existing nodes and build tag set for dedup
  const existingNodes = await loadNodes();
  const existingTags = new Set(existingNodes.map(n => n.tag));
  
  const imported: Node[] = [];
  const skippedTags: string[] = [];
  let failed = 0;
  
  // Also track tags within this batch to prevent batch-internal duplicates
  const batchTags = new Set<string>();
  
  for (const node of parsed) {
    if (existingTags.has(node.tag) || batchTags.has(node.tag)) {
      skippedTags.push(node.tag);
      continue;
    }
    
    if (!node.tag || !node.address) {
      failed++;
      errors.push(`Invalid node data: ${node.tag || 'unknown'}`);
      continue;
    }
    
    batchTags.add(node.tag);
    imported.push(node);
  }
  
  // Save imported nodes
  if (imported.length > 0) {
    existingNodes.push(...imported);
    await saveNodes(existingNodes);
  }
  
  return {
    imported: imported.length,
    skipped: skippedTags.length,
    failed,
    nodes: imported,
    skippedTags,
    errors,
  };
}

/**
 * Update node test results (latency, speed)
 */
export async function updateNodeTestResult(
  id: string,
  latency?: number,
  speed?: number
): Promise<void> {
  const nodes = await loadNodes();
  const node = nodes.find(n => n.id === id);
  if (!node) return;
  
  if (latency !== undefined) node.latency = latency;
  if (speed !== undefined) node.speed = speed;
  node.updatedAt = Date.now();
  
  await saveNodes(nodes);
}
