import { Hono } from 'hono';
import { getStatus } from '../services/xray-service.js';
import { exec } from '../utils/shell.js';
import type { TrafficStats } from '@xray-manager/shared';

const status = new Hono();

// GET /api/status - Get service status + traffic stats
status.get('/', async (c) => {
  try {
    const serviceStatus = await getStatus();
    const traffic = await getTrafficStats();
    
    return c.json({
      ...serviceStatus,
      traffic,
    });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

/**
 * Get network traffic stats
 */
async function getTrafficStats(): Promise<TrafficStats> {
  try {
    const result = await exec('cat', ['/proc/net/dev']);
    const lines = result.stdout.split('\n').slice(2); // Skip headers
    
    const interfaces: Record<string, { rx: number; tx: number }> = {};
    let rxSpeed = 0;
    let txSpeed = 0;
    
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      
      const [name, ...values] = trimmed.split(/[:\s]+/);
      if (!name || name === 'lo') continue;
      
      const rx = parseInt(values[0]) || 0;
      const tx = parseInt(values[8]) || 0;
      
      interfaces[name] = { rx, tx };
      rxSpeed += rx;
      txSpeed += tx;
    }
    
    return { rxSpeed, txSpeed, interfaces };
  } catch {
    return { rxSpeed: 0, txSpeed: 0, interfaces: {} };
  }
}

export default status;
