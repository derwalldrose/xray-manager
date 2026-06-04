import { Hono } from 'hono';
import { getStatus, startXray, stopXray, restartXray } from '../services/xray-service.js';
import { exec } from '../utils/shell.js';
import type { TrafficStats } from '@xray-manager/shared';
import { IS_WINDOWS } from '../constants.js';

const status = new Hono();

status.get('/', async (c) => {
  try {
    const serviceStatus = await getStatus();
    const traffic = await getTrafficStats();
    return c.json({ ...serviceStatus, traffic });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

status.post('/', async (c) => {
  const body = await c.req.json().catch(() => ({}));
  const action = body.action;
  try {
    if (action === 'start') await startXray();
    else if (action === 'stop') await stopXray();
    else if (action === 'restart') await restartXray();
    else return c.json({ error: 'action must be start, stop, or restart' }, 400);
    return c.json({ ok: true, action, status: await getStatus() });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

status.post('/:action', async (c) => {
  const action = c.req.param('action');
  try {
    if (action === 'start') await startXray();
    else if (action === 'stop') await stopXray();
    else if (action === 'restart') await restartXray();
    else return c.json({ error: 'action must be start, stop, or restart' }, 400);
    return c.json({ ok: true, action, status: await getStatus() });
  } catch (err: any) {
    return c.json({ ok: false, error: err.message }, 500);
  }
});

async function getTrafficStats(): Promise<TrafficStats> {
  if (IS_WINDOWS) {
    try {
      const ps = await exec('powershell.exe', ['-NoProfile', '-Command', 'Get-NetAdapterStatistics | Select-Object Name,ReceivedBytes,SentBytes | ConvertTo-Json -Compress'], { timeout: 15000 });
      const parsed = JSON.parse(ps.stdout || '[]');
      const rows = Array.isArray(parsed) ? parsed : [parsed];
      const interfaces: Record<string, { rx: number; tx: number }> = {};
      let rxSpeed = 0;
      let txSpeed = 0;
      for (const r of rows) {
        if (!r?.Name) continue;
        const rx = Number(r.ReceivedBytes || 0);
        const tx = Number(r.SentBytes || 0);
        interfaces[r.Name] = { rx, tx };
        rxSpeed += rx;
        txSpeed += tx;
      }
      return { rxSpeed, txSpeed, interfaces };
    } catch {
      return { rxSpeed: 0, txSpeed: 0, interfaces: {} };
    }
  }

  try {
    const result = await exec('cat', ['/proc/net/dev']);
    const lines = result.stdout.split('\n').slice(2);
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
