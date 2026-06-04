
import { Hono } from 'hono';
import { listBackups, createBackup, restoreBackup } from '../services/backup-service.js';
import { restartXray } from '../services/xray-service.js';

const backups = new Hono();

backups.get('/', async (c) => {
  const list = await listBackups();
  return c.json({ backups: list });
});

backups.post('/create', async (c) => {
  try {
    const result = await createBackup();
    return c.json(result);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

backups.post('/restore', async (c) => {
  try {
    const body = await c.req.json();
    const { name } = body;
    if (!name) return c.json({ error: 'Missing backup name' }, 400);
    
    const result = await restoreBackup(name);
    if (result.ok) {
      await restartXray();
    }
    return c.json(result);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

export default backups;
