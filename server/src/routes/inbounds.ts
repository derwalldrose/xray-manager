
import { Hono } from 'hono';
import { readFile, writeFile } from 'fs/promises';
import { CONFIG_FILE, XRAY_BIN } from '../constants.js';
import { exec } from '../utils/shell.js';
import { restartXray } from '../services/xray-service.js';

const inbounds = new Hono();

inbounds.get('/', async (c) => {
  try {
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    return c.json({ inbounds: cfg.inbounds || [] });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

inbounds.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const { inbound, index } = body;
    if (!inbound) return c.json({ error: 'Missing inbound' }, 400);
    
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    if (!cfg.inbounds) cfg.inbounds = [];
    
    // Backup
    const bak = CONFIG_FILE + '.bak.' + Date.now();
    await exec('cp', [CONFIG_FILE, bak]).catch(() => {});
    
    if (index !== undefined && index >= 0) {
      cfg.inbounds[index] = inbound;
    } else {
      cfg.inbounds.push(inbound);
    }
    
    await writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    
    // Test config
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]).catch(e => ({ code: 1, stderr: e.message }));
    if (test.code !== 0) {
      await exec('cp', [bak, CONFIG_FILE]).catch(() => {});
      return c.json({ error: 'Config test failed: ' + (test.stderr || ''), rolled: true }, 400);
    }
    
    await restartXray();
    return c.json({ ok: true, inbounds: cfg.inbounds });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

inbounds.delete('/:index', async (c) => {
  try {
    const index = parseInt(c.req.param('index'));
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    if (!cfg.inbounds || index < 0 || index >= cfg.inbounds.length) {
      return c.json({ error: 'Invalid index' }, 400);
    }
    
    const bak = CONFIG_FILE + '.bak.' + Date.now();
    await exec('cp', [CONFIG_FILE, bak]).catch(() => {});
    
    cfg.inbounds.splice(index, 1);
    await writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]).catch(e => ({ code: 1, stderr: e.message }));
    if (test.code !== 0) {
      await exec('cp', [bak, CONFIG_FILE]).catch(() => {});
      return c.json({ error: 'Config test failed', rolled: true }, 400);
    }
    
    await restartXray();
    return c.json({ ok: true, inbounds: cfg.inbounds });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

export default inbounds;
