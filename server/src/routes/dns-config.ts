
import { Hono } from 'hono';
import { readFile, writeFile } from 'fs/promises';
import { CONFIG_FILE, XRAY_BIN } from '../constants.js';
import { exec } from '../utils/shell.js';
import { restartXray } from '../services/xray-service.js';

const dnsConfig = new Hono();

dnsConfig.get('/', async (c) => {
  try {
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    return c.json(cfg.dns || { servers: [], hosts: {} });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

dnsConfig.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    
    const bak = CONFIG_FILE + '.bak.' + Date.now();
    await exec('cp', [CONFIG_FILE, bak]).catch(() => {});
    
    cfg.dns = body;
    await writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]).catch(e => ({ code: 1, stderr: e.message }));
    if (test.code !== 0) {
      await exec('cp', [bak, CONFIG_FILE]).catch(() => {});
      return c.json({ error: 'Config test failed: ' + (test.stderr || ''), rolled: true }, 400);
    }
    
    await restartXray();
    return c.json({ ok: true, ...cfg.dns });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

dnsConfig.get('/hosts', async (c) => {
  try {
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    return c.json(cfg.dns?.hosts || {});
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

dnsConfig.post('/hosts', async (c) => {
  try {
    const body = await c.req.json();
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    if (!cfg.dns) cfg.dns = { servers: [], hosts: {} };
    
    const bak = CONFIG_FILE + '.bak.' + Date.now();
    await exec('cp', [CONFIG_FILE, bak]).catch(() => {});
    
    cfg.dns.hosts = body;
    await writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    await restartXray();
    return c.json({ ok: true, ...cfg.dns.hosts });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

export default dnsConfig;
