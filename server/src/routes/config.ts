import { Hono } from 'hono';
import { copyFile, readFile, writeFile } from 'fs/promises';
import { CONFIG_FILE, XRAY_BIN } from '../constants.js';
import { exec } from '../utils/shell.js';
import { restartXray } from '../services/xray-service.js';

const config = new Hono();

// GET /api/config - Read full xray config
config.get('/', async (c) => {
  try {
    const raw = await readFile(CONFIG_FILE, 'utf-8');
    const json = JSON.parse(raw);
    return c.json({ ok: true, config: json, raw, path: CONFIG_FILE });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

// POST /api/config/test - Validate config
config.post('/test', async (c) => {
  try {
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]);
    return c.json({ ok: test.code === 0, output: test.stderr + test.stdout });
  } catch (e: any) {
    return c.json({ ok: false, error: e.message });
  }
});

// POST /api/config - Save full config (raw JSON)
config.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const cfg = body.config || body;
    const content = typeof cfg === 'string' ? cfg : JSON.stringify(cfg, null, 2);
    
    // Validate JSON
    JSON.parse(content);
    
    // Backup
    const bak = CONFIG_FILE + '.bak.' + Date.now();
    await copyFile(CONFIG_FILE, bak).catch(() => {});
    
    await writeFile(CONFIG_FILE, content.endsWith('\n') ? content : content + '\n');
    
    // Test
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]).catch(e => ({ code: 1, stderr: e.message }));
    if (test.code !== 0) {
      await copyFile(bak, CONFIG_FILE).catch(() => {});
      return c.json({ ok: false, error: 'Config test failed: ' + (test.stderr || ''), rolled: true }, 400);
    }
    
    await restartXray();
    return c.json({ ok: true });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

export default config;
