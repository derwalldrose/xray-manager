
import { Hono } from 'hono';
import { readFile, writeFile } from 'fs/promises';
import { CONFIG_FILE, XRAY_BIN } from '../constants.js';
import { exec } from '../utils/shell.js';
import { restartXray } from '../services/xray-service.js';

const routing = new Hono();

routing.get('/', async (c) => {
  try {
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    return c.json({
      domainStrategy: cfg.routing?.domainStrategy || 'IPIfNonMatch',
      rules: cfg.routing?.rules || [],
      balancers: cfg.routing?.balancers || [],
    });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

routing.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const cfg = JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
    
    const bak = CONFIG_FILE + '.bak.' + Date.now();
    await exec('cp', [CONFIG_FILE, bak]).catch(() => {});
    
    if (!cfg.routing) cfg.routing = {};
    if (body.domainStrategy !== undefined) cfg.routing.domainStrategy = body.domainStrategy;
    if (body.rules !== undefined) cfg.routing.rules = body.rules;
    if (body.balancers !== undefined) cfg.routing.balancers = body.balancers;
    
    await writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]).catch(e => ({ code: 1, stderr: e.message }));
    if (test.code !== 0) {
      await exec('cp', [bak, CONFIG_FILE]).catch(() => {});
      return c.json({ error: 'Config test failed: ' + (test.stderr || ''), rolled: true }, 400);
    }
    
    await restartXray();
    return c.json({ ok: true, domainStrategy: cfg.routing.domainStrategy, rules: cfg.routing.rules, balancers: cfg.routing.balancers });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

export default routing;
