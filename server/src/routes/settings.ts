import { Hono } from 'hono';
import { copyFile, readFile, writeFile } from 'fs/promises';
import {
  getSettings,
  updateSettings,
  updateDns,
  updateRouting,
} from '../services/settings-service.js';
import { generateConfig } from '../services/config-generator.js';
import { writeJson } from '../utils/file.js';
import { CONFIG_FILE, XRAY_BIN } from '../constants.js';
import { restartXray } from '../services/xray-service.js';
import { exec } from '../utils/shell.js';

const settings = new Hono();

async function readConfig(): Promise<any | null> {
  try {
    return JSON.parse(await readFile(CONFIG_FILE, 'utf-8'));
  } catch {
    return null;
  }
}

function portsFromConfig(cfg: any, fallback: any) {
  const inbounds = cfg?.inbounds || [];
  const find = (tag: string) => inbounds.find((i: any) => i.tag === tag)?.port;
  return {
    socks: Number(find('socks-in') || fallback?.socks || 10810),
    http: Number(find('http-in') || fallback?.http || 10818),
    transparent: Number(find('transparent') || find('transparent-in') || fallback?.transparent || 12345),
  };
}

function applyPortsToConfig(cfg: any, ports: any) {
  if (!cfg.inbounds) cfg.inbounds = [];
  const ensure = (tag: string, protocol: string, port: number, extra: any = {}) => {
    let inbound = cfg.inbounds.find((i: any) => i.tag === tag);
    if (!inbound) {
      inbound = { tag, protocol, listen: '0.0.0.0', port, ...extra };
      cfg.inbounds.push(inbound);
    }
    inbound.port = Number(port);
    inbound.listen = inbound.listen || '0.0.0.0';
    inbound.protocol = inbound.protocol || protocol;
  };
  if (ports.socks !== undefined) ensure('socks-in', 'socks', ports.socks, { settings: { udp: true, auth: 'noauth' }, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] } });
  if (ports.http !== undefined) ensure('http-in', 'http', ports.http, { settings: {}, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] } });
  if (ports.transparent !== undefined) {
    const old = cfg.inbounds.find((i: any) => i.tag === 'transparent-in');
    if (old && !cfg.inbounds.find((i: any) => i.tag === 'transparent')) old.tag = 'transparent';
    ensure('transparent', 'dokodemo-door', ports.transparent, { settings: { network: 'tcp,udp', followRedirect: true }, sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] } });
  }
}

async function saveConfigWithTest(cfg: any) {
  const bak = CONFIG_FILE + '.bak.' + Date.now();
  await copyFile(CONFIG_FILE, bak).catch(() => {});
  await writeFile(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n');
  const test = await exec(XRAY_BIN, ['run', '-test', '-config', CONFIG_FILE]).catch((e: any) => ({ code: 1, stderr: e.message, stdout: '' }));
  if (test.code !== 0) {
    await copyFile(bak, CONFIG_FILE).catch(() => {});
    throw new Error('Config test failed: ' + (test.stderr || test.stdout || 'unknown error'));
  }
  await restartXray();
}

// GET /api/settings - Get current settings, with mutable runtime sections derived from live Xray config.
settings.get('/', async (c) => {
  const s = await getSettings();
  const cfg = await readConfig();
  return c.json({
    ...s,
    ports: portsFromConfig(cfg, s.ports),
    dns: cfg?.dns || s.dns,
    routing: {
      domainStrategy: cfg?.routing?.domainStrategy || s.routing?.domainStrategy || 'IPIfNonMatch',
      rules: cfg?.routing?.rules || s.routing?.rules || [],
    },
  });
});

// POST /api/settings - Update settings. Ports are applied to the live Xray inbounds.
settings.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const updated = await updateSettings(body);
    
    if (body.ports) {
      const cfg = (await readConfig()) || {};
      applyPortsToConfig(cfg, body.ports);
      await saveConfigWithTest(cfg);
      return c.json({ ...updated, ports: portsFromConfig(cfg, updated.ports) });
    }
    
    // Non-port settings still use generated config path.
    const config = await generateConfig();
    await writeJson(CONFIG_FILE, config);
    await restartXray();
    return c.json(updated);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// GET /api/settings/dns - Get DNS from live config
settings.get('/dns', async (c) => {
  const s = await getSettings();
  const cfg = await readConfig();
  return c.json(cfg?.dns || s.dns);
});

// POST /api/settings/dns - Update live DNS config
settings.post('/dns', async (c) => {
  try {
    const body = await c.req.json();
    await updateDns(body);
    const cfg = (await readConfig()) || {};
    cfg.dns = body;
    await saveConfigWithTest(cfg);
    return c.json(cfg.dns);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// GET /api/settings/routing - Get routing from live config
settings.get('/routing', async (c) => {
  const s = await getSettings();
  const cfg = await readConfig();
  return c.json({
    domainStrategy: cfg?.routing?.domainStrategy || s.routing?.domainStrategy || 'IPIfNonMatch',
    rules: cfg?.routing?.rules || s.routing?.rules || [],
    balancers: cfg?.routing?.balancers || [],
  });
});

// POST /api/settings/routing - Update live routing config
settings.post('/routing', async (c) => {
  try {
    const body = await c.req.json();
    await updateRouting({ domainStrategy: body.domainStrategy || 'IPIfNonMatch', rules: body.rules || [] });
    const cfg = (await readConfig()) || {};
    if (!cfg.routing) cfg.routing = {};
    if (body.domainStrategy !== undefined) cfg.routing.domainStrategy = body.domainStrategy;
    if (body.rules !== undefined) cfg.routing.rules = body.rules;
    if (body.balancers !== undefined) cfg.routing.balancers = body.balancers;
    await saveConfigWithTest(cfg);
    return c.json({ domainStrategy: cfg.routing.domainStrategy, rules: cfg.routing.rules || [], balancers: cfg.routing.balancers || [] });
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

export default settings;
