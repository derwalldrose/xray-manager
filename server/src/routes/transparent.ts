
import { Hono } from 'hono';
import {
  getStatus, enableTransparent, disableTransparent,
  getBypassCidrs, saveBypassCidrs, toggleDnsHijack,
} from '../services/transparent-service.js';
import { getIptablesRules } from '../services/iptables-service.js';

const transparent = new Hono();

transparent.get('/status', async (c) => {
  const status = await getStatus();
  return c.json(status);
});

transparent.post('/enable', async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));
    const port = body.port || 12345;
    const state = await enableTransparent(port);
    return c.json({ ok: true, ...state });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

transparent.post('/disable', async (c) => {
  try {
    const state = await disableTransparent();
    return c.json({ ok: true, ...state });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

transparent.get('/bypass', async (c) => {
  const cidrs = await getBypassCidrs();
  return c.json({ cidrs });
});

transparent.post('/bypass', async (c) => {
  try {
    const body = await c.req.json();
    const cidrs = body.cidrs || body;
    await saveBypassCidrs(cidrs);
    return c.json({ ok: true, cidrs });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

transparent.post('/toggle-dns', async (c) => {
  try {
    const result = await toggleDnsHijack();
    return c.json({ ok: true, ...result });
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

transparent.get('/iptables', async (c) => {
  try {
    const rules = await getIptablesRules();
    return c.json(rules);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

export default transparent;
