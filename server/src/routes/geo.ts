
import { Hono } from 'hono';
import { getGeoInfo, getGeoUrls, saveGeoUrls, updateGeoFiles } from '../services/geo-service.js';

const geo = new Hono();

geo.get('/info', async (c) => {
  const info = await getGeoInfo();
  return c.json({ files: info });
});

geo.get('/urls', async (c) => {
  const urls = await getGeoUrls();
  return c.json(urls);
});

geo.post('/urls', async (c) => {
  try {
    const body = await c.req.json();
    const updated = await saveGeoUrls(body);
    return c.json({ ok: true, ...updated });
  } catch (e: any) {
    return c.json({ error: e.message }, 400);
  }
});

geo.post('/update', async (c) => {
  try {
    const result = await updateGeoFiles();
    return c.json(result);
  } catch (e: any) {
    return c.json({ error: e.message }, 500);
  }
});

export default geo;
