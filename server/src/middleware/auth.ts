import type { Context, Next } from 'hono';
import { readText, writeText } from '../utils/file.js';
import { DATA_DIR } from '../constants.js';
import { join } from 'path';
import { existsSync } from 'fs';

const TOKEN_FILE = join(DATA_DIR, 'token');
const DEFAULT_TOKEN = '123456';

async function getToken(): Promise<string> {
  if (existsSync(TOKEN_FILE)) {
    const token = await readText(TOKEN_FILE);
    return token.trim() || DEFAULT_TOKEN;
  }
  // Initialize default token
  await writeText(TOKEN_FILE, DEFAULT_TOKEN);
  return DEFAULT_TOKEN;
}

export async function authMiddleware(c: Context, next: Next): Promise<void> {
  // Skip auth for health check
  if (c.req.path === '/api/health') {
    await next();
    return;
  }

  // Skip auth for static files (frontend)
  if (!c.req.path.startsWith('/api/')) {
    await next();
    return;
  }

  const token = c.req.header('X-Token') || c.req.query('token');
  const expected = await getToken();

  if (!token || token !== expected) {
    c.status(401);
    await c.json({ error: 'Unauthorized: invalid or missing X-Token header' });
    return;
  }

  await next();
}
