import { Hono } from 'hono';
import { exec } from '../utils/shell.js';
import { SERVICE_NAME } from '../constants.js';

const logs = new Hono();

// GET /api/logs - Get Xray service logs
logs.get('/', async (c) => {
  try {
    const lines = parseInt(c.req.query('lines') || '100');
    const clamped = Math.min(Math.max(lines, 10), 1000);
    
    const result = await exec('journalctl', [
      '-u', SERVICE_NAME,
      '-n', String(clamped),
      '--no-pager',
      '-o', 'short-iso',
    ]);
    
    return c.json({
      logs: result.stdout,
      lines: clamped,
    });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

export default logs;
