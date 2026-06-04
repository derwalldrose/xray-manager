import { Hono } from 'hono';
import { readFile } from 'fs/promises';
import { exec } from '../utils/shell.js';
import { SERVICE_NAME, IS_WINDOWS, XRAY_LOG_FILE } from '../constants.js';

const logs = new Hono();

// GET /api/logs - Get Xray service logs
logs.get('/', async (c) => {
  try {
    const lines = parseInt(c.req.query('lines') || '100');
    const clamped = Math.min(Math.max(lines, 10), 1000);

    // On Windows or managed-process mode, read from log file directly
    if (IS_WINDOWS) {
      try {
        const content = await readFile(XRAY_LOG_FILE, 'utf-8');
        const allLines = content.split('\n').filter(Boolean);
        const tail = allLines.slice(-clamped);
        return c.json({ logs: tail.join('\n'), lines: clamped });
      } catch {
        return c.json({ logs: '(无日志)', lines: clamped });
      }
    }

    // Linux: try journalctl first, fall back to log file
    try {
      const result = await exec('journalctl', [
        '-u', SERVICE_NAME,
        '-n', String(clamped),
        '--no-pager',
        '-o', 'short-iso',
      ]);
      if (result.code === 0 && result.stdout.trim()) {
        return c.json({ logs: result.stdout, lines: clamped });
      }
    } catch {}

    // Fallback: read log file
    try {
      const content = await readFile(XRAY_LOG_FILE, 'utf-8');
      const allLines = content.split('\n').filter(Boolean);
      const tail = allLines.slice(-clamped);
      return c.json({ logs: tail.join('\n'), lines: clamped });
    } catch {
      return c.json({ logs: '(无日志)', lines: clamped });
    }
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

export default logs;
