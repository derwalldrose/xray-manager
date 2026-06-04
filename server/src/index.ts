import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import { serve } from '@hono/node-server';
import { resolve, join, dirname } from 'path';
import { existsSync } from 'fs';
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';

import { authMiddleware } from './middleware/auth.js';
import { DATA_DIR, CONFIG_DIR, SERVER_PORT, LOG_DIR, BIN_DIR, BACKUP_DIR, PLATFORM, BASE_DIR } from './constants.js';
import { ensureDir } from './utils/file.js';

// Routes
import nodes from './routes/nodes.js';
import connections from './routes/connections.js';
import settings from './routes/settings.js';
import status from './routes/status.js';
import logs from './routes/logs.js';
import system from './routes/system.js';
import transparent from './routes/transparent.js';
import geo from './routes/geo.js';
import inbounds from './routes/inbounds.js';
import routing from './routes/routing.js';
import dnsConfig from './routes/dns-config.js';
import backups from './routes/backups.js';
import configRoute from './routes/config.js';
import systemProxy from './routes/system-proxy.js';

// Initialize
import { getSettings } from './services/settings-service.js';
import { loadConnections } from './services/connection-service.js';
import { getNodes } from './services/node-service.js';
import { ensureXrayBinary } from './services/xray-download-service.js';

async function main() {
  // Ensure directories exist
  await ensureDir(DATA_DIR);
  await ensureDir(CONFIG_DIR);
  await ensureDir(LOG_DIR);
  await ensureDir(BIN_DIR);
  await ensureDir(BACKUP_DIR);
  
  // Initialize defaults by loading them (triggers creation if not exist)
  await getSettings();
  await loadConnections();
  await getNodes();

  // Ensure the platform-matching Xray binary exists. This auto-downloads
  // Xray-core from GitHub on fresh Windows/Linux/macOS installs.
  try {
    const xray = await ensureXrayBinary();
    console.log(`[xray] ${xray.message}: ${xray.path}`);
  } catch (err) {
    console.warn('[xray] auto-install failed:', err instanceof Error ? err.message : err);
  }
  
  // Create Hono app
  const app = new Hono();
  
  // Auth middleware
  app.use('*', authMiddleware);
  
  // Health check (no auth required - handled in middleware)
  app.get('/api/health', (c) => c.json({ status: 'ok', timestamp: Date.now() }));
  
  // API routes
  app.route('/api/nodes', nodes);
  app.route('/api/connections', connections);
  app.route('/api/settings', settings);
  app.route('/api/status', status);
  app.route('/api/logs', logs);
  app.route('/api/sysctl', system);
  app.route('/api/transparent', transparent);
  app.route('/api/geo', geo);
  app.route('/api/inbounds', inbounds);
  app.route('/api/routing', routing);
  app.route('/api/dns', dnsConfig);
  app.route('/api/backups', backups);
  app.route('/api/config', configRoute);
  app.route('/api/system-proxy', systemProxy);
  
  // Serve static frontend files
  const webDist = resolve(process.cwd(), 'web-dist');
  
  if (existsSync(webDist)) {
    // Serve static assets
    app.use(
      '/assets/*',
      serveStatic({ root: webDist })
    );
    
    // SPA fallback - serve index.html for non-API routes
    app.get('*', async (c) => {
      const indexPath = join(webDist, 'index.html');
      if (existsSync(indexPath)) {
        const html = await readFile(indexPath, 'utf-8');
        return c.html(html);
      }
      return c.text('Frontend not built. Run: cd web && npm run build', 404);
    });
  } else {
    app.get('*', (c) => {
      return c.text('Frontend not built. Run: cd web && npm run build', 404);
    });
  }
  
  // Start server
  const port = SERVER_PORT;
  
  serve({
    fetch: app.fetch,
    port,
  }, (info) => {
    console.log(`Xray Manager v4 server listening on http://0.0.0.0:${port}`);
    console.log(`Platform: ${PLATFORM}`);
    console.log(`Base directory: ${BASE_DIR}`);
    console.log(`Data directory: ${DATA_DIR}`);
    console.log(`Config directory: ${CONFIG_DIR}`);
  });
}

main().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
