import { Hono } from 'hono';
import {
  getConnections,
  connectNodes,
  disconnectNode,
  disconnectAll,
} from '../services/connection-service.js';

const connections = new Hono();

// GET /api/connections - Get current connections
connections.get('/', async (c) => {
  const state = await getConnections();
  return c.json(state);
});

// POST /api/connections/connect - Connect selected nodes with strategy
connections.post('/connect', async (c) => {
  try {
    const body = await c.req.json();
    const { nodeIds, strategy, transparent } = body;
    
    if (!nodeIds || !Array.isArray(nodeIds) || nodeIds.length === 0) {
      return c.json({ error: 'Missing or invalid nodeIds array' }, 400);
    }
    
    const state = await connectNodes(nodeIds, strategy || 'roundRobin', transparent || false);
    return c.json(state);
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

// POST /api/connections/disconnect - Disconnect all nodes
connections.post('/disconnect', async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));
    const { nodeId } = body;
    
    if (!nodeId) {
      // Disconnect all
      const state = await disconnectAll();
      return c.json(state);
    }
    
    const state = await disconnectNode(nodeId);
    return c.json(state);
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

// GET /api/connections/status - Get connection status with reconcile
connections.get('/status', async (c) => {
  const state = await getConnections();
  return c.json(state);
});

export default connections;
