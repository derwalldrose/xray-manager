import { Hono } from 'hono';
import { getNodes, addNode, deleteNode, importNodes, updateNode } from '../services/node-service.js';
import { getNode } from '../services/node-service.js';
import { testNode, testNodes } from '../services/test-service.js';
import { getTestUrls, saveTestUrls } from '../services/test-url-service.js';

const nodes = new Hono();

// GET /api/nodes - List all nodes
nodes.get('/', async (c) => {
  const allNodes = await getNodes();
  return c.json({ nodes: allNodes });
});

// POST /api/nodes - Add a node manually
nodes.post('/', async (c) => {
  try {
    const body = await c.req.json();
    const { tag, protocol, address, port, settings, streamSettings, mux } = body;
    
    if (!tag || !protocol || !address || !port) {
      return c.json({ error: 'Missing required fields: tag, protocol, address, port' }, 400);
    }
    
    const node = await addNode({
      tag,
      protocol,
      address,
      port,
      settings: settings || {},
      streamSettings,
      mux,
    });
    
    return c.json(node, 201);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// PUT /api/nodes/:id - Update a node
nodes.put('/:id', async (c) => {
  try {
    const id = c.req.param('id');
    const body = await c.req.json();
    const updated = await updateNode(id, body);
    if (!updated) return c.json({ error: 'Node not found' }, 404);
    return c.json(updated);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// DELETE /api/nodes/:id - Delete a node
nodes.delete('/:id', async (c) => {
  const id = c.req.param('id');
  const deleted = await deleteNode(id);
  
  if (!deleted) {
    return c.json({ error: 'Node not found' }, 404);
  }
  
  return c.json({ ok: true });
});

// POST /api/nodes/import - Import nodes from share links
nodes.post('/import', async (c) => {
  try {
    const body = await c.req.json();
    const { text } = body;
    
    if (!text) {
      return c.json({ error: 'Missing text field' }, 400);
    }
    
    const result = await importNodes(text);
    return c.json(result);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

// POST /api/nodes/test - Test nodes (single or batch)
nodes.post('/test', async (c) => {
  try {
    const body = await c.req.json().catch(() => ({}));
    const { nodeIds, mode } = body;
    
    if (nodeIds && Array.isArray(nodeIds) && nodeIds.length > 0) {
      // Batch test specific nodes
      const allNodes = await getNodes();
      const targets = allNodes.filter(n => nodeIds.includes(n.id));
      if (targets.length === 0) {
        return c.json({ error: 'No matching nodes found' }, 404);
      }
      const results = await testNodes(targets, mode === 'speed' ? 'speed' : 'ping');
      return c.json({ results });
    }
    
    // Test all nodes
    const allNodes = await getNodes();
    const results = await testNodes(allNodes, mode === 'speed' ? 'speed' : 'ping');
    return c.json({ results });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

nodes.get('/test-urls', async (c) => {
  const urls = await getTestUrls();
  return c.json(urls);
});

nodes.post('/test-urls', async (c) => {
  try {
    const body = await c.req.json();
    const urls = await saveTestUrls(body || {});
    return c.json(urls);
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

export default nodes;
