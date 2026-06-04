import { Hono } from 'hono';
import { exec } from '../utils/shell.js';
import { IS_WINDOWS } from '../constants.js';

const system = new Hono();

const SYSCTL_PARAMS = [
  { key: 'net.ipv4.ip_forward', desc: 'IPv4 转发', recommended: '1' },
  { key: 'net.ipv6.conf.all.forwarding', desc: 'IPv6 转发', recommended: '0' },
  { key: 'net.ipv4.conf.all.send_redirects', desc: 'ICMP 重定向', recommended: '0' },
  { key: 'net.ipv4.conf.default.send_redirects', desc: '默认 ICMP 重定向', recommended: '0' },
  { key: 'net.ipv4.ip_local_port_range', desc: '本地端口范围', recommended: '1024 65000' },
  { key: 'net.core.default_qdisc', desc: '默认队列算法', recommended: 'fq' },
  { key: 'net.ipv4.tcp_congestion_control', desc: 'TCP 拥塞控制', recommended: 'bbr' },
  { key: 'net.ipv4.tcp_fastopen', desc: 'TCP Fast Open', recommended: '3' },
  { key: 'net.core.rmem_max', desc: '最大接收缓冲', recommended: '134217728' },
  { key: 'net.core.wmem_max', desc: '最大发送缓冲', recommended: '134217728' },
  { key: 'net.ipv4.tcp_rmem', desc: 'TCP 接收缓冲', recommended: '4096 87380 67108864' },
  { key: 'net.ipv4.tcp_wmem', desc: 'TCP 发送缓冲', recommended: '4096 65536 67108864' },
];

system.get('/', async (c) => {
  if (IS_WINDOWS) {
    return c.json({
      supported: false,
      params: [],
      raw: {},
      message: 'Windows native mode does not support Linux sysctl parameters.'
    });
  }
  try {
    const raw: Record<string, string> = {};
    const params = [];
    for (const p of SYSCTL_PARAMS) {
      try {
        const res = await exec('sysctl', ['-n', p.key]);
        const value = res.code === 0 ? res.stdout.trim() : '';
        raw[p.key] = value;
        params.push({ ...p, value });
      } catch {
        raw[p.key] = '';
        params.push({ ...p, value: '' });
      }
    }
    return c.json({ params, raw });
  } catch (err: any) {
    return c.json({ error: err.message }, 500);
  }
});

system.post('/', async (c) => {
  if (IS_WINDOWS) {
    return c.json({
      supported: false,
      applied: [],
      results: {},
      message: 'Windows native mode does not support Linux sysctl parameters.'
    }, 400);
  }
  try {
    const body = await c.req.json();
    const changes: Record<string, any> = body.changes || body;
    const results: Record<string, { success: boolean; error?: string }> = {};
    const applied: string[] = [];
    for (const [key, value] of Object.entries(changes)) {
      if (!key.startsWith('net.')) {
        results[key] = { success: false, error: 'Only net.* parameters allowed' };
        continue;
      }
      try {
        const res = await exec('sysctl', ['-w', `${key}=${value}`]);
        const ok = res.code === 0;
        if (ok) applied.push(key);
        results[key] = { success: ok, error: ok ? undefined : res.stderr };
      } catch (err: any) {
        results[key] = { success: false, error: err.message };
      }
    }
    return c.json({ applied, results });
  } catch (err: any) {
    return c.json({ error: err.message }, 400);
  }
});

export default system;
