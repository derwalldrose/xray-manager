import type { Node } from '@xray-manager/shared';
import { randomUUID } from 'crypto';

/**
 * Parse vless:// share link
 */
function parseVless(link: string): Node | null {
  try {
    const url = new URL(link);
    const id = url.username;
    const address = url.hostname;
    const port = parseInt(url.port) || 443;
    const params = url.searchParams;
    
    const security = params.get('security') || 'tls';
    const type = params.get('type') || 'tcp';
    const sni = params.get('sni') || address;
    const fp = params.get('fp') || 'chrome';
    const flow = params.get('flow') || '';
    const pbk = params.get('pbk') || '';
    const sid = params.get('sid') || '';
    const path = params.get('path') || '';
    const host = params.get('host') || '';
    
    const settings: any = {
      vnext: [{
        address,
        port,
        users: [{
          id,
          encryption: 'none',
          flow: security === 'reality' ? '' : flow,
        }],
      }],
    };
    
    const streamSettings: any = {
      network: type,
      security,
    };
    
    if (security === 'tls') {
      streamSettings.tlsSettings = {
        serverName: sni,
        fingerprint: fp,
        allowInsecure: false,
      };
    } else if (security === 'reality') {
      streamSettings.realitySettings = {
        serverName: sni,
        fingerprint: fp,
        publicKey: pbk,
        shortId: sid,
      };
    }
    
    if (type === 'ws') {
      streamSettings.wsSettings = { path, headers: { Host: host } };
    } else if (type === 'grpc') {
      streamSettings.grpcSettings = { serviceName: path };
    }
    
    const tag = url.hash.slice(1) || `${address}:${port}`;
    
    return {
      id: randomUUID(),
      tag: decodeURIComponent(tag),
      protocol: 'vless',
      address,
      port,
      settings,
      streamSettings,
      mux: { enabled: false, concurrency: -1 },
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  } catch {
    return null;
  }
}

/**
 * Parse vmess:// share link
 */
function parseVmess(link: string): Node | null {
  try {
    const base64 = link.replace('vmess://', '');
    const json = Buffer.from(base64, 'base64').toString('utf-8');
    const cfg = JSON.parse(json);
    
    const address = cfg.add;
    const port = parseInt(cfg.port) || 443;
    
    const settings: any = {
      vnext: [{
        address,
        port,
        users: [{
          id: cfg.id,
          alterId: parseInt(cfg.aid) || 0,
          security: cfg.scy || 'auto',
        }],
      }],
    };
    
    const streamSettings: any = {
      network: cfg.net || 'tcp',
      security: cfg.tls || 'none',
    };
    
    if (cfg.tls === 'tls') {
      streamSettings.tlsSettings = {
        serverName: cfg.sni || address,
        fingerprint: cfg.fp || 'chrome',
        allowInsecure: cfg.verify === false,
      };
    }
    
    if (cfg.net === 'ws') {
      streamSettings.wsSettings = {
        path: cfg.path || '/',
        headers: { Host: cfg.host || '' },
      };
    } else if (cfg.net === 'grpc') {
      streamSettings.grpcSettings = { serviceName: cfg.path || '' };
    }
    
    return {
      id: randomUUID(),
      tag: cfg.ps || `${address}:${port}`,
      protocol: 'vmess',
      address,
      port,
      settings,
      streamSettings,
      mux: { enabled: false, concurrency: -1 },
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  } catch {
    return null;
  }
}

/**
 * Parse trojan:// share link
 */
function parseTrojan(link: string): Node | null {
  try {
    const url = new URL(link);
    const password = url.username;
    const address = url.hostname;
    const port = parseInt(url.port) || 443;
    const params = url.searchParams;
    
    const sni = params.get('sni') || address;
    const type = params.get('type') || 'tcp';
    const host = params.get('host') || '';
    const path = params.get('path') || '';
    
    const settings: any = {
      servers: [{
        address,
        port,
        password,
      }],
    };
    
    const streamSettings: any = {
      network: type,
      security: 'tls',
      tlsSettings: {
        serverName: sni,
        allowInsecure: false,
      },
    };
    
    if (type === 'ws') {
      streamSettings.wsSettings = { path, headers: { Host: host } };
    }
    
    const tag = url.hash.slice(1) || `${address}:${port}`;
    
    return {
      id: randomUUID(),
      tag: decodeURIComponent(tag),
      protocol: 'trojan',
      address,
      port,
      settings,
      streamSettings,
      mux: { enabled: false, concurrency: -1 },
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  } catch {
    return null;
  }
}

/**
 * Parse ss:// share link
 */
function parseShadowsocks(link: string): Node | null {
  try {
    const url = new URL(link);
    let method: string, password: string;
    
    // ss://BASE64(method:password)@host:port#tag
    const userInfo = url.username;
    if (userInfo) {
      const decoded = Buffer.from(userInfo, 'base64').toString('utf-8');
      [method, password] = decoded.split(':');
    } else {
      // ss://BASE64(method:password@host:port)#tag
      const base64 = link.replace('ss://', '').split('#')[0];
      const decoded = Buffer.from(base64, 'base64').toString('utf-8');
      const match = decoded.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
      if (!match) return null;
      [, method, password] = match;
      url.hostname = match[3];
      url.port = match[4];
    }
    
    const address = url.hostname;
    const port = parseInt(url.port) || 8388;
    
    const settings: any = {
      servers: [{
        address,
        port,
        method,
        password,
      }],
    };
    
    const tag = url.hash.slice(1) || `${address}:${port}`;
    
    return {
      id: randomUUID(),
      tag: decodeURIComponent(tag),
      protocol: 'shadowsocks',
      address,
      port,
      settings,
      mux: { enabled: false, concurrency: -1 },
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };
  } catch {
    return null;
  }
}

/**
 * Parse a share link (vless://, vmess://, trojan://, ss://)
 */
export function parseShareLink(link: string): Node | null {
  const trimmed = link.trim();
  
  if (trimmed.startsWith('vless://')) {
    return parseVless(trimmed);
  } else if (trimmed.startsWith('vmess://')) {
    return parseVmess(trimmed);
  } else if (trimmed.startsWith('trojan://')) {
    return parseTrojan(trimmed);
  } else if (trimmed.startsWith('ss://')) {
    return parseShadowsocks(trimmed);
  }
  
  return null;
}

/**
 * Parse multiple share links from text (one per line)
 */
export function parseShareLinks(text: string): Node[] {
  const lines = text.split('\n').map(l => l.trim()).filter(l => l);
  const nodes: Node[] = [];
  
  for (const line of lines) {
    const node = parseShareLink(line);
    if (node) nodes.push(node);
  }
  
  return nodes;
}
