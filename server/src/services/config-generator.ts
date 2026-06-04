import type { XrayConfig, XrayInbound, XrayOutbound, XrayRoutingRule, XrayBalancer, XrayDns } from '@xray-manager/shared';
import type { Node, Connection, Settings } from '@xray-manager/shared';
import { readFile } from 'fs/promises';
import { getSettings } from './settings-service.js';
import { getNodes } from './node-service.js';
import { getConnections } from './connection-service.js';
import { CONFIG_FILE } from '../constants.js';

const SYSTEM_OUTBOUND_TAGS = new Set(['direct', 'block', 'dns-out']);
const MANAGED_INBOUND_TAGS = new Set(['socks-in', 'http-in', 'transparent', 'transparent-in', 'dns']);

/** Generate SOCKS inbound fallback */
function generateSocksInbound(port: number): XrayInbound {
  return {
    tag: 'socks-in',
    port,
    listen: '0.0.0.0',
    protocol: 'socks',
    settings: { udp: true, auth: 'noauth' },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
  };
}

/** Generate HTTP inbound fallback */
function generateHttpInbound(port: number): XrayInbound {
  return {
    tag: 'http-in',
    port,
    listen: '0.0.0.0',
    protocol: 'http',
    settings: {},
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
  };
}

/** Generate transparent proxy inbound (dokodemo-door) */
function generateTransparentInbound(port: number): XrayInbound {
  return {
    tag: 'transparent',
    port,
    listen: '0.0.0.0',
    protocol: 'dokodemo-door',
    settings: { network: 'tcp,udp', followRedirect: true },
    sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
  };
}

/** Generate DNS dokodemo inbound */
function generateDnsInbound(): XrayInbound {
  return {
    tag: 'dns',
    port: 53,
    listen: '0.0.0.0',
    protocol: 'dokodemo-door',
    settings: { address: '8.8.8.8', port: 53, network: 'tcp,udp' },
  };
}

async function readLiveConfig(): Promise<XrayConfig | null> {
  try {
    return JSON.parse(await readFile(CONFIG_FILE, 'utf-8')) as XrayConfig;
  } catch {
    return null;
  }
}

function uniqByTag<T extends { tag: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  const out: T[] = [];
  for (const item of items) {
    if (!item?.tag || seen.has(item.tag)) continue;
    seen.add(item.tag);
    out.push(item);
  }
  return out;
}

function buildInbounds(settings: Settings, live: XrayConfig | null): XrayInbound[] {
  const inbounds = [...(live?.inbounds || [])];

  if (!inbounds.some(i => i.tag === 'socks-in')) inbounds.push(generateSocksInbound(settings.ports.socks || 10810));
  if (!inbounds.some(i => i.tag === 'http-in')) inbounds.push(generateHttpInbound(settings.ports.http || 10818));
  if (!inbounds.some(i => i.tag === 'dns')) inbounds.push(generateDnsInbound());
  if (!inbounds.some(i => i.tag === 'transparent')) inbounds.push(generateTransparentInbound(settings.ports.transparent || 12345));

  // Normalize older v3 tag so the UI/routing consistently uses "transparent".
  // Also normalize listen addresses: socks-in and http-in must be 0.0.0.0 for LAN gateway access.
  for (const inbound of inbounds) {
    if (inbound.tag === 'transparent-in') inbound.tag = 'transparent';
    if (inbound.tag === 'socks-in' || inbound.tag === 'http-in' || inbound.tag === 'transparent') {
      if (!inbound.listen || inbound.listen === '127.0.0.1') inbound.listen = '0.0.0.0';
    }
  }

  return uniqByTag(inbounds);
}

/** Generate outbound from node */
function generateOutbound(node: Node, connection: Connection): XrayOutbound {
  return {
    tag: connection.outbound,
    protocol: node.protocol,
    settings: node.settings,
    streamSettings: node.streamSettings,
    mux: node.mux,
  };
}

function systemOutbound(tag: string, live: XrayConfig | null): XrayOutbound | undefined {
  const existing = live?.outbounds?.find(o => o.tag === tag);
  if (existing) return existing;
  if (tag === 'direct') return { tag: 'direct', protocol: 'freedom', settings: { domainStrategy: 'UseIP' } };
  if (tag === 'block') return { tag: 'block', protocol: 'blackhole', settings: {} };
  if (tag === 'dns-out') return { tag: 'dns-out', protocol: 'dns', settings: {} };
  return undefined;
}

function buildOutbounds(connections: Connection[], nodeMap: Map<string, Node>, live: XrayConfig | null): XrayOutbound[] {
  const outbounds: XrayOutbound[] = [];
  for (const conn of connections) {
    const node = nodeMap.get(conn.nodeId);
    if (node) outbounds.push(generateOutbound(node, conn));
  }

  // Always keep system outbounds. Prefer live definitions so DNS/freedom sockopt marks are preserved.
  for (const tag of ['direct', 'block', 'dns-out']) {
    const outbound = systemOutbound(tag, live);
    if (outbound) outbounds.push(outbound);
  }

  return uniqByTag(outbounds);
}

function normalizeStrategy(strategy?: string): string {
  if (!strategy) return 'roundRobin';
  if (strategy === 'round-robin') return 'roundRobin';
  return strategy;
}

function targetForConnections(outboundTags: string[], strategy: string): { ruleTarget: Pick<XrayRoutingRule, 'outboundTag' | 'balancerTag'>; balancers: XrayBalancer[] } {
  if (outboundTags.length > 1) {
    return {
      ruleTarget: { balancerTag: 'proxy-balancer' },
      balancers: [{ tag: 'proxy-balancer', selector: outboundTags, strategy: { type: normalizeStrategy(strategy) } }],
    };
  }
  if (outboundTags.length === 1) return { ruleTarget: { outboundTag: outboundTags[0] }, balancers: [] };
  return { ruleTarget: { outboundTag: 'direct' }, balancers: [] };
}

function isManagedConnectionRule(rule: XrayRoutingRule): boolean {
  if (!Array.isArray(rule.inboundTag)) return false;
  return rule.inboundTag.some(tag => MANAGED_INBOUND_TAGS.has(tag));
}

function isDefaultBypassRule(rule: XrayRoutingRule): boolean {
  const domains = rule.domain || [];
  const ips = rule.ip || [];
  return (
    rule.outboundTag === 'direct' && (
      domains.some(d => ['geosite:cn', 'geosite:private'].includes(d)) ||
      ips.some(ip => ['geoip:cn', 'geoip:private'].includes(ip)) ||
      rule.network === 'udp'
    )
  );
}

function defaultBypassRules(): XrayRoutingRule[] {
  return [
    { type: 'field', ip: ['geoip:private'], outboundTag: 'direct' },
    { type: 'field', ip: ['geoip:cn'], outboundTag: 'direct' },
    { type: 'field', domain: ['geosite:cn'], outboundTag: 'direct' },
    { type: 'field', network: 'udp', outboundTag: 'direct' },
  ];
}

function buildRoutingRules(
  inbounds: XrayInbound[],
  connections: Connection[],
  settings: Settings,
  live: XrayConfig | null,
  strategy: string
): { rules: XrayRoutingRule[]; balancers: XrayBalancer[] } {
  const outboundTags = connections.map(c => c.outbound);
  const { ruleTarget, balancers } = targetForConnections(outboundTags, strategy);

  const rules: XrayRoutingRule[] = [];

  // DNS should never be proxied by the generic proxy target.
  if (inbounds.some(i => i.tag === 'dns')) {
    rules.push({ type: 'field', inboundTag: ['dns'], outboundTag: 'direct' });
  }

  // Generate one clear inbound binding rule per non-DNS entry. This preserves dynamic inbounds.
  for (const inbound of inbounds) {
    if (!inbound.tag || inbound.tag === 'dns') continue;
    rules.push({ type: 'field', inboundTag: [inbound.tag], ...ruleTarget });
  }

  // Preserve user/custom rules from live config and settings, but do not duplicate managed inbound/default rules.
  const customRules: XrayRoutingRule[] = [
    ...(settings.routing?.rules || []) as XrayRoutingRule[],
    ...(live?.routing?.rules || []) as XrayRoutingRule[],
  ].filter(rule => !isManagedConnectionRule(rule) && !isDefaultBypassRule(rule));

  rules.push(...customRules);
  rules.push(...defaultBypassRules());

  return { rules, balancers };
}

function generateDns(settings: Settings, live: XrayConfig | null): XrayDns | undefined {
  // Prefer the live DNS section so connect/disconnect does not silently replace user-tuned DNS.
  if (live?.dns) return live.dns;
  if (settings.dns?.servers?.length) {
    return {
      servers: settings.dns.servers,
      hosts: Object.keys(settings.dns.hosts || {}).length > 0 ? settings.dns.hosts : undefined,
    };
  }
  return {
    hosts: {},
    servers: ['119.29.29.29', '223.5.5.5'],
  };
}

/**
 * Generate complete Xray config from current live config + settings + connected nodes.
 * Preserves dynamic inbounds, always keeps DNS/transparent-ready inbounds and CN/private/UDP direct rules.
 */
export async function generateConfig(strategy: string = 'roundRobin'): Promise<XrayConfig> {
  const settings = await getSettings();
  const allNodes = await getNodes();
  const connectionState = await getConnections();
  const live = await readLiveConfig();
  const connections = connectionState.connected;
  const nodeMap = new Map(allNodes.map(n => [n.id, n]));

  const inbounds = buildInbounds(settings, live);
  const outbounds = buildOutbounds(connections, nodeMap, live);
  const { rules, balancers } = buildRoutingRules(inbounds, connections, settings, live, strategy);

  return {
    log: live?.log || { loglevel: settings.logLevel },
    inbounds,
    outbounds,
    routing: {
      domainStrategy: live?.routing?.domainStrategy || settings.routing.domainStrategy || 'IPIfNonMatch',
      rules,
      balancers: balancers.length > 0 ? balancers : live?.routing?.balancers?.filter(b => b.tag !== 'proxy-balancer'),
    },
    dns: generateDns(settings, live),
  };
}
