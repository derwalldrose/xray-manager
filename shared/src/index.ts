// Node types
export interface Node {
  id: string;
  tag: string;
  protocol: 'vless' | 'vmess' | 'trojan' | 'shadowsocks';
  address: string;
  port: number;
  settings: any;
  streamSettings?: any;
  mux?: any;
  latency?: number;
  speed?: number;
  createdAt: number;
  updatedAt: number;
}

export interface Subscription {
  id: string;
  url: string;
  name: string;
  nodeIds: string[];
  lastUpdated: number;
}

// Connection types
export interface Connection {
  nodeId: string;
  outbound: string;
}

export interface ConnectionState {
  connected: Connection[];
  active: boolean;
  startedAt?: number;
}

// Settings types
export interface Ports {
  socks: number;
  http: number;
  transparent: number;
}

export interface DnsConfig {
  servers: string[];
  hosts: Record<string, string>;
}

export interface RoutingRule {
  type: string;
  domain?: string[];
  ip?: string[];
  port?: string;
  network?: string;
  inboundTag?: string[];
  outboundTag?: string;
  balancerTag?: string;
}

export interface RoutingConfig {
  domainStrategy: string;
  rules: RoutingRule[];
}

export interface TransparentConfig {
  enabled: boolean;
  bypassCidrs: string[];
}

export interface Settings {
  ports: Ports;
  dns: DnsConfig;
  routing: RoutingConfig;
  transparent: TransparentConfig;
  logLevel: string;
}

// API types
export interface ServiceStatus {
  running: boolean;
  pid?: number;
  memory?: string;
  uptime?: string;
  version?: string;
  listenPorts: string[];
}

export interface TrafficStats {
  rxSpeed: number;
  txSpeed: number;
  interfaces: Record<string, { rx: number; tx: number }>;
}

export interface TestResult {
  nodeId: string;
  ok: boolean;
  latency?: number;
  speed?: number;
  exitIp?: string;
  error?: string;
}

// Xray config types
export interface XrayConfig {
  log: { loglevel: string };
  inbounds: XrayInbound[];
  outbounds: XrayOutbound[];
  routing: {
    domainStrategy: string;
    rules: XrayRoutingRule[];
    balancers?: XrayBalancer[];
  };
  dns?: XrayDns;
}

export interface XrayInbound {
  tag: string;
  port: number;
  listen: string;
  protocol: string;
  settings?: any;
  streamSettings?: any;
  sniffing?: any;
}

export interface XrayOutbound {
  tag: string;
  protocol: string;
  settings?: any;
  streamSettings?: any;
  mux?: any;
}

export interface XrayRoutingRule {
  type: string;
  domain?: string[];
  ip?: string[];
  port?: string;
  network?: string;
  inboundTag?: string[];
  outboundTag?: string;
  balancerTag?: string;
}

export interface XrayBalancer {
  tag: string;
  selector: string[];
  strategy?: { type: string };
}

export interface XrayDns {
  servers: (string | { address: string; domains?: string[] })[];
  hosts?: Record<string, string | string[]>;
}
