
import { exec } from '../utils/shell.js';
import { IS_WINDOWS } from '../constants.js';
import { networkInterfaces } from 'os';

let cachedBinary: string | null = null;

/** Detect iptables-legacy first (matches working v1/v2 behavior). */
async function ipt(): Promise<string> {
  if (IS_WINDOWS) return 'unsupported-windows-iptables';
  if (cachedBinary) return cachedBinary;
  for (const bin of ['iptables-legacy', 'iptables-nft', 'iptables']) {
    try {
      const r = await exec('which', [bin]);
      if (r.code === 0 && r.stdout.trim()) {
        cachedBinary = r.stdout.trim();
        return cachedBinary;
      }
    } catch {}
  }
  cachedBinary = 'iptables';
  return cachedBinary;
}

async function run(bin: string, args: string[]): Promise<void> {
  await exec(bin, args).catch(() => {});
}

async function delLoop(bin: string, args: string[]): Promise<void> {
  for (let i = 0; i < 20; i++) {
    const r = await exec(bin, args).catch(() => ({ code: 1 } as any));
    if (r.code !== 0) break;
  }
}

/** Detect local LAN subnets for MASQUERADE (gateway mode). */
function getLocalSubnets(): string[] {
  const subnets: string[] = [];
  const ifaces = networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (!addrs || name === 'lo' || name.startsWith('docker') || name.startsWith('br-') || name.startsWith('veth')) continue;
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        // Convert IP + netmask to CIDR
        const parts = addr.address.split('.').map(Number);
        const maskParts = addr.netmask.split('.').map(Number);
        const network = parts.map((p, i) => p & maskParts[i]).join('.');
        const cidrBits = maskParts.reduce((acc, m) => acc + m.toString(2).split('1').length - 1, 0);
        subnets.push(`${network}/${cidrBits}`);
      }
    }
  }
  return [...new Set(subnets)];
}

export async function getIptablesRules(): Promise<{ binary: string; nat: string; filter: string; mangle: string }> {
  if (IS_WINDOWS) {
    return { binary: 'unsupported-windows-iptables', nat: '', filter: '', mangle: '' };
  }
  const bin = await ipt();
  const [nat, filter, mangle] = await Promise.all([
    exec(bin + '-save', ['-t', 'nat']).then(r => r.stdout).catch(() => ''),
    exec(bin + '-save', ['-t', 'filter']).then(r => r.stdout).catch(() => ''),
    exec(bin + '-save', ['-t', 'mangle']).then(r => r.stdout).catch(() => ''),
  ]);
  return { binary: bin, nat, filter, mangle };
}

export async function setupTransparentProxy(redirPort: number, bypassCidrs: string[]): Promise<void> {
  if (IS_WINDOWS) {
    throw new Error('Windows native mode does not support Linux iptables transparent proxy. Use Windows system proxy mode instead.');
  }
  const bin = await ipt();

  // Idempotency: remove stale jumps first, then rebuild chains.
  await cleanupTransparentProxy();

  for (const chain of ['XRAY_MGR_OUT', 'XRAY_MGR_PRE', 'XRAY_MGR_RULE']) {
    await run(bin, ['-t', 'nat', '-N', chain]);
    await run(bin, ['-t', 'nat', '-F', chain]);
  }

  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_OUT', '-j', 'XRAY_MGR_RULE']);
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_PRE', '-j', 'XRAY_MGR_RULE']);

  // Full bypass list matching working v1/v2 (transparent-bypass.json + hardcoded).
  const bypass = new Set([
    ...bypassCidrs,
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
    '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    '127.0.0.1/32', '119.29.29.29/32', '223.5.5.5/32',
  ]);
  for (const cidr of bypass) {
    await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-d', cidr, '-j', 'RETURN']);
  }

  // Xray outbounds set sockopt.mark=128 (0x80); never redirect Xray's own traffic.
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-m', 'mark', '--mark', '0x80/0x80', '-j', 'RETURN']);

  // Mirror the proven v1/v2 REDIRECT shape:
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-p', 'tcp', '-j', 'REDIRECT', '--to-ports', String(redirPort)]);
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-p', 'udp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(redirPort)]);

  // Attach with protocol filters and before Docker's PREROUTING/OUTPUT local rules.
  await run(bin, ['-t', 'nat', '-I', 'PREROUTING', '1', '-p', 'tcp', '-j', 'XRAY_MGR_PRE']);
  await run(bin, ['-t', 'nat', '-I', 'PREROUTING', '1', '-p', 'udp', '--dport', '53', '-j', 'XRAY_MGR_PRE']);
  await run(bin, ['-t', 'nat', '-I', 'OUTPUT', '1', '-p', 'tcp', '-j', 'XRAY_MGR_OUT']);

  // POSTROUTING MASQUERADE — required for gateway mode (LAN clients need NAT for return traffic).
  for (const subnet of getLocalSubnets()) {
    await run(bin, ['-t', 'nat', '-A', 'POSTROUTING', '-s', subnet, '!', '-o', 'lo', '-j', 'MASQUERADE']);
  }

  // QUIC/HTTP3 bypasses REDIRECT; block both local and forwarded UDP 443.
  await run(bin, ['-I', 'OUTPUT', '1', '-p', 'udp', '--dport', '443', '-j', 'DROP']);
  await run(bin, ['-I', 'FORWARD', '1', '-p', 'udp', '--dport', '443', '-j', 'DROP']);

  // Gateway sysctl settings (matching working v1/v2).
  await exec('sysctl', ['-w', 'net.ipv4.ip_forward=1']).catch(() => {});
  await exec('sysctl', ['-w', 'net.ipv4.conf.all.rp_filter=0']).catch(() => {});
  await exec('sysctl', ['-w', 'net.ipv4.conf.default.rp_filter=0']).catch(() => {});
}

export async function cleanupTransparentProxy(): Promise<void> {
  if (IS_WINDOWS) return;
  const bin = await ipt();

  // Remove both the old generic v3 jumps and the corrected protocol-filtered jumps.
  await delLoop(bin, ['-t', 'nat', '-D', 'OUTPUT', '-p', 'tcp', '-j', 'XRAY_MGR_OUT']);
  await delLoop(bin, ['-t', 'nat', '-D', 'OUTPUT', '-j', 'XRAY_MGR_OUT']);
  await delLoop(bin, ['-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '-j', 'XRAY_MGR_PRE']);
  await delLoop(bin, ['-t', 'nat', '-D', 'PREROUTING', '-p', 'udp', '--dport', '53', '-j', 'XRAY_MGR_PRE']);
  await delLoop(bin, ['-t', 'nat', '-D', 'PREROUTING', '-j', 'XRAY_MGR_PRE']);

  for (const chain of ['XRAY_MGR_OUT', 'XRAY_MGR_PRE', 'XRAY_MGR_RULE']) {
    await run(bin, ['-t', 'nat', '-F', chain]);
  }
  for (const chain of ['XRAY_MGR_OUT', 'XRAY_MGR_PRE', 'XRAY_MGR_RULE']) {
    await run(bin, ['-t', 'nat', '-X', chain]);
  }

  // Remove MASQUERADE rules we added for local subnets.
  for (const subnet of getLocalSubnets()) {
    await delLoop(bin, ['-t', 'nat', '-D', 'POSTROUTING', '-s', subnet, '!', '-o', 'lo', '-j', 'MASQUERADE']);
  }

  await delLoop(bin, ['-D', 'OUTPUT', '-p', 'udp', '--dport', '443', '-j', 'DROP']);
  await delLoop(bin, ['-D', 'FORWARD', '-p', 'udp', '--dport', '443', '-j', 'DROP']);
}

export async function hasIptablesRules(): Promise<boolean> {
  if (IS_WINDOWS) return false;
  const bin = await ipt();
  try {
    const r = await exec(bin + '-save', ['-t', 'nat']);
    return r.stdout.includes(':XRAY_MGR_RULE')
      && r.stdout.includes('-p tcp')
      && r.stdout.includes('--to-ports 12345')
      && r.stdout.includes('-p udp')
      && r.stdout.includes('--dport 53');
  } catch {
    return false;
  }
}

export async function hasQuicBlock(): Promise<boolean> {
  if (IS_WINDOWS) return false;
  const bin = await ipt();
  try {
    const r = await exec(bin + '-save', ['-t', 'filter']);
    return r.stdout.includes('-A OUTPUT -p udp')
      && r.stdout.includes('--dport 443')
      && r.stdout.includes('-A FORWARD -p udp')
      && r.stdout.includes(' -j DROP');
  } catch {
    return false;
  }
}
