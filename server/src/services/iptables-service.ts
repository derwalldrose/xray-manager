
import { exec } from '../utils/shell.js';
import { IS_WINDOWS } from '../constants.js';

let cachedBinary: string | null = null;

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

  // Idempotency: remove stale v3/v1 jumps first, then rebuild chains.
  await cleanupTransparentProxy();

  for (const chain of ['XRAY_MGR_OUT', 'XRAY_MGR_PRE', 'XRAY_MGR_RULE']) {
    await run(bin, ['-t', 'nat', '-N', chain]);
    await run(bin, ['-t', 'nat', '-F', chain]);
  }

  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_OUT', '-j', 'XRAY_MGR_RULE']);
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_PRE', '-j', 'XRAY_MGR_RULE']);

  const bypass = new Set([
    ...bypassCidrs,
    // Keep upstream DNS and localhost out of the redirect path, matching the working v1 rules.
    '127.0.0.1/32',
    '119.29.29.29/32',
    '223.5.5.5/32',
  ]);
  for (const cidr of bypass) {
    await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-d', cidr, '-j', 'RETURN']);
  }

  // Xray outbounds set sockopt.mark=128 (0x80); never redirect Xray's own traffic.
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-m', 'mark', '--mark', '0x80/0x80', '-j', 'RETURN']);

  // Mirror the proven v1/v2 REDIRECT shape:
  // - TCP traffic -> transparent dokodemo-door
  // - only UDP DNS (53) -> transparent dokodemo-door
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-p', 'tcp', '-j', 'REDIRECT', '--to-ports', String(redirPort)]);
  await run(bin, ['-t', 'nat', '-A', 'XRAY_MGR_RULE', '-p', 'udp', '--dport', '53', '-j', 'REDIRECT', '--to-ports', String(redirPort)]);

  // Attach with protocol filters and before Docker's PREROUTING/OUTPUT local rules.
  await run(bin, ['-t', 'nat', '-I', 'PREROUTING', '1', '-p', 'tcp', '-j', 'XRAY_MGR_PRE']);
  await run(bin, ['-t', 'nat', '-I', 'PREROUTING', '1', '-p', 'udp', '--dport', '53', '-j', 'XRAY_MGR_PRE']);
  await run(bin, ['-t', 'nat', '-I', 'OUTPUT', '1', '-p', 'tcp', '-j', 'XRAY_MGR_OUT']);

  // QUIC/HTTP3 bypasses REDIRECT; block both local and forwarded UDP 443.
  await run(bin, ['-I', 'OUTPUT', '1', '-p', 'udp', '--dport', '443', '-j', 'DROP']);
  await run(bin, ['-I', 'FORWARD', '1', '-p', 'udp', '--dport', '443', '-j', 'DROP']);

  await exec('sysctl', ['-w', 'net.ipv4.ip_forward=1']).catch(() => {});
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
