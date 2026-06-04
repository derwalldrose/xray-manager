import type { TestResult, Node } from '@xray-manager/shared';
import { spawn } from 'child_process';
import { exec } from '../utils/shell.js';
import { XRAY_BIN } from '../constants.js';
import { writeFile, unlink, mkdir, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir } from 'os';
import { randomUUID } from 'crypto';
import { updateNodeTestResult } from './node-service.js';
import { getTestUrls } from './test-url-service.js';

export async function testNode(node: Node, mode: 'ping' | 'speed' | 'both' = 'both'): Promise<TestResult> {
  const testId = randomUUID();
  const tempDir = join(tmpdir(), `xray-test-${testId}`);
  const configPath = join(tempDir, 'config.json');
  const socksPort = 30000 + Math.floor(Math.random() * 10000);
  let xrayProc: any = null;
  try {
    await mkdir(tempDir, { recursive: true });
    const config = {
      log: { loglevel: 'error' },
      inbounds: [{ tag: 'socks-in', port: socksPort, listen: '127.0.0.1', protocol: 'socks', settings: { udp: false, auth: 'noauth' } }],
      outbounds: [{ tag: 'test-out', protocol: node.protocol, settings: node.settings, streamSettings: node.streamSettings, mux: node.mux }],
      routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', outboundTag: 'test-out', network: 'tcp' }] },
    };
    await writeFile(configPath, JSON.stringify(config, null, 2));
    const test = await exec(XRAY_BIN, ['run', '-test', '-config', configPath]).catch((e: any) => ({ code: 1, stderr: e.message }));
    if (test.code !== 0) throw new Error(`Xray config test failed: ${test.stderr}`);
    xrayProc = spawn(XRAY_BIN, ['run', '-config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
    let xrayError = '';
    xrayProc.stderr?.on('data', (data: Buffer) => { xrayError += data.toString(); });
    await sleep(1200);
    if (xrayProc.exitCode !== null) throw new Error(`Xray failed to start: ${xrayError}`);

    const urls = await getTestUrls();
    let latency: number | undefined;
    let speed: number | undefined;
    let exitIp: string | undefined;

    if (mode === 'ping' || mode === 'both') {
      const startTime = Date.now();
      const curlResult = await exec('curl', ['--socks5', `127.0.0.1:${socksPort}`, '--connect-timeout', '5', '--max-time', '12', '-s', urls.latency], { timeout: 15000 });
      if (curlResult.code !== 0) throw new Error(`curl failed: ${curlResult.stderr}`);
      latency = Date.now() - startTime;
      const body = curlResult.stdout.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(body)) exitIp = body;
    }

    if (mode === 'speed' || mode === 'both') {
      const speedResult = await exec('curl', ['--socks5', `127.0.0.1:${socksPort}`, '--connect-timeout', '5', '--max-time', '25', '-s', '-o', '/dev/null', '-w', '%{speed_download}', urls.speed], { timeout: 30000 });
      if (speedResult.code === 0) {
        const bps = parseFloat(speedResult.stdout.trim());
        if (bps > 0) speed = Math.round((bps * 8) / 1000000 * 100) / 100;
      }
    }

    if (latency !== undefined || speed !== undefined) await updateNodeTestResult(node.id, latency, speed);
    return { nodeId: node.id, ok: true, latency, speed, exitIp };
  } catch (err: any) {
    return { nodeId: node.id, ok: false, error: err.message || 'Unknown error' };
  } finally {
    if (xrayProc) {
      try { xrayProc.kill('SIGTERM'); } catch {}
      await sleep(300);
      try { if (xrayProc.exitCode === null) xrayProc.kill('SIGKILL'); } catch {}
    }
    try { await unlink(configPath); } catch {}
    try { await rm(tempDir, { recursive: true, force: true }); } catch {}
  }
}

export async function testNodes(nodes: Node[], mode: 'ping' | 'speed' | 'both' = 'both'): Promise<TestResult[]> {
  const results: TestResult[] = [];
  for (const node of nodes) results.push(await testNode(node, mode));
  return results;
}

function sleep(ms: number): Promise<void> { return new Promise(resolve => setTimeout(resolve, ms)); }
