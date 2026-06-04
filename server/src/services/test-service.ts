import type { TestResult, Node } from '@xray-manager/shared';
import { spawn } from 'child_process';
import { exec } from '../utils/shell.js';
import { XRAY_BIN, IS_WINDOWS } from '../constants.js';
import { writeFile, unlink, mkdir, rm } from 'fs/promises';
import { join } from 'path';
import { tmpdir, devNull } from 'os';
import { randomUUID } from 'crypto';
import { updateNodeTestResult } from './node-service.js';
import { getTestUrls } from './test-url-service.js';

function curlCommand(): string {
  return IS_WINDOWS ? 'curl.exe' : 'curl';
}

function curlError(prefix: string, r: { code: number; stdout?: string; stderr?: string }): Error {
  const detail = [
    `exit=${r.code}`,
    r.stderr ? `stderr=${r.stderr}` : '',
    r.stdout ? `stdout=${r.stdout.slice(0, 500)}` : '',
  ].filter(Boolean).join(' ');
  return new Error(`${prefix}: ${detail || 'no output'}`);
}

export async function testNode(node: Node, mode: 'ping' | 'speed' | 'both' = 'both'): Promise<TestResult> {
  const testId = randomUUID();
  const tempDir = join(tmpdir(), `xray-test-${testId}`);
  const configPath = join(tempDir, 'config.json');
  const socksPort = 30000 + Math.floor(Math.random() * 10000);
  let xrayProc: any = null;
  try {
    await mkdir(tempDir, { recursive: true });
    const config = {
      log: { loglevel: 'warning' },
      inbounds: [{ tag: 'socks-in', port: socksPort, listen: '127.0.0.1', protocol: 'socks', settings: { udp: false, auth: 'noauth' } }],
      outbounds: [{ tag: 'test-out', protocol: node.protocol, settings: node.settings, streamSettings: node.streamSettings, mux: node.mux }],
      routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', outboundTag: 'test-out', network: 'tcp' }] },
    };
    await writeFile(configPath, JSON.stringify(config, null, 2));

    const test = await exec(XRAY_BIN, ['run', '-test', '-config', configPath]).catch((e: any) => ({ code: 1, stdout: '', stderr: e.message }));
    if (test.code !== 0) throw curlError('Xray config test failed', test);

    xrayProc = spawn(XRAY_BIN, ['run', '-config', configPath], { cwd: tempDir, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    let xrayError = '';
    xrayProc.stderr?.on('data', (data: Buffer) => { xrayError += data.toString(); });
    await sleep(1500);
    if (xrayProc.exitCode !== null) throw new Error(`Xray failed to start: ${xrayError || `exitCode=${xrayProc.exitCode}`}`);

    const urls = await getTestUrls();
    let latency: number | undefined;
    let speed: number | undefined;
    let exitIp: string | undefined;
    const proxy = `socks5h://127.0.0.1:${socksPort}`;

    if (mode === 'ping' || mode === 'both') {
      const startTime = Date.now();
      const curlResult = await exec(curlCommand(), ['-L', '-k', '-x', proxy, '--connect-timeout', '5', '--max-time', '12', '-sS', urls.latency], { timeout: 15000 });
      if (curlResult.code !== 0) throw curlError('curl latency failed', curlResult);
      latency = Date.now() - startTime;
      const body = curlResult.stdout.trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(body)) exitIp = body;
    }

    if (mode === 'speed' || mode === 'both') {
      const speedResult = await exec(curlCommand(), ['-L', '-k', '-x', proxy, '--connect-timeout', '5', '--max-time', '25', '-sS', '-o', devNull, '-w', '%{speed_download}', urls.speed], { timeout: 30000 });
      if (speedResult.code === 0) {
        const bps = parseFloat(speedResult.stdout.trim());
        if (bps > 0) speed = Math.round((bps * 8) / 1000000 * 100) / 100;
      } else if (mode === 'speed') {
        throw curlError('curl speed failed', speedResult);
      }
    }

    if (latency !== undefined || speed !== undefined) await updateNodeTestResult(node.id, latency, speed);
    return { nodeId: node.id, ok: true, latency, speed, exitIp };
  } catch (err: any) {
    return { nodeId: node.id, ok: false, error: err.message || 'Unknown error' };
  } finally {
    if (xrayProc) {
      try { xrayProc.kill(IS_WINDOWS ? undefined : 'SIGTERM'); } catch {}
      await sleep(300);
      try { if (xrayProc.exitCode === null) xrayProc.kill(IS_WINDOWS ? undefined : 'SIGKILL'); } catch {}
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
