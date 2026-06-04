import { spawn } from 'child_process';
import { mkdir } from 'fs/promises';
import { dirname } from 'path';

export interface ShellResult {
  stdout: string;
  stderr: string;
  code: number;
}

/** Execute a command safely without shell injection. */
export function exec(
  command: string,
  args: string[] = [],
  options: { timeout?: number; cwd?: string; env?: Record<string, string> } = {}
): Promise<ShellResult> {
  const { timeout = 30000, cwd, env } = options;

  return new Promise((resolve, reject) => {
    const proc = spawn(command, args, {
      cwd,
      env: env ? { ...process.env, ...env } : process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });

    let stdout = '';
    let stderr = '';
    let killed = false;

    const timer = setTimeout(() => {
      killed = true;
      proc.kill(process.platform === 'win32' ? undefined : 'SIGKILL');
    }, timeout);

    proc.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      clearTimeout(timer);
      if (killed) {
        reject(new Error(`Command timed out after ${timeout}ms: ${command} ${args.join(' ')}`));
        return;
      }
      resolve({ stdout: stdout.trim(), stderr: stderr.trim(), code: code ?? 1 });
    });

    proc.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export async function systemctl(action: string, unit: string): Promise<ShellResult> {
  return exec('systemctl', [action, unit]);
}

export async function execOrThrow(
  command: string,
  args: string[] = [],
  options?: { timeout?: number; cwd?: string }
): Promise<string> {
  const result = await exec(command, args, options);
  if (result.code !== 0) {
    throw new Error(`${command} failed (code ${result.code}): ${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

export async function ensureParentDir(path: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
}
