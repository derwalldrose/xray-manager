import { existsSync } from 'fs';
import { XRAY_BIN } from '../constants.js';
import { exec } from '../utils/shell.js';

export async function getInstalledVersion(): Promise<string | undefined> {
  if (!existsSync(XRAY_BIN)) return undefined;
  const result = await exec(XRAY_BIN, ['version'], { timeout: 10000 });
  const match = result.stdout.match(/Xray\s+(\S+)/);
  return match?.[1];
}
