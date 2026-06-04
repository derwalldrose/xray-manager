import { Hono } from 'hono';
import { exec } from '../utils/shell.js';
import { IS_WINDOWS } from '../constants.js';

const systemProxy = new Hono();
const REG_PATH = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

function unsupported() {
  return { supported: false, enabled: false, message: 'System proxy API is currently implemented for Windows native mode only.' };
}

async function ps(command: string) {
  return exec('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command], { timeout: 15000 });
}

systemProxy.get('/status', async (c) => {
  if (!IS_WINDOWS) return c.json(unsupported());
  const cmd = `$p=Get-ItemProperty -Path '${REG_PATH}'; [pscustomobject]@{ProxyEnable=$p.ProxyEnable;ProxyServer=$p.ProxyServer;ProxyOverride=$p.ProxyOverride;AutoConfigURL=$p.AutoConfigURL}|ConvertTo-Json -Compress`;
  const r = await ps(cmd);
  if (r.code !== 0) return c.json({ supported: true, enabled: false, error: r.stderr || r.stdout }, 500);
  const data = JSON.parse(r.stdout || '{}');
  return c.json({ supported: true, enabled: Number(data.ProxyEnable || 0) === 1, ...data });
});

systemProxy.post('/enable', async (c) => {
  if (!IS_WINDOWS) return c.json(unsupported(), 400);
  const body = await c.req.json().catch(() => ({}));
  const host = body.host || '127.0.0.1';
  const port = Number(body.port || 10818);
  const bypass = body.bypass || '<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*';
  const server = body.server || `${host}:${port}`;
  const cmd = `Set-ItemProperty -Path '${REG_PATH}' -Name ProxyEnable -Value 1; Set-ItemProperty -Path '${REG_PATH}' -Name ProxyServer -Value '${String(server).replace(/'/g, "''")}'; Set-ItemProperty -Path '${REG_PATH}' -Name ProxyOverride -Value '${String(bypass).replace(/'/g, "''")}'; Set-ItemProperty -Path '${REG_PATH}' -Name AutoConfigURL -Value ''; Add-Type -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);' -Name WinInet -Namespace Native; [Native.WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0) | Out-Null; [Native.WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0) | Out-Null`;
  const r = await ps(cmd);
  if (r.code !== 0) return c.json({ ok: false, error: r.stderr || r.stdout }, 500);
  return c.json({ ok: true, enabled: true, server, bypass });
});

systemProxy.post('/disable', async (c) => {
  if (!IS_WINDOWS) return c.json(unsupported(), 400);
  const cmd = `Set-ItemProperty -Path '${REG_PATH}' -Name ProxyEnable -Value 0; Set-ItemProperty -Path '${REG_PATH}' -Name ProxyServer -Value ''; Set-ItemProperty -Path '${REG_PATH}' -Name ProxyOverride -Value ''; Set-ItemProperty -Path '${REG_PATH}' -Name AutoConfigURL -Value ''; Add-Type -MemberDefinition '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);' -Name WinInet -Namespace Native; [Native.WinInet]::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0) | Out-Null; [Native.WinInet]::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0) | Out-Null`;
  const r = await ps(cmd);
  if (r.code !== 0) return c.json({ ok: false, error: r.stderr || r.stdout }, 500);
  return c.json({ ok: true, enabled: false });
});

export default systemProxy;
