# xray-manager v4

Cross-platform Xray Manager based on v3, with native Windows support.

## Goals

- Linux: keep v3 systemd/supervisor support and transparent proxy features.
- Windows: run as a native Node.js web panel that directly manages `xray.exe`.
- First start automatically downloads the matching Xray-core release for the current OS/CPU.
- Windows global proxy uses Windows system proxy APIs instead of Linux iptables.

## Runtime directories

Default base directory:

- Windows: `C:\xray-manager-v4`
- Linux: `/root/xray-manager-v4`
- macOS: `/usr/local/xray-manager-v4`

Override with:

```bash
XRAY_MANAGER_HOME=/custom/path
# or
XRAY_MANAGER_V4_HOME=/custom/path
```

Layout:

```text
<base>/
  bin/                 # xray(.exe), geoip.dat, geosite.dat
  config/              # xray-multi-socks.json
  data/                # token, nodes.json, connections.json, xray.pid
  backup/
  logs/                # xray.log
  index.js
  web-dist/
```

## Download prebuilt portable ZIP

The `v4` branch includes a GitHub Actions workflow: `.github/workflows/build-v4.yml`.

It builds these artifacts on every push to the `v4` branch and on manual workflow runs:

- `xray-manager-v4-windows-x64.zip`
- `xray-manager-v4-linux-x64.zip`
- `xray-manager-v4-macos-x64.zip`

For normal users:

1. Open GitHub → repository → **Actions** → **Build v4 portable packages**.
2. Open the latest successful run.
3. Download the `xray-manager-v4-windows-x64` artifact.
4. Unzip it and run `run-windows.bat` or `run-windows.ps1`.
5. Open `http://127.0.0.1:54321`, default token is `123456`.

If a `v4*` tag is pushed, the same ZIP files are uploaded to GitHub Releases.

> Note: the portable ZIP still requires Node.js 20+ installed on the machine. Xray itself is downloaded automatically by xray-manager on first start.

## Windows quick start from source

```powershell
cd C:\xray-manager-v4-src
corepack enable
corepack prepare pnpm@11.5.1 --activate
pnpm install --config.dangerouslyAllowAllBuilds=true
pnpm run build

New-Item -ItemType Directory -Force C:\xray-manager-v4 | Out-Null
Copy-Item server\dist\index.js C:\xray-manager-v4\index.js -Force
Copy-Item web\dist C:\xray-manager-v4\web-dist -Recurse -Force

$env:XRAY_MANAGER_HOME = 'C:\xray-manager-v4'
$env:PORT = '54321'
node C:\xray-manager-v4\index.js
```

On first start, v4 downloads `Xray-windows-<arch>.zip` from XTLS/Xray-core and extracts `xray.exe` into `bin/`.

## Platform differences

Windows native mode does **not** support Linux transparent proxy features:

- no `iptables` REDIRECT chains
- no `/etc/resolv.conf` DNS hijack
- no Linux `sysctl`

Use the Windows system proxy endpoint instead:

```http
POST /api/system-proxy/enable
POST /api/system-proxy/disable
GET  /api/system-proxy/status
```

The Windows Xray runtime is process-managed:

```text
node index.js
  └── xray.exe run -config <base>\config\xray-multi-socks.json
```

Linux can still use systemd/supervisor, with process-managed fallback for development.
