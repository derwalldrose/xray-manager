$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Runtime = $env:XRAY_MANAGER_HOME
if ([string]::IsNullOrWhiteSpace($Runtime)) {
  $Runtime = 'C:\xray-manager-v4'
}
$Port = $env:PORT
if ([string]::IsNullOrWhiteSpace($Port)) {
  $Port = '54321'
}

Write-Host "Building xray-manager v4..."
Set-Location $Root
corepack enable
pnpm install --config.dangerouslyAllowAllBuilds=true
pnpm run build

Write-Host "Installing runtime to $Runtime ..."
New-Item -ItemType Directory -Force $Runtime | Out-Null
Copy-Item "$Root\server\dist\index.js" "$Runtime\index.js" -Force
if (Test-Path "$Runtime\web-dist") { Remove-Item "$Runtime\web-dist" -Recurse -Force }
Copy-Item "$Root\web\dist" "$Runtime\web-dist" -Recurse -Force

New-Item -ItemType Directory -Force "$Runtime\bin", "$Runtime\config", "$Runtime\data", "$Runtime\logs", "$Runtime\backup" | Out-Null

Write-Host "Starting panel on http://127.0.0.1:$Port"
$env:XRAY_MANAGER_HOME = $Runtime
$env:PORT = $Port
node "$Runtime\index.js"
