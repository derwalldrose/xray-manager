# xray-manager-v4 portable launcher
$ErrorActionPreference = 'Stop'
$Runtime = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($env:XRAY_MANAGER_HOME)) {
  $env:XRAY_MANAGER_HOME = $Runtime
}
if ([string]::IsNullOrWhiteSpace($env:PORT)) {
  $env:PORT = '54321'
}
if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Write-Host '[xray-manager-v4] Node.js 20+ is required but was not found in PATH.' -ForegroundColor Red
  Write-Host 'Install Node.js from https://nodejs.org/ and run this script again.'
  Read-Host 'Press Enter to exit'
  exit 1
}
Write-Host "[xray-manager-v4] Starting http://127.0.0.1:$env:PORT"
node (Join-Path $Runtime 'index.js')
