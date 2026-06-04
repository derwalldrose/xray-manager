import { join } from 'path';

export const PLATFORM = process.platform;
export const IS_WINDOWS = PLATFORM === 'win32';
export const IS_LINUX = PLATFORM === 'linux';
export const IS_MACOS = PLATFORM === 'darwin';

const DEFAULT_BASE = IS_WINDOWS
  ? 'C:\\xray-manager-v4'
  : IS_MACOS
    ? '/usr/local/xray-manager-v4'
    : '/root/xray-manager-v4';

export const BASE_DIR = process.env.XRAY_MANAGER_HOME || process.env.XRAY_MANAGER_V4_HOME || DEFAULT_BASE;
export const DATA_DIR = join(BASE_DIR, 'data');
export const CONFIG_DIR = join(BASE_DIR, 'config');
export const BACKUP_DIR = join(BASE_DIR, 'backup');
export const LOG_DIR = join(BASE_DIR, 'logs');
export const BIN_DIR = join(BASE_DIR, 'bin');
export const XRAY_BIN = join(BIN_DIR, IS_WINDOWS ? 'xray.exe' : 'xray');
export const SERVICE_NAME = process.env.XRAY_SERVICE_NAME || 'xray-multi-socks.service';
export const CONFIG_FILE = join(CONFIG_DIR, 'xray-multi-socks.json');
export const NODES_FILE = join(DATA_DIR, 'nodes.json');
export const CONNECTIONS_FILE = join(DATA_DIR, 'connections.json');
export const SETTINGS_FILE = join(DATA_DIR, 'settings.json');
export const XRAY_PID_FILE = join(DATA_DIR, 'xray.pid');
export const XRAY_LOG_FILE = join(LOG_DIR, 'xray.log');
export const SERVER_PORT = parseInt(process.env.PORT || '54321', 10);
