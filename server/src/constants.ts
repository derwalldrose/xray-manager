import { join } from 'path';

export const BASE_DIR = '/root/xray-manager-v3';
export const DATA_DIR = join(BASE_DIR, 'data');
export const CONFIG_DIR = join(BASE_DIR, 'config');
export const XRAY_BIN = join(BASE_DIR, 'bin/xray');
export const SERVICE_NAME = 'xray-multi-socks.service';
export const CONFIG_FILE = join(CONFIG_DIR, 'xray-multi-socks.json');
export const NODES_FILE = join(DATA_DIR, 'nodes.json');
export const CONNECTIONS_FILE = join(DATA_DIR, 'connections.json');
export const SETTINGS_FILE = join(DATA_DIR, 'settings.json');
export const SERVER_PORT = 54321;
