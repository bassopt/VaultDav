import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import { createProxyMiddleware } from 'http-proxy-middleware';
import Database from 'better-sqlite3';
import { spawn, ChildProcess, execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import QRCode from 'qrcode';
import JSZip from 'jszip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
process.env.DISABLE_HMR = 'true';

// Canonical paths
const DATA_DIR = process.env.SQLITE_DB_PATH
  ? path.dirname(process.env.SQLITE_DB_PATH)
  : path.join(__dirname, 'data', 'db');
const DB_PATH = process.env.SQLITE_DB_PATH || path.join(DATA_DIR, 'vaultdav.sqlite');

const HOST_VOLUMES_DIR = process.env.HOST_VOLUMES_DIR
  ? path.resolve(process.env.HOST_VOLUMES_DIR)
  : path.join(__dirname, 'host_volumes');

const SYNCTHING_CONFIG_DIR = path.join(__dirname, 'data', 'syncthing-config');
const SYNCTHING_CONFIG_FILE = path.join(SYNCTHING_CONFIG_DIR, 'config.xml');
const RUNTIME_SYNCTHING_DIR = '/tmp/vaultdav-syncthing-runtime';
const SYNCTHING_BIN = fs.existsSync('/tmp/vaultdav-runtime/bin/syncthing')
  ? '/tmp/vaultdav-runtime/bin/syncthing'
  : path.join(__dirname, 'bin', 'syncthing');

const ENV_STACK_FILE = path.join(__dirname, 'data', '.env.stack');

// Ensure directories exist
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(HOST_VOLUMES_DIR, { recursive: true });
fs.mkdirSync(SYNCTHING_CONFIG_DIR, { recursive: true });
fs.mkdirSync(RUNTIME_SYNCTHING_DIR, { recursive: true });

// Ensure default host volume subfolders
const initialSubfolders = ['documents', 'projects', 'media', 'photos', 'backups'];
for (const sub of initialSubfolders) {
  const p = path.join(HOST_VOLUMES_DIR, sub);
  fs.mkdirSync(p, { recursive: true });
  const readmePath = path.join(p, `${sub}-readme.md`);
  if (!fs.existsSync(readmePath)) {
    fs.writeFileSync(
      readmePath,
      `# ${sub.toUpperCase()} Folder\n\nShared unencrypted inside \`./host_volumes/${sub}\` and bridged between WebDAV and Syncthing.\n`,
      'utf8'
    );
  }
}

// ============================================================================
// 1. SQLITE DATABASE: STRICTLY & EXCLUSIVELY FOR ENCRYPTED CREDENTIALS
// ============================================================================
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

const MASTER_SECRET = process.env.SQLITE_MASTER_KEY || 'vaultdav-aes256-gcm-master-secret-key-2026';
const KDF_SALT = 'vaultdav-sqlite-kdf-salt-v1';
const SYNCTHING_API_KEY = 'vaultdav-syncthing-local-api-key';
const SYNCTHING_TARGET_URL = process.env.SYNCTHING_URL || 'http://127.0.0.1:8384';

const activeSessions = new Map<string, { username: string; createdAt: number }>();

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function deriveEncryptionKey(secret: string): Buffer {
  return crypto.pbkdf2Sync(secret, KDF_SALT, 100000, 32, 'sha256');
}

function encryptSecret(plaintext: string, masterSecret = MASTER_SECRET) {
  const key = deriveEncryptionKey(masterSecret);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertextHex: encrypted.toString('hex'),
    ivHex: iv.toString('hex'),
    authTagHex: authTag.toString('hex'),
  };
}

function decryptSecret(ciphertextHex: string, ivHex: string, authTagHex: string, masterSecret = MASTER_SECRET): string {
  const key = deriveEncryptionKey(masterSecret);
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const encrypted = Buffer.from(ciphertextHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

function generateSafeWebdavPassword(length = 24): string {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#%^&*-_=+';
  const all = upper + lower + digits + symbols;

  const pick = (charset: string) => charset[crypto.randomInt(0, charset.length)];
  const chars: string[] = [
    pick(upper),
    pick(upper),
    pick(lower),
    pick(lower),
    pick(digits),
    pick(digits),
    pick(symbols),
    pick(symbols),
  ];

  while (chars.length < length) {
    chars.push(pick(all));
  }

  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    const tmp = chars[i];
    chars[i] = chars[j];
    chars[j] = tmp;
  }

  return chars.join('');
}

// Database tables
db.exec(`
  CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    ciphertext_hex TEXT NOT NULL,
    iv_hex TEXT NOT NULL,
    auth_tag_hex TEXT NOT NULL,
    totp_ciphertext_hex TEXT NOT NULL DEFAULT '',
    totp_iv_hex TEXT NOT NULL DEFAULT '',
    totp_auth_tag_hex TEXT NOT NULL DEFAULT '',
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    webdav_ciphertext_hex TEXT NOT NULL DEFAULT '',
    webdav_iv_hex TEXT NOT NULL DEFAULT '',
    webdav_auth_tag_hex TEXT NOT NULL DEFAULT '',
    kdf_spec TEXT NOT NULL DEFAULT 'PBKDF2-HMAC-SHA256 (100,000 iter) -> AES-256-GCM',
    created_at TEXT NOT NULL,
    last_used_at TEXT
  );
`);

function ensureWebdavCredentialsInSqlite() {
  const row = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
  if (row && (!row.webdav_ciphertext_hex || !row.webdav_iv_hex || !row.webdav_auth_tag_hex)) {
    const safePassword = generateSafeWebdavPassword(24);
    const encDav = encryptSecret(safePassword);
    db.prepare(`
      UPDATE credentials
      SET webdav_ciphertext_hex = ?, webdav_iv_hex = ?, webdav_auth_tag_hex = ?
      WHERE id = 1
    `).run(encDav.ciphertextHex, encDav.ivHex, encDav.authTagHex);
  }
}
ensureWebdavCredentialsInSqlite();

// TOTP (RFC 6238)
function generateBase32Secret(length = 20): string {
  const bytes = crypto.randomBytes(length);
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += BASE32_ALPHABET[bytes[i] % 32];
  }
  return secret;
}

function base32ToBuffer(base32: string): Buffer {
  const cleaned = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(output);
}

function generateTotpAtCounter(secretBase32: string, counter: number, digits = 6): string {
  const key = base32ToBuffer(secretBase32);
  const buf = Buffer.alloc(8);
  let tmp = counter;
  for (let i = 7; i >= 0; i--) {
    buf[i] = tmp & 0xff;
    tmp = Math.floor(tmp / 256);
  }

  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    (((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff)) %
    Math.pow(10, digits);

  return code.toString().padStart(digits, '0');
}

function verifyTotpCode(secretBase32: string, token: string, windowSteps = 1): boolean {
  const cleanToken = (token || '').trim().replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleanToken)) return false;

  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  for (let errorWindow = -windowSteps; errorWindow <= windowSteps; errorWindow++) {
    const expected = generateTotpAtCounter(secretBase32, currentCounter + errorWindow);
    if (expected === cleanToken) {
      return true;
    }
  }
  return false;
}

function verifyMainAppCredentials(username: string, plainPassword: string, totpCode?: string): { ok: boolean; error?: string } {
  const row = db
    .prepare(
      'SELECT id, username, ciphertext_hex, iv_hex, auth_tag_hex, totp_ciphertext_hex, totp_iv_hex, totp_auth_tag_hex, totp_enabled FROM credentials WHERE id = 1'
    )
    .get() as any;
  if (!row || row.username !== username) {
    return { ok: false, error: 'Invalid username or password' };
  }
  try {
    const decryptedPass = decryptSecret(row.ciphertext_hex, row.iv_hex, row.auth_tag_hex);
    const a = Buffer.from(plainPassword, 'utf8');
    const b = Buffer.from(decryptedPass, 'utf8');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return { ok: false, error: 'Invalid username or password' };
    }

    const isTotpActive = Boolean(row.totp_enabled && row.totp_ciphertext_hex && row.totp_iv_hex && row.totp_auth_tag_hex);
    if (isTotpActive) {
      if (!totpCode) {
        return { ok: false, error: '6-digit TOTP 2FA code is required' };
      }
      const decryptedTotpSecret = decryptSecret(row.totp_ciphertext_hex, row.totp_iv_hex, row.totp_auth_tag_hex);
      if (!verifyTotpCode(decryptedTotpSecret, totpCode)) {
        return { ok: false, error: 'Invalid 6-digit TOTP 2FA code' };
      }
    }

    db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = 1').run(new Date().toISOString());
    return { ok: true };
  } catch {
    return { ok: false, error: 'Decryption error verifying credentials' };
  }
}

function verifyWebdavBasicAuth(authHeader?: string): { ok: boolean; username?: string; error?: string } {
  const row = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
  if (!row) {
    return { ok: false, error: 'Account not initialized in SQLite' };
  }

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { ok: false, error: 'WebDAV Basic Authentication required' };
  }

  try {
    const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
    const colonIdx = decoded.indexOf(':');
    if (colonIdx === -1) return { ok: false, error: 'Malformed Basic Auth header' };

    const reqUser = decoded.slice(0, colonIdx);
    const reqPass = decoded.slice(colonIdx + 1);

    if (reqUser !== row.username) {
      return { ok: false, error: 'WebDAV username must match your account login username' };
    }

    const expectedSafePass = decryptSecret(
      row.webdav_ciphertext_hex,
      row.webdav_iv_hex,
      row.webdav_auth_tag_hex
    );

    const a = Buffer.from(reqPass, 'utf8');
    const b = Buffer.from(expectedSafePass, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = 1').run(new Date().toISOString());
      return { ok: true, username: reqUser };
    }

    return { ok: false, error: 'Invalid WebDAV safe password' };
  } catch {
    return { ok: false, error: 'Invalid WebDAV credentials' };
  }
}

function getDetectedLocalIp(): string {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal && !net.address.startsWith('169.254.')) {
        return net.address;
      }
    }
  }
  return '0.0.0.0';
}

// ============================================================================
// 2. STACK ENVIRONMENT & SINGLE HOST VOLUMES ROOT FOLDER
// ============================================================================
interface CustomHeaderItem {
  header_name: string;
  header_value: string;
  enabled: boolean;
}

function parseStackEnv(): {
  headers: CustomHeaderItem[];
  webdavHost: string;
  webdavPort: string;
} {
  let raw = '';
  if (fs.existsSync(ENV_STACK_FILE)) {
    raw = fs.readFileSync(ENV_STACK_FILE, 'utf8');
  }

  const map: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim().replace(/^"(.*)"$/, '$1');
    map[key] = val;
  }

  const headers: CustomHeaderItem[] = [];
  const rawHeaders = map['WEBDAV_CUSTOM_HEADERS'] || '';
  if (rawHeaders) {
    for (const part of rawHeaders.split(';')) {
      if (!part.trim()) continue;
      const [nv, flag] = part.split('|');
      const colonIdx = (nv || '').indexOf(':');
      if (colonIdx !== -1) {
        const hName = nv.slice(0, colonIdx).trim();
        const hVal = nv.slice(colonIdx + 1).trim();
        headers.push({
          header_name: hName,
          header_value: hVal,
          enabled: flag !== '0',
        });
      }
    }
  }

  const rawHost = map['WEBDAV_HOST'] || getDetectedLocalIp();
  const webdavHost = rawHost.startsWith('169.254.') ? '0.0.0.0' : rawHost;
  const webdavPort = map['WEBDAV_PORT'] || '8080';

  return { headers, webdavHost, webdavPort };
}

function writeStackEnv(
  headers: CustomHeaderItem[],
  webdavHost?: string,
  webdavPort?: string
) {
  const current = parseStackEnv();
  const finalHost = webdavHost !== undefined ? webdavHost : current.webdavHost;
  const finalPort = webdavPort !== undefined ? webdavPort : current.webdavPort;

  const serializedHeaders = headers
    .map((h) => `${h.header_name}:${h.header_value}|${h.enabled ? '1' : '0'}`)
    .join(';');

  const lines = [
    '# VaultDAV & Syncthing Container Environment (.env)',
    'PUID=1000',
    'PGID=1000',
    'TZ=UTC',
    `WEBDAV_HOST="${finalHost}"`,
    `WEBDAV_PORT=${finalPort}`,
    'SYNCTHING_GUI_PORT=8384',
    'SYNCTHING_SYNC_PORT=22000',
    '',
    '# SQLite Credential Store Encryption (SQLite is used ONLY for credentials)',
    `SQLITE_MASTER_KEY="${MASTER_SECRET}"`,
    'SQLITE_DB_PATH="/data/db/vaultdav.sqlite"',
    '',
    '# File Bridge Policy: Files bridged from WebDAV to Syncthing are UNENCRYPTED on disk',
    'ENCRYPT_BRIDGED_FILES=false',
    `WEBDAV_CUSTOM_HEADERS="${serializedHeaders}"`,
    '',
    '# Single Host Volumes Mount (All subfolders and files are configured inside this folder)',
    'HOST_VOLUMES_PATH="./host_volumes"',
    'CONTAINER_VOLUMES_PATH="/var/webdav"',
    '',
  ];

  const envContent = lines.join('\n');
  fs.writeFileSync(ENV_STACK_FILE, envContent, 'utf8');
  return envContent;
}

function readHostVolumesItems(): {
  slug: string;
  folder_name: string;
  host_path: string;
  container_path: string;
  exposed: boolean;
  syncthing_enabled: boolean;
  fileCount: number;
  totalBytes: number;
  files: string[];
}[] {
  fs.mkdirSync(HOST_VOLUMES_DIR, { recursive: true });
  const entries = fs.readdirSync(HOST_VOLUMES_DIR, { withFileTypes: true });

  const folders = entries
    .filter((e) => e.isDirectory() && !e.name.startsWith('.'))
    .map((e) => {
      const folderPath = path.join(HOST_VOLUMES_DIR, e.name);
      let fileCount = 0;
      let totalBytes = 0;
      const files: string[] = [];

      try {
        for (const f of fs.readdirSync(folderPath, { withFileTypes: true })) {
          if (f.name === '.stfolder') continue;
          if (f.isFile()) {
            fileCount++;
            files.push(f.name);
            try {
              totalBytes += fs.statSync(path.join(folderPath, f.name)).size;
            } catch {}
          } else if (f.isDirectory()) {
            files.push(`${f.name}/`);
          }
        }
      } catch {}

      return {
        slug: e.name.toUpperCase().replace(/[^A-Z0-9_]/g, '_'),
        folder_name: e.name,
        host_path: `./host_volumes/${e.name}`,
        container_path: `/var/webdav/${e.name}`,
        exposed: true,
        syncthing_enabled: true,
        fileCount,
        totalBytes,
        files,
      };
    });

  return folders;
}

// Syncthing config xml generator (ONE SINGLE FOLDER - NO NESTED SUBFOLDERS)
function buildSyncthingConfigXml(): string {
  const xml = `<configuration version="37">
    <folder id="host-volumes" label="Host Volumes (/var/webdav)" path="/var/webdav" type="sendreceive" rescanIntervalS="60" fsWatcherEnabled="true" fsWatcherDelayS="2" ignorePerms="false" autoNormalize="true">
        <filesystemType>basic</filesystemType>
        <minDiskFree unit="%">1</minDiskFree>
        <markerName>.stfolder</markerName>
    </folder>
    <gui enabled="true" tls="false" debugging="false" sendBasicAuthPrompt="false">
        <address>0.0.0.0:8384</address>
        <apikey>${SYNCTHING_API_KEY}</apikey>
        <theme>dark</theme>
        <insecureSkipHostcheck>true</insecureSkipHostcheck>
        <insecureAdminAccess>true</insecureAdminAccess>
    </gui>
    <options>
        <listenAddress>default</listenAddress>
        <globalAnnounceEnabled>true</globalAnnounceEnabled>
        <localAnnounceEnabled>true</localAnnounceEnabled>
        <relaysEnabled>true</relaysEnabled>
        <natEnabled>true</natEnabled>
        <startBrowser>false</startBrowser>
        <urAccepted>-1</urAccepted>
        <autoUpgradeIntervalH>0</autoUpgradeIntervalH>
        <crashReportingEnabled>false</crashReportingEnabled>
    </options>
</configuration>
`;
  try {
    fs.writeFileSync(SYNCTHING_CONFIG_FILE, xml, 'utf8');
  } catch {}
  return xml;
}

let syncthingProc: ChildProcess | null = null;
function startLocalSyncthingDaemon() {
  if (process.env.SYNCTHING_URL) return;
  if (!fs.existsSync(SYNCTHING_BIN)) return;

  try {
    fs.chmodSync(SYNCTHING_BIN, 0o755);
  } catch {}

  const localHome = RUNTIME_SYNCTHING_DIR;
  if (!fs.existsSync(path.join(localHome, 'cert.pem'))) {
    try {
      execSync(`${SYNCTHING_BIN} generate --home=${localHome}`);
    } catch {}
  }

  // Local config: path is HOST_VOLUMES_DIR
  const localXml = `<configuration version="37">
    <folder id="host-volumes" label="Host Volumes (${HOST_VOLUMES_DIR})" path="${HOST_VOLUMES_DIR}" type="sendreceive" rescanIntervalS="60" fsWatcherEnabled="true" fsWatcherDelayS="2" ignorePerms="false" autoNormalize="true">
        <filesystemType>basic</filesystemType>
        <minDiskFree unit="%">1</minDiskFree>
        <markerName>.stfolder</markerName>
    </folder>
    <gui enabled="true" tls="false" debugging="false" sendBasicAuthPrompt="false">
        <address>127.0.0.1:8384</address>
        <apikey>${SYNCTHING_API_KEY}</apikey>
        <theme>dark</theme>
        <insecureSkipHostcheck>true</insecureSkipHostcheck>
        <insecureAdminAccess>true</insecureAdminAccess>
    </gui>
    <options>
        <listenAddress>default</listenAddress>
        <globalAnnounceEnabled>false</globalAnnounceEnabled>
        <localAnnounceEnabled>true</localAnnounceEnabled>
        <relaysEnabled>false</relaysEnabled>
        <natEnabled>false</natEnabled>
        <startBrowser>false</startBrowser>
        <urAccepted>-1</urAccepted>
        <autoUpgradeIntervalH>0</autoUpgradeIntervalH>
        <crashReportingEnabled>false</crashReportingEnabled>
    </options>
</configuration>`;

  fs.writeFileSync(path.join(localHome, 'config.xml'), localXml, 'utf8');
  fs.mkdirSync(path.join(HOST_VOLUMES_DIR, '.stfolder'), { recursive: true });

  syncthingProc = spawn(
    SYNCTHING_BIN,
    [
      'serve',
      '--no-browser',
      '--no-upgrade',
      `--home=${localHome}`,
      '--gui-address=127.0.0.1:8384',
    ],
    {
      stdio: 'ignore',
      env: { ...process.env, STNOUPGRADE: '1' },
    }
  );
}

function generateStackArtifacts() {
  const { headers, webdavHost, webdavPort } = parseStackEnv();
  const envContent = writeStackEnv(headers, webdavHost, webdavPort);

  const composeContent = `# Docker Compose — VaultDAV + Syncthing Stack
# SQLite (/data/db/vaultdav.sqlite) is used strictly for encrypted credentials.
# Only ./host_volumes is exposed to both containers; all subfolders are configured inside ./host_volumes.

services:
  vaultdav:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: vaultdav-server
    restart: unless-stopped
    ports:
      - "\${WEBDAV_PORT:-8080}:3000"
    env_file:
      - .env
    environment:
      - ENCRYPT_BRIDGED_FILES=false
      - WEBDAV_HOST=\${WEBDAV_HOST:-0.0.0.0}
      - SQLITE_DB_PATH=/data/db/vaultdav.sqlite
      - HOST_VOLUMES_DIR=/var/webdav
      - SYNCTHING_URL=http://syncthing:8384
    volumes:
      - ./data/db:/data/db
      # Single exposed host_volumes folder
      - \${HOST_VOLUMES_PATH:-./host_volumes}:/var/webdav:rw
    networks:
      - vaultdav_net

  syncthing:
    image: lscr.io/linuxserver/syncthing:latest
    container_name: vaultdav-syncthing
    hostname: vaultdav-syncthing
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - PUID=\${PUID:-1000}
      - PGID=\${PGID:-1000}
      - TZ=\${TZ:-UTC}
    ports:
      - "\${SYNCTHING_GUI_PORT:-8384}:8384"
      - "\${SYNCTHING_SYNC_PORT:-22000}:22000/tcp"
      - "\${SYNCTHING_SYNC_PORT:-22000}:22000/udp"
      - "21027:21027/udp"
    volumes:
      - ./data/syncthing-config:/config
      # Single exposed host_volumes folder
      - \${HOST_VOLUMES_PATH:-./host_volumes}:/var/webdav:rw
    networks:
      - vaultdav_net

networks:
  vaultdav_net:
    driver: bridge
`;

  const dockerfileContent = `FROM node:22-alpine

# Install build dependencies for better-sqlite3 native addon
RUN apk add --no-cache python3 make g++ sqlite

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .
RUN npm run build

# Create persistent directories for SQLite database and single host_volumes mount
RUN mkdir -p /data/db /var/webdav

EXPOSE 3000

CMD ["npm", "run", "start"]
`;

  const syncthingXmlContent = buildSyncthingConfigXml();

  return { envContent, composeContent, dockerfileContent, syncthingXmlContent };
}

function addDirectoryToZip(zip: JSZip, fsDirPath: string, zipDirPath: string) {
  if (!fs.existsSync(fsDirPath)) return;
  for (const entry of fs.readdirSync(fsDirPath, { withFileTypes: true })) {
    if (entry.name === '.stfolder' || entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') continue;
    const fullFsPath = path.join(fsDirPath, entry.name);
    const fullZipPath = `${zipDirPath}/${entry.name}`;
    if (entry.isDirectory()) {
      addDirectoryToZip(zip, fullFsPath, fullZipPath);
    } else if (entry.isFile()) {
      zip.file(fullZipPath, fs.readFileSync(fullFsPath));
    }
  }
}

async function createDockerComposeZipBuffer(): Promise<Buffer> {
  const zip = new JSZip();
  const artifacts = generateStackArtifacts();
  const { webdavHost, webdavPort } = parseStackEnv();

  // Root stack orchestration files (prefer current files on disk to preserve any manual edits)
  const composePath = path.join(__dirname, 'docker-compose.yml');
  const envExamplePath = path.join(__dirname, '.env.example');
  const dockerfilePath = path.join(__dirname, 'Dockerfile');
  const syncthingConfigPath = path.join(SYNCTHING_CONFIG_DIR, 'config.xml');

  zip.file(
    'docker-compose.yml',
    fs.existsSync(composePath) ? fs.readFileSync(composePath, 'utf8') : artifacts.composeContent
  );
  zip.file('.env', artifacts.envContent);
  zip.file(
    '.env.example',
    fs.existsSync(envExamplePath) ? fs.readFileSync(envExamplePath, 'utf8') : artifacts.envContent
  );
  zip.file(
    'Dockerfile',
    fs.existsSync(dockerfilePath) ? fs.readFileSync(dockerfilePath, 'utf8') : artifacts.dockerfileContent
  );

  // App build files
  const rootFiles = ['package.json', 'tsconfig.json', 'vite.config.ts', 'index.html', 'server.ts', 'metadata.json'];
  for (const rf of rootFiles) {
    const rfPath = path.join(__dirname, rf);
    if (fs.existsSync(rfPath)) {
      zip.file(rf, fs.readFileSync(rfPath));
    }
  }

  // App source code directory
  addDirectoryToZip(zip, path.join(__dirname, 'src'), 'src');

  // Syncthing initial configuration (single unnested folder)
  zip.file(
    'data/syncthing-config/config.xml',
    fs.existsSync(syncthingConfigPath) ? fs.readFileSync(syncthingConfigPath, 'utf8') : artifacts.syncthingXmlContent
  );

  // Initial data/db directory placeholder
  zip.folder('data/db');
  zip.file('data/db/.gitkeep', '# SQLite credential database directory\n');

  // Include ./host_volumes
  addDirectoryToZip(zip, HOST_VOLUMES_DIR, 'host_volumes');

  const readme = `# VaultDAV + Syncthing Docker Compose Package

This archive contains the complete, ready-to-run Docker Compose stack for **VaultDAV** and **Syncthing**.

## How to Run

\`\`\`bash
# 1. Unzip the archive into a folder
unzip vaultdav-docker-compose.zip -d vaultdav-docker-compose
cd vaultdav-docker-compose

# 2. Build and start the stack in the background
docker compose up -d --build
\`\`\`

## Access Endpoints

- **VaultDAV & WebDAV**:
  - Web UI: http://localhost:${webdavPort} (or http://${webdavHost}:${webdavPort})
  - WebDAV Root Endpoint: http://localhost:${webdavPort}/dav/
- **Native Syncthing Web GUI**:
  - Web UI: http://localhost:8384
  - Synchronization Port: 22000 (TCP/UDP)

## Architecture

1. **Single \`./host_volumes\` Mount**:
   \`docker-compose.yml\` and \`.env\` only expose the single \`./host_volumes\` parent folder (\`/var/webdav\` inside both containers). All subfolders (\`documents\`, \`projects\`, \`media\`, \`photos\`, \`backups\`, etc.) live inside \`./host_volumes\`.
2. **SQLite Used Strictly for Encrypted Credentials**:
   Account passwords, optional TOTP secret, and auto-generated safe WebDAV passwords are stored in \`./data/db/vaultdav.sqlite\` encrypted with AES-256-GCM.
3. **Unified Username**:
   Your WebDAV username is identical to the login username set during account setup.
4. **Optional TOTP 2FA**:
   2FA can be enabled or disabled at any time from the Account & Security menu on the main dashboard.
`;
  zip.file('README.md', readme);

  const buffer = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });

  // Keep static vaultdav-docker-compose.zip file synced to the root filesystem
  try {
    fs.writeFileSync(path.join(__dirname, 'vaultdav-docker-compose.zip'), buffer);
  } catch {}

  return buffer;
}

function getMimeType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  const mimeMap: Record<string, string> = {
    '.txt': 'text/plain; charset=utf-8',
    '.md': 'text/markdown; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.xml': 'application/xml; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.ts': 'text/plain; charset=utf-8',
    '.tsx': 'text/plain; charset=utf-8',
    '.yml': 'text/yaml; charset=utf-8',
    '.yaml': 'text/yaml; charset=utf-8',
    '.csv': 'text/csv; charset=utf-8',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.mp4': 'video/mp4',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
  };
  return mimeMap[ext] || 'application/octet-stream';
}

function renderWebdavBrowserHtml(
  currentHref: string,
  parentHref: string | null,
  items: { name: string; href: string; isDir: boolean; size: number; mtime: string }[]
): string {
  const rows = items
    .map(
      (item) => `
      <tr>
        <td><a href="${item.href}">${item.isDir ? '📁 ' : '📄 '}${item.name}${item.isDir ? '/' : ''}</a></td>
        <td>${item.isDir ? 'Directory' : `${item.size} B`}</td>
        <td>${item.mtime}</td>
      </tr>`
    )
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>VaultDAV — ${currentHref}</title>
  <style>
    body { background: #050507; color: #f4f4f5; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; margin: 0; padding: 32px; }
    .container { max-width: 960px; margin: 0 auto; }
    .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #27272a; padding-bottom: 16px; margin-bottom: 24px; }
    h1 { font-size: 18px; margin: 0; color: #60a5fa; }
    .badge { background: #1e293b; color: #60a5fa; padding: 4px 10px; border-radius: 4px; font-size: 12px; border: 1px solid #3b82f6; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #18181b; }
    th { color: #a1a1aa; font-weight: 600; }
    a { color: #60a5fa; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .meta { margin-top: 24px; font-size: 12px; color: #71717a; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>VaultDAV Index of ${currentHref}</h1>
      <span class="badge">Host Volumes Root Mount</span>
    </div>
    <table>
      <thead>
        <tr><th>Name</th><th>Size</th><th>Last Modified</th></tr>
      </thead>
      <tbody>
        ${parentHref ? `<tr><td><a href="${parentHref}">⬆️ Parent Directory (..)</a></td><td>-</td><td>-</td></tr>` : ''}
        ${rows || '<tr><td colspan="3">Empty directory</td></tr>'}
      </tbody>
    </table>
    <div class="meta">Served by VaultDAV RFC 4918 WebDAV Server · Single ./host_volumes Mount · SQLite AES-256-GCM Auth</div>
  </div>
</body>
</html>`;
}

function requireAppAuth(req: Request, res: Response, next: NextFunction) {
  const token = String(req.headers['x-session-token'] || '');
  const session = token ? activeSessions.get(token) : undefined;
  if (!session) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }
  (req as any).sessionUser = session.username;
  next();
}

async function startServer() {
  startLocalSyncthingDaemon();

  const app = express();

  // 1. Syncthing Reverse Proxy
  app.use(
    '/syncthing',
    createProxyMiddleware({
      target: SYNCTHING_TARGET_URL,
      changeOrigin: true,
      on: {
        proxyReq: (proxyReq) => {
          proxyReq.setHeader('X-API-Key', SYNCTHING_API_KEY);
        },
        proxyRes: (proxyRes) => {
          delete proxyRes.headers['x-frame-options'];
          delete proxyRes.headers['content-security-policy'];
        },
      },
    })
  );

  // 2. Public Docker Compose ZIP download endpoints
  const handleZipDownload = async (_req: Request, res: Response) => {
    try {
      const zipBuffer = await createDockerComposeZipBuffer();
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="vaultdav-docker-compose.zip"');
      res.setHeader('Content-Length', String(zipBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).end(zipBuffer);
    } catch (err: any) {
      console.error('Failed to generate zip:', err);
      res.status(500).json({ error: 'Failed to create docker zip package: ' + err.message });
    }
  };
  app.get('/api/docker/download-zip', handleZipDownload);
  app.get('/vaultdav-docker-compose.zip', handleZipDownload);

  // Raw binary body parser for WebDAV (/dav)
  app.use('/dav', express.raw({ type: '*/*', limit: '500mb' }));

  app.use(express.json({ limit: '25mb' }));
  app.use(express.text({ type: ['text/*', 'application/xml', 'application/yaml'], limit: '25mb' }));

  // ============================================================================
  // 3. Single-Account SQLite Auth Endpoints (/api/auth/*)
  // ============================================================================
  app.get('/api/auth/status', async (req: Request, res: Response) => {
    const account = db.prepare('SELECT username, totp_enabled, totp_ciphertext_hex FROM credentials WHERE id = 1').get() as any;
    const token = String(req.headers['x-session-token'] || '');
    const session = token ? activeSessions.get(token) : undefined;
    const isTotpEnabled = Boolean(account && account.totp_enabled && account.totp_ciphertext_hex);

    res.json({
      hasAccount: Boolean(account),
      authenticated: Boolean(session && account && session.username === account.username),
      username: session?.username || null,
      totpEnabled: isTotpEnabled,
    });
  });

  app.post('/api/auth/setup', (req: Request, res: Response) => {
    const existing = db.prepare('SELECT id FROM credentials WHERE id = 1').get();
    if (existing) {
      res.status(403).json({ error: 'An account already exists in SQLite. Only one account creation is allowed.' });
      return;
    }

    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!username || !password) {
      res.status(400).json({ error: 'Username and password are required' });
      return;
    }

    const encPass = encryptSecret(password);
    const webdavSafePassword = generateSafeWebdavPassword(24);
    const encWebdav = encryptSecret(webdavSafePassword);
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO credentials (
        id, username,
        ciphertext_hex, iv_hex, auth_tag_hex,
        totp_ciphertext_hex, totp_iv_hex, totp_auth_tag_hex, totp_enabled,
        webdav_ciphertext_hex, webdav_iv_hex, webdav_auth_tag_hex,
        created_at, last_used_at
      )
      VALUES (1, ?, ?, ?, ?, '', '', '', 0, ?, ?, ?, ?, ?)
    `).run(
      username,
      encPass.ciphertextHex,
      encPass.ivHex,
      encPass.authTagHex,
      encWebdav.ciphertextHex,
      encWebdav.ivHex,
      encWebdav.authTagHex,
      now,
      now
    );

    const token = crypto.randomBytes(24).toString('hex');
    activeSessions.set(token, { username, createdAt: Date.now() });

    res.status(201).json({ ok: true, token, username });
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');
    const totpCode = String(req.body.totpCode || '').trim();

    const check = verifyMainAppCredentials(username, password, totpCode);
    if (!check.ok) {
      res.status(401).json({ error: check.error || 'Invalid credentials' });
      return;
    }

    const token = crypto.randomBytes(24).toString('hex');
    activeSessions.set(token, { username, createdAt: Date.now() });

    res.json({ ok: true, token, username });
  });

  app.post('/api/auth/logout', (req: Request, res: Response) => {
    const token = String(req.headers['x-session-token'] || '');
    if (token) activeSessions.delete(token);
    res.json({ ok: true });
  });

  // ============================================================================
  // 4. RFC 4918 WebDAV Server (/dav and /dav/*)
  // Direct access to ./host_volumes root and all subfolders/files
  // ============================================================================
  const applyWebdavHeadersAndAuth = (req: Request, res: Response) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Depth, Overwrite, Destination, Content-Type, X-Requested-With, *');
    res.setHeader('Access-Control-Expose-Headers', 'DAV, Allow, X-Received-Custom-Headers');

    const { headers } = parseStackEnv();
    for (const h of headers.filter((x) => x.enabled)) {
      try {
        res.setHeader(h.header_name, h.header_value);
      } catch {}
    }

    if (req.method.toUpperCase() === 'OPTIONS') {
      res.setHeader('DAV', '1, 2');
      res.setHeader('Allow', 'OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY');
      res.status(200).end();
      return { handled: true };
    }

    const auth = verifyWebdavBasicAuth(req.headers.authorization);
    if (!auth.ok) {
      res.setHeader('WWW-Authenticate', 'Basic realm="VaultDAV Server"');
      res.status(401).send(auth.error || 'Unauthorized: WebDAV username (same as login) and safe password required');
      return { handled: true };
    }

    return { handled: false };
  };

  // Helper to map /dav request path to filesystem inside HOST_VOLUMES_DIR
  function resolveWebdavPath(reqUrl: string): { fsPath: string; relPath: string; isRoot: boolean } | null {
    const rawPath = reqUrl.split('?')[0];
    const stripped = rawPath.replace(/^\/dav\/?/, '');
    const decoded = decodeURIComponent(stripped);
    const normalized = path.normalize(decoded).replace(/^(\.\.(\/|\\|$))+/, '').replace(/^\/+/, '');
    const fsPath = path.resolve(HOST_VOLUMES_DIR, normalized);
    if (!fsPath.startsWith(HOST_VOLUMES_DIR)) {
      return null;
    }
    return {
      fsPath,
      relPath: normalized,
      isRoot: fsPath === HOST_VOLUMES_DIR,
    };
  }

  app.all(['/dav', '/dav/*'], (req: Request, res: Response) => {
    const { handled } = applyWebdavHeadersAndAuth(req, res);
    if (handled) return;

    const resolved = resolveWebdavPath(req.originalUrl || req.url);
    if (!resolved) {
      res.status(403).send('Forbidden path');
      return;
    }

    const { fsPath, relPath, isRoot } = resolved;
    const method = req.method.toUpperCase();

    // PROPFIND
    if (method === 'PROPFIND') {
      if (!fs.existsSync(fsPath)) {
        res.status(404).send('Not Found');
        return;
      }
      const stat = fs.statSync(fsPath);
      const isDir = stat.isDirectory();
      const responsesXml: string[] = [];

      const escapeXml = (str: string) =>
        str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

      const cleanRel = relPath ? relPath.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '') : '';
      const baseHref = isRoot ? '/dav/' : `/dav/${cleanRel}${isDir ? '/' : ''}`;

      responsesXml.push(`  <D:response>
    <D:href>${baseHref}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${escapeXml(isRoot ? 'dav' : path.basename(fsPath))}</D:displayname>
        <D:getlastmodified>${stat.mtime.toUTCString()}</D:getlastmodified>
        <D:getcontentlength>${isDir ? 0 : stat.size}</D:getcontentlength>
        <D:resourcetype>${isDir ? '<D:collection/>' : ''}</D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`);

      if (isDir && req.headers.depth !== '0') {
        try {
          const children = fs.readdirSync(fsPath).filter((c) => c !== '.stfolder');
          for (const child of children) {
            try {
              const childPath = path.join(fsPath, child);
              const childStat = fs.statSync(childPath);
              const childIsDir = childStat.isDirectory();
              const childHref = `${baseHref}${encodeURIComponent(child)}${childIsDir ? '/' : ''}`;
              responsesXml.push(`  <D:response>
    <D:href>${childHref}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${escapeXml(child)}</D:displayname>
        <D:getlastmodified>${childStat.mtime.toUTCString()}</D:getlastmodified>
        <D:getcontentlength>${childIsDir ? 0 : childStat.size}</D:getcontentlength>
        <D:resourcetype>${childIsDir ? '<D:collection/>' : ''}</D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`);
            } catch {}
          }
        } catch {}
      }

      const xml = `<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">\n${responsesXml.join('\n')}\n</D:multistatus>`;
      res.setHeader('Content-Type', 'application/xml; charset=utf-8');
      res.status(207).send(xml);
      return;
    }

    // GET / HEAD
    if (method === 'GET' || method === 'HEAD') {
      if (!fs.existsSync(fsPath)) {
        res.status(404).send('Not Found');
        return;
      }
      const stat = fs.statSync(fsPath);
      if (stat.isDirectory()) {
        const cleanRel = relPath ? relPath.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '') : '';
        const currentHref = isRoot ? '/dav/' : `/dav/${cleanRel}/`;
        let parentHref: string | null = null;
        if (!isRoot) {
          const parts = cleanRel.split('/');
          parts.pop();
          parentHref = parts.length > 0 ? `/dav/${parts.join('/')}/` : '/dav/';
        }

        const items = fs
          .readdirSync(fsPath)
          .filter((c) => c !== '.stfolder')
          .map((child) => {
            const cStat = fs.statSync(path.join(fsPath, child));
            return {
              name: child,
              href: `${currentHref}${encodeURIComponent(child)}${cStat.isDirectory() ? '/' : ''}`,
              isDir: cStat.isDirectory(),
              size: cStat.isDirectory() ? 0 : cStat.size,
              mtime: cStat.mtime.toUTCString(),
            };
          });

        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.status(200).send(renderWebdavBrowserHtml(currentHref, parentHref, items));
        return;
      }

      // Binary-safe file serving
      res.setHeader('Content-Type', getMimeType(fsPath));
      res.setHeader('Content-Length', String(stat.size));
      res.setHeader('Last-Modified', stat.mtime.toUTCString());
      if (method === 'HEAD') {
        res.status(200).end();
      } else {
        const stream = fs.createReadStream(fsPath);
        stream.pipe(res);
      }
      return;
    }

    // PUT
    if (method === 'PUT') {
      if (isRoot) {
        res.status(405).send('Cannot overwrite root collection');
        return;
      }
      fs.mkdirSync(path.dirname(fsPath), { recursive: true });

      if (Buffer.isBuffer(req.body)) {
        fs.writeFileSync(fsPath, req.body);
        res.status(201).send('Created');
      } else if (typeof req.body === 'string') {
        fs.writeFileSync(fsPath, req.body, 'utf8');
        res.status(201).send('Created');
      } else if (req.body && typeof req.body === 'object' && !('pipe' in req.body)) {
        fs.writeFileSync(fsPath, JSON.stringify(req.body, null, 2), 'utf8');
        res.status(201).send('Created');
      } else if (typeof (req as any).pipe === 'function' && !req.readableEnded) {
        // Stream writing when body parser has not consumed req
        const out = fs.createWriteStream(fsPath);
        req.pipe(out);
        out.on('finish', () => {
          res.status(201).send('Created');
        });
        out.on('error', (err) => {
          res.status(500).send('Write error: ' + err.message);
        });
      } else {
        // Fallback: create empty file if body was empty
        fs.writeFileSync(fsPath, Buffer.alloc(0));
        res.status(201).send('Created');
      }
      return;
    }

    // MKCOL
    if (method === 'MKCOL') {
      if (fs.existsSync(fsPath)) {
        res.status(405).send('Collection already exists');
        return;
      }
      fs.mkdirSync(fsPath, { recursive: true });
      res.status(201).send('Created');
      return;
    }

    // DELETE
    if (method === 'DELETE') {
      if (isRoot) {
        res.status(403).send('Cannot delete root collection');
        return;
      }
      if (!fs.existsSync(fsPath)) {
        res.status(404).send('Not Found');
        return;
      }
      fs.rmSync(fsPath, { recursive: true, force: true });
      res.status(204).end();
      return;
    }

    res.status(405).send('Method Not Allowed');
  });

  // ============================================================================
  // 5. Authenticated App API Routes (/api/*)
  // ============================================================================
  app.use('/api', requireAppAuth);

  app.get('/api/state', (req: Request, res: Response) => {
    const account = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
    const sqliteTables = (
      db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all() as {
        name: string;
      }[]
    ).map((t) => t.name);

    let decryptedWebdavPassword = '';
    if (account && account.webdav_ciphertext_hex) {
      try {
        decryptedWebdavPassword = decryptSecret(
          account.webdav_ciphertext_hex,
          account.webdav_iv_hex,
          account.webdav_auth_tag_hex
        );
      } catch {}
    }

    const folders = readHostVolumesItems();
    const { headers, webdavHost, webdavPort } = parseStackEnv();
    const artifacts = generateStackArtifacts();
    const detectedIp = getDetectedLocalIp();
    const detectedHost = String(req.headers.host || `${detectedIp}:3000`);

    res.json({
      account,
      webdavCredentials: {
        username: account?.username || '',
        password: decryptedWebdavPassword,
        ciphertext_hex: account?.webdav_ciphertext_hex || '',
        iv_hex: account?.webdav_iv_hex || '',
        auth_tag_hex: account?.webdav_auth_tag_hex || '',
      },
      webdavHostConfig: {
        domainOrIp: webdavHost,
        port: webdavPort,
        detectedIp,
        detectedHost,
      },
      sqliteTables,
      folders,
      customHeaders: headers,
      webdavUrl: '/dav/',
      syncthingUrl: '/syncthing/',
      artifacts,
    });
  });

  app.post('/api/account/2fa/prepare', async (_req: Request, res: Response) => {
    const account = db.prepare('SELECT username FROM credentials WHERE id = 1').get() as any;
    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }
    const secret = generateBase32Secret(20);
    const otpauthUri = `otpauth://totp/VaultDAV:${account.username}?secret=${secret}&issuer=VaultDAV&algorithm=SHA1&digits=6&period=30`;
    let qrSvg = '';
    try {
      qrSvg = await QRCode.toString(otpauthUri, {
        type: 'svg',
        margin: 1,
        color: { dark: '#f4f4f5', light: '#050507' },
      });
    } catch {}

    res.json({ secret, qrSvg });
  });

  app.post('/api/account/2fa/activate', (req: Request, res: Response) => {
    const secret = String(req.body.secret || '').trim();
    const code = String(req.body.code || '').trim();
    if (!secret || !code) {
      res.status(400).json({ error: 'Secret and 6-digit confirmation code are required' });
      return;
    }

    if (!verifyTotpCode(secret, code)) {
      res.status(400).json({ error: 'Invalid 6-digit code. Please check your authenticator app.' });
      return;
    }

    const encTotp = encryptSecret(secret);
    db.prepare(`
      UPDATE credentials
      SET totp_ciphertext_hex = ?, totp_iv_hex = ?, totp_auth_tag_hex = ?, totp_enabled = 1
      WHERE id = 1
    `).run(encTotp.ciphertextHex, encTotp.ivHex, encTotp.authTagHex);

    res.json({ ok: true, message: 'TOTP 2FA successfully activated on your account' });
  });

  app.post('/api/account/2fa/disable', (req: Request, res: Response) => {
    const password = String(req.body.password || '');
    if (!password) {
      res.status(400).json({ error: 'Account password is required to disable 2FA' });
      return;
    }

    const account = db.prepare('SELECT ciphertext_hex, iv_hex, auth_tag_hex FROM credentials WHERE id = 1').get() as any;
    if (!account) {
      res.status(404).json({ error: 'Account not found' });
      return;
    }

    try {
      const decryptedPassword = decryptSecret(account.ciphertext_hex, account.iv_hex, account.auth_tag_hex);
      const passBuf = Buffer.from(password, 'utf8');
      const decBuf = Buffer.from(decryptedPassword, 'utf8');
      if (passBuf.length !== decBuf.length || !crypto.timingSafeEqual(passBuf, decBuf)) {
        res.status(401).json({ error: 'Incorrect account password' });
        return;
      }

      db.prepare(`
        UPDATE credentials
        SET totp_ciphertext_hex = '', totp_iv_hex = '', totp_auth_tag_hex = '', totp_enabled = 0
        WHERE id = 1
      `).run();

      res.json({ ok: true, message: 'TOTP 2FA has been disabled' });
    } catch {
      res.status(500).json({ error: 'Failed to verify account password' });
    }
  });

  app.post('/api/webdav-credentials/regenerate', (_req: Request, res: Response) => {
    const account = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
    if (!account) {
      res.status(404).json({ error: 'Account not found in SQLite' });
      return;
    }

    const nextSafePassword = generateSafeWebdavPassword(24);
    const encDav = encryptSecret(nextSafePassword);

    db.prepare(`
      UPDATE credentials
      SET webdav_ciphertext_hex = ?, webdav_iv_hex = ?, webdav_auth_tag_hex = ?
      WHERE id = 1
    `).run(encDav.ciphertextHex, encDav.ivHex, encDav.authTagHex);

    res.json({
      ok: true,
      webdavCredentials: {
        username: account.username,
        password: nextSafePassword,
        ciphertext_hex: encDav.ciphertextHex,
        iv_hex: encDav.ivHex,
        auth_tag_hex: encDav.authTagHex,
      },
    });
  });

  app.put('/api/webdav-host', async (req: Request, res: Response) => {
    const domainOrIp = String(req.body?.domainOrIp || '').trim() || getDetectedLocalIp();
    const port = String(req.body?.port || '8080').trim() || '8080';
    const { headers } = parseStackEnv();
    writeStackEnv(headers, domainOrIp, port);
    res.json({ ok: true, domainOrIp, port });
  });

  // Host folder operations inside ./host_volumes
  app.post('/api/folders', (req: Request, res: Response) => {
    const rawName = String(req.body.name || req.body.slug || '').trim();
    const cleanName = path.basename(rawName).replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!cleanName) {
      res.status(400).json({ error: 'Folder name required' });
      return;
    }
    const targetDir = path.join(HOST_VOLUMES_DIR, cleanName);
    fs.mkdirSync(targetDir, { recursive: true });
    res.status(201).json({ ok: true, name: cleanName });
  });

  app.delete('/api/folders/:name', (req: Request, res: Response) => {
    const name = path.basename(String(req.params.name || '').trim());
    if (!name) {
      res.status(400).json({ error: 'Folder name required' });
      return;
    }
    const targetDir = path.join(HOST_VOLUMES_DIR, name);
    if (fs.existsSync(targetDir)) {
      fs.rmSync(targetDir, { recursive: true, force: true });
    }
    res.json({ ok: true });
  });

  app.post('/api/headers', (req: Request, res: Response) => {
    const headerName = String(req.body.header_name || '').trim();
    const headerValue = String(req.body.header_value || '').trim();
    if (!headerName || !headerValue) {
      res.status(400).json({ error: 'Header name and value required' });
      return;
    }
    const { headers } = parseStackEnv();
    headers.push({ header_name: headerName, header_value: headerValue, enabled: true });
    writeStackEnv(headers);
    res.status(201).json({ ok: true });
  });

  app.put('/api/headers/:index', (req: Request, res: Response) => {
    const idx = Number(req.params.index);
    const { headers } = parseStackEnv();
    if (headers[idx]) {
      headers[idx].enabled = Boolean(req.body.enabled);
      writeStackEnv(headers);
    }
    res.json({ ok: true });
  });

  app.delete('/api/headers/:index', (req: Request, res: Response) => {
    const idx = Number(req.params.index);
    const { headers } = parseStackEnv();
    headers.splice(idx, 1);
    writeStackEnv(headers);
    res.json({ ok: true });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      plugins: [
        {
          name: 'disable-vite8-hmr-websocket-throw',
          transform(code, id) {
            if (id.includes('vite/dist/client/client.mjs')) {
              return {
                code: code
                  .replace('transport.connect(createHMRHandler(handleMessage));', '')
                  .replace('throw e;', 'return;'),
                map: null,
              };
            }
          },
        },
      ],
      server: {
        middlewareMode: true,
        hmr: false,
        watch: null,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`VaultDAV Server + Native Syncthing Proxy listening on http://0.0.0.0:${PORT}`);
    // Pre-generate static zip archive for instant docker-compose download
    createDockerComposeZipBuffer().catch((err) => {
      console.warn('Initial docker-compose.zip generation error:', err);
    });
  });
}

startServer();
