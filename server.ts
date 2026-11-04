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

const DATA_DIR = path.join(__dirname, 'data', 'db');
const SYNCTHING_HOME_DIR = path.join(__dirname, 'data', 'syncthing-home');
const SYNCTHING_BIN = path.join(__dirname, 'bin', 'syncthing');
const HOST_VOLUMES_DIR = path.join(__dirname, 'host_volumes');
const ENV_STACK_FILE = path.join(__dirname, 'data', '.env.stack');
const STATIC_ZIP_FILE = path.join(__dirname, 'vaultdav-docker-compose.zip');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(SYNCTHING_HOME_DIR, { recursive: true });
fs.mkdirSync(HOST_VOLUMES_DIR, { recursive: true });

// ============================================================================
// 1. SQLITE DATABASE: STRICTLY & EXCLUSIVELY FOR ENCRYPTED CREDENTIALS
// ============================================================================
const DB_PATH = path.join(DATA_DIR, 'vaultdav.sqlite');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

const MASTER_SECRET = process.env.SQLITE_MASTER_KEY || 'vaultdav-aes256-gcm-master-secret-key-2026';
const KDF_SALT = 'vaultdav-sqlite-kdf-salt-v1';
const SYNCTHING_API_KEY = 'vaultdav-syncthing-local-api-key';

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

// Cryptographically safe password generator for WebDAV (alphanumeric + safe symbols, no colon ':')
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

// Ensure credentials table exists in SQLite
const existingCols = db.prepare("PRAGMA table_info(credentials)").all() as { name: string }[];
if (existingCols.length > 0 && !existingCols.some((c) => c.name === 'totp_ciphertext_hex')) {
  db.exec('DROP TABLE IF EXISTS credentials;');
}

db.exec(`
  DROP TABLE IF EXISTS exposed_folders;
  DROP TABLE IF EXISTS webdav_custom_headers;
  DROP TABLE IF EXISTS syncthing_devices;
  DROP TABLE IF EXISTS syncthing_block_events;
  DROP TABLE IF EXISTS webdav_audit_logs;
  DROP TABLE IF EXISTS stack_settings;
  DROP TABLE IF EXISTS webdav_credentials;

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
    kdf_spec TEXT NOT NULL DEFAULT 'PBKDF2-SHA256 (100k) -> AES-256-GCM + TOTP',
    created_at TEXT NOT NULL,
    last_used_at TEXT
  );
`);

// Add columns if migrating an older database
const currentCols = db.prepare("PRAGMA table_info(credentials)").all() as { name: string }[];
if (!currentCols.some((c) => c.name === 'totp_enabled')) {
  db.exec(`
    ALTER TABLE credentials ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
  `);
}
if (!currentCols.some((c) => c.name === 'webdav_ciphertext_hex')) {
  db.exec(`
    ALTER TABLE credentials ADD COLUMN webdav_ciphertext_hex TEXT NOT NULL DEFAULT '';
    ALTER TABLE credentials ADD COLUMN webdav_iv_hex TEXT NOT NULL DEFAULT '';
    ALTER TABLE credentials ADD COLUMN webdav_auth_tag_hex TEXT NOT NULL DEFAULT '';
  `);
}

// Auto-populate initial safe WebDAV password into SQLite if missing
const existingAccountRow = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
if (existingAccountRow && !existingAccountRow.webdav_ciphertext_hex) {
  const autoDavPass = generateSafeWebdavPassword(24);
  const encDav = encryptSecret(autoDavPass);
  db.prepare(`
    UPDATE credentials
    SET webdav_ciphertext_hex = ?, webdav_iv_hex = ?, webdav_auth_tag_hex = ?
    WHERE id = 1
  `).run(encDav.ciphertextHex, encDav.ivHex, encDav.authTagHex);
}

function generateBase32Secret(byteLength = 20): string {
  const buf = crypto.randomBytes(byteLength);
  let bits = 0;
  let value = 0;
  let output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function decodeBase32(base32: string): Buffer {
  const clean = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpAtCounter(base32Secret: string, counter: number): string {
  const key = decodeBase32(base32Secret);
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
    1000000;
  return String(code).padStart(6, '0');
}

function verifyTotpCode(base32Secret: string, token: string, windowSteps = 1): boolean {
  const cleanToken = String(token || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleanToken)) return false;
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  for (let w = -windowSteps; w <= windowSteps; w++) {
    if (generateTotpAtCounter(base32Secret, currentCounter + w) === cleanToken) {
      return true;
    }
  }
  return false;
}

function verifyMainAppCredentials(
  username: string,
  password: string,
  totpCode?: string
): { ok: boolean; account?: any; error?: string } {
  const row = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
  if (!row) {
    return { ok: false, error: 'No account exists in SQLite yet. Create the single account first.' };
  }
  if (row.username !== username) {
    return { ok: false, error: 'Invalid username or password' };
  }
  try {
    const decryptedPassword = decryptSecret(row.ciphertext_hex, row.iv_hex, row.auth_tag_hex);
    const passBuf = Buffer.from(password, 'utf8');
    const decBuf = Buffer.from(decryptedPassword, 'utf8');
    if (passBuf.length !== decBuf.length || !crypto.timingSafeEqual(passBuf, decBuf)) {
      return { ok: false, error: 'Invalid username or password' };
    }

    // Check if TOTP 2FA is enabled for this account
    const isTotpEnabled = Boolean(row.totp_enabled && row.totp_ciphertext_hex && row.totp_ciphertext_hex.trim() !== '');
    if (isTotpEnabled) {
      if (!totpCode || !totpCode.trim()) {
        return { ok: false, error: '6-digit TOTP 2FA code is required for this account' };
      }
      const decryptedTotpSecret = decryptSecret(
        row.totp_ciphertext_hex,
        row.totp_iv_hex,
        row.totp_auth_tag_hex
      );
      if (!verifyTotpCode(decryptedTotpSecret, String(totpCode || ''))) {
        return { ok: false, error: 'Invalid 6-digit TOTP 2FA code' };
      }
    }

    db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = 1').run(new Date().toISOString());
    return { ok: true, account: row };
  } catch {
    return { ok: false, error: 'Failed to decrypt SQLite credential' };
  }
}

// WebDAV Basic Auth: The username MUST be the SAME username used for login!
// Password is the auto-generated safe password (or login password) stored encrypted in SQLite.
function verifyWebdavBasicAuth(
  authHeader: string | undefined
): { ok: boolean; username: string; error?: string } {
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { ok: false, username: 'anonymous', error: 'WebDAV username and safe password required' };
  }
  const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8');
  const colonIdx = decoded.indexOf(':');
  if (colonIdx === -1) {
    return { ok: false, username: 'invalid', error: 'Malformed Basic Auth header' };
  }
  const username = decoded.slice(0, colonIdx);
  const password = decoded.slice(colonIdx + 1);

  const row = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
  if (!row) {
    return { ok: false, username, error: 'No account configured in SQLite yet' };
  }

  // 1. Username MUST match the login username
  if (username !== row.username) {
    return { ok: false, username, error: `Invalid WebDAV username. Must match login username (${row.username})` };
  }

  try {
    const passBuf = Buffer.from(password, 'utf8');

    // 2. Check the safe auto-generated password stored encrypted in SQLite
    if (row.webdav_ciphertext_hex) {
      const decryptedDavPass = decryptSecret(
        row.webdav_ciphertext_hex,
        row.webdav_iv_hex,
        row.webdav_auth_tag_hex
      );
      const decDavBuf = Buffer.from(decryptedDavPass, 'utf8');
      if (passBuf.length === decDavBuf.length && crypto.timingSafeEqual(passBuf, decDavBuf)) {
        db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = 1').run(new Date().toISOString());
        return { ok: true, username: row.username };
      }
    }

    // 3. Fallback: also accept the main login password stored in SQLite
    const decryptedMainPass = decryptSecret(row.ciphertext_hex, row.iv_hex, row.auth_tag_hex);
    const decMainBuf = Buffer.from(decryptedMainPass, 'utf8');
    if (passBuf.length === decMainBuf.length && crypto.timingSafeEqual(passBuf, decMainBuf)) {
      db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = 1').run(new Date().toISOString());
      return { ok: true, username: row.username };
    }

    return { ok: false, username, error: 'Invalid WebDAV password' };
  } catch {
    return { ok: false, username, error: 'Failed to verify SQLite credentials' };
  }
}

function getDetectedLocalIp(): string {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name] || []) {
      if (net.family === 'IPv4' && !net.internal) {
        return net.address;
      }
    }
  }
  return '127.0.0.1';
}

// ============================================================================
// 2. .ENV & HOST FILESYSTEM ENGINE (Folders & Unencrypted Files)
// ============================================================================
interface FolderConfigItem {
  slug: string;
  exposed: boolean;
  syncthing_enabled: boolean;
  host_path: string;
  container_path: string;
}

interface CustomHeaderItem {
  header_name: string;
  header_value: string;
  enabled: boolean;
}

function resolveFolderAbsPath(folder: FolderConfigItem): string {
  const hp = (folder.host_path || `./host_volumes/${folder.slug.toLowerCase()}`).trim();
  const resolved = path.isAbsolute(hp) ? path.normalize(hp) : path.resolve(__dirname, hp);
  if (!resolved.startsWith(__dirname)) {
    return path.join(HOST_VOLUMES_DIR, folder.slug.toLowerCase());
  }
  return resolved;
}

function toRelativeHostPath(absPath: string): string {
  const rel = path.relative(__dirname, absPath).replace(/\\/g, '/');
  if (!rel || rel === '') return '.';
  return rel.startsWith('.') ? rel : `./${rel}`;
}

function ensureInitialEnvFile() {
  const sampleDirs = ['documents', 'projects', 'media', 'backups', 'photos', 'shared_notes'];
  for (const dir of sampleDirs) {
    const abs = path.join(HOST_VOLUMES_DIR, dir);
    fs.mkdirSync(abs, { recursive: true });
    const existing = fs.readdirSync(abs).filter((n) => n !== '.stfolder');
    if (existing.length === 0) {
      fs.writeFileSync(
        path.join(abs, `${dir}-info.txt`),
        `Unencrypted file in host folder ./host_volumes/${dir}\nBridged directly between WebDAV and native Syncthing.\n`,
        'utf8'
      );
    }
  }

  if (!fs.existsSync(ENV_STACK_FILE)) {
    const detectedIp = getDetectedLocalIp();
    const defaultEnv = [
      '# VaultDAV & Syncthing Container Environment (.env)',
      'PUID=1000',
      'PGID=1000',
      'TZ=UTC',
      `WEBDAV_HOST="${detectedIp}"`,
      'WEBDAV_PORT=8080',
      'SYNCTHING_GUI_PORT=8384',
      'SYNCTHING_SYNC_PORT=22000',
      `SQLITE_MASTER_KEY="${MASTER_SECRET}"`,
      'SQLITE_DB_PATH="/data/db/vaultdav.sqlite"',
      'ENCRYPT_BRIDGED_FILES=false',
      'WEBDAV_CUSTOM_HEADERS=""',
      '',
      '# Host Folders Exposed to Containers (Controlled directly via .env)',
      'EXPOSE_FOLDER_DOCUMENTS=true',
      'SYNCTHING_FOLDER_DOCUMENTS=true',
      'HOST_PATH_DOCUMENTS="./host_volumes/documents"',
      'CONTAINER_PATH_DOCUMENTS="/var/webdav/documents"',
      '',
      'EXPOSE_FOLDER_PROJECTS=true',
      'SYNCTHING_FOLDER_PROJECTS=true',
      'HOST_PATH_PROJECTS="./host_volumes/projects"',
      'CONTAINER_PATH_PROJECTS="/var/webdav/projects"',
      '',
      'EXPOSE_FOLDER_MEDIA=true',
      'SYNCTHING_FOLDER_MEDIA=true',
      'HOST_PATH_MEDIA="./host_volumes/media"',
      'CONTAINER_PATH_MEDIA="/var/webdav/media"',
    ].join('\n');
    fs.writeFileSync(ENV_STACK_FILE, defaultEnv, 'utf8');
  }
}
ensureInitialEnvFile();

function parseStackEnv(): {
  folders: FolderConfigItem[];
  headers: CustomHeaderItem[];
  webdavHost: string;
  webdavPort: string;
} {
  ensureInitialEnvFile();
  const raw = fs.readFileSync(ENV_STACK_FILE, 'utf8');
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

  const slugs = new Set<string>();
  for (const key of Object.keys(map)) {
    if (key.startsWith('EXPOSE_FOLDER_')) {
      slugs.add(key.replace('EXPOSE_FOLDER_', ''));
    }
  }

  const folders: FolderConfigItem[] = Array.from(slugs).map((slug) => ({
    slug,
    exposed: map[`EXPOSE_FOLDER_${slug}`] === 'true',
    syncthing_enabled: map[`SYNCTHING_FOLDER_${slug}`] !== 'false',
    host_path: map[`HOST_PATH_${slug}`] || `./host_volumes/${slug.toLowerCase()}`,
    container_path: map[`CONTAINER_PATH_${slug}`] || `/var/webdav/${slug.toLowerCase()}`,
  }));

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
        if (
          (hName === 'X-VaultDAV-Node' && hVal === 'vaultdav-sqlite-aes256gcm') ||
          (hName === 'X-Content-Type-Options' && hVal === 'nosniff')
        ) {
          continue;
        }
        headers.push({
          header_name: hName,
          header_value: hVal,
          enabled: flag !== '0',
        });
      }
    }
  }

  const webdavHost = map['WEBDAV_HOST'] || getDetectedLocalIp();
  const webdavPort = map['WEBDAV_PORT'] || '8080';

  return { folders, headers, webdavHost, webdavPort };
}

function writeStackEnv(
  folders: FolderConfigItem[],
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

  const lines: string[] = [
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
    '# Host Folders Exposed to Containers (Read directly from .env & filesystem)',
  ];

  for (const f of folders) {
    lines.push(`EXPOSE_FOLDER_${f.slug}=${f.exposed ? 'true' : 'false'}`);
    lines.push(`SYNCTHING_FOLDER_${f.slug}=${f.syncthing_enabled ? 'true' : 'false'}`);
    lines.push(`HOST_PATH_${f.slug}="${f.host_path}"`);
    lines.push(`CONTAINER_PATH_${f.slug}="${f.container_path}"`);
    lines.push('');
  }

  const envContent = lines.join('\n');
  fs.writeFileSync(ENV_STACK_FILE, envContent, 'utf8');
  return envContent;
}

function ensureFilesystemFolders() {
  const { folders } = parseStackEnv();
  for (const f of folders) {
    const absDir = resolveFolderAbsPath(f);
    fs.mkdirSync(path.join(absDir, '.stfolder'), { recursive: true });
    const existing = fs.readdirSync(absDir).filter((name) => name !== '.stfolder');
    if (existing.length === 0) {
      fs.writeFileSync(
        path.join(absDir, `${f.slug.toLowerCase()}-readme.md`),
        `# ${f.slug} Shared Volume\n\n- Host Path: \`${f.host_path}\`\n- Exposed via \`EXPOSE_FOLDER_${f.slug}=${f.exposed}\` in \`.env\`\n- Stored unencrypted on disk and bridged between WebDAV and native Syncthing.\n`,
        'utf8'
      );
    }
  }
}
ensureFilesystemFolders();

function readFilesystemFoldersWithStats() {
  const { folders } = parseStackEnv();
  return folders.map((f) => {
    const absDir = resolveFolderAbsPath(f);
    fs.mkdirSync(path.join(absDir, '.stfolder'), { recursive: true });
    let fileCount = 0;
    let totalBytes = 0;
    const files: string[] = [];
    for (const entry of fs.readdirSync(absDir, { withFileTypes: true })) {
      if (entry.name === '.stfolder') continue;
      if (!entry.isDirectory()) {
        fileCount++;
        files.push(entry.name);
        try {
          totalBytes += fs.statSync(path.join(absDir, entry.name)).size;
        } catch {}
      } else {
        files.push(`${entry.name}/`);
      }
    }
    return {
      slug: f.slug,
      env_expose_key: `EXPOSE_FOLDER_${f.slug}`,
      env_host_key: `HOST_PATH_${f.slug}`,
      env_container_key: `CONTAINER_PATH_${f.slug}`,
      host_path: f.host_path,
      container_path: f.container_path,
      exposed: f.exposed,
      syncthing_enabled: f.syncthing_enabled,
      fileCount,
      totalBytes,
      files,
    };
  });
}

// ============================================================================
// 3. NATIVE SYNCTHING BINARY DAEMON MANAGER & LIVE CONFIG SYNC
// ============================================================================
let syncthingProc: ChildProcess | null = null;
let localSyncthingDeviceId = 'BKMTX3T-MODC2KK-PY7UWVU-Q43YZ3J-UORQVQS-5JH2KIO-HO6PT7P-K6UY2AY';

function buildNativeSyncthingConfigXml(): string {
  const configPath = path.join(SYNCTHING_HOME_DIR, 'config.xml');
  if (fs.existsSync(configPath)) {
    const raw = fs.readFileSync(configPath, 'utf8');
    const match = raw.match(/<device id="([A-Z0-9-]+)"/);
    if (match && match[1]) {
      localSyncthingDeviceId = match[1];
    }
  }

  const { folders } = parseStackEnv();
  const activeSyncFolders = folders.filter((f) => f.exposed && f.syncthing_enabled);

  const folderBlocks = activeSyncFolders
    .map((f) => {
      const absHostPath = resolveFolderAbsPath(f);
      fs.mkdirSync(path.join(absHostPath, '.stfolder'), { recursive: true });
      return `    <folder id="vaultdav-${f.slug.toLowerCase()}" label="${f.slug} (${f.host_path})" path="${absHostPath}" type="sendreceive" rescanIntervalS="60" fsWatcherEnabled="true" fsWatcherDelayS="2" ignorePerms="false" autoNormalize="true">
        <filesystemType>basic</filesystemType>
        <device id="${localSyncthingDeviceId}" introducedBy="">
            <encryptionPassword></encryptionPassword>
        </device>
        <minDiskFree unit="%">1</minDiskFree>
        <markerName>.stfolder</markerName>
    </folder>`;
    })
    .join('\n');

  const xml = `<configuration version="37">
${folderBlocks}
    <device id="${localSyncthingDeviceId}" name="vaultdav-syncthing-node" compression="metadata" introducer="false" skipIntroductionRemovals="false" introducedBy="">
        <address>dynamic</address>
        <paused>false</paused>
        <autoAcceptFolders>false</autoAcceptFolders>
        <untrusted>false</untrusted>
    </device>
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

  fs.writeFileSync(configPath, xml, 'utf8');
  return xml;
}

async function syncFoldersToRunningSyncthing() {
  const xml = buildNativeSyncthingConfigXml();
  const { folders } = parseStackEnv();
  const activeSyncFolders = folders.filter((f) => f.exposed && f.syncthing_enabled);

  try {
    const folderPayload = activeSyncFolders.map((f) => ({
      id: `vaultdav-${f.slug.toLowerCase()}`,
      label: `${f.slug} (${f.host_path})`,
      filesystemType: 'basic',
      path: resolveFolderAbsPath(f),
      type: 'sendreceive',
      devices: [{ deviceID: localSyncthingDeviceId, introducedBy: '', encryptionPassword: '' }],
      rescanIntervalS: 60,
      fsWatcherEnabled: true,
      fsWatcherDelayS: 2,
      ignorePerms: false,
      autoNormalize: true,
      markerName: '.stfolder',
    }));

    await fetch('http://127.0.0.1:8384/rest/config/folders', {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': SYNCTHING_API_KEY,
      },
      body: JSON.stringify(folderPayload),
    });
  } catch {
    // Syncthing may still be starting up
  }
  return xml;
}

function startNativeSyncthingDaemon() {
  if (!fs.existsSync(SYNCTHING_BIN)) {
    console.warn('Syncthing binary not found at', SYNCTHING_BIN);
    return;
  }

  try {
    fs.chmodSync(SYNCTHING_BIN, 0o755);
  } catch (err) {
    console.warn('Failed to chmod syncthing binary:', err);
  }

  if (!fs.existsSync(path.join(SYNCTHING_HOME_DIR, 'cert.pem'))) {
    try {
      execSync(`${SYNCTHING_BIN} generate --home=${SYNCTHING_HOME_DIR}`);
    } catch {}
  }

  buildNativeSyncthingConfigXml();

  syncthingProc = spawn(
    SYNCTHING_BIN,
    [
      'serve',
      '--no-browser',
      '--no-upgrade',
      `--home=${SYNCTHING_HOME_DIR}`,
      '--gui-address=127.0.0.1:8384',
    ],
    {
      stdio: 'ignore',
      env: { ...process.env, STNOUPGRADE: '1' },
    }
  );

  syncthingProc.on('error', (err) => {
    console.error('Native Syncthing daemon error:', err);
  });

  syncthingProc.on('exit', (code) => {
    console.log(`Native Syncthing daemon exited with code ${code}`);
  });
}

function generateStackArtifacts() {
  const { folders, headers, webdavHost, webdavPort } = parseStackEnv();
  const envContent = writeStackEnv(folders, headers, webdavHost, webdavPort);
  const exposedFolders = folders.filter((f) => f.exposed);
  const syncthingFolders = folders.filter((f) => f.exposed && f.syncthing_enabled);

  const webdavVolumeLines = exposedFolders.map(
    (f) => `      - \${HOST_PATH_${f.slug}:-${f.host_path}}:\${CONTAINER_PATH_${f.slug}:-${f.container_path}}:rw`
  );
  const syncthingVolumeLines = syncthingFolders.map(
    (f) => `      - \${HOST_PATH_${f.slug}:-${f.host_path}}:\${CONTAINER_PATH_${f.slug}:-${f.container_path}}:rw`
  );

  const composeContent = `# Docker Compose — VaultDAV + Syncthing Stack
# SQLite (/data/db/vaultdav.sqlite) is used strictly for encrypted credentials.
# Folders and unencrypted files are mounted directly via .env into both containers.

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
    volumes:
      - ./data/db:/data/db
      # Host Folders Exposed via .env (Unencrypted on disk)
${webdavVolumeLines.length > 0 ? webdavVolumeLines.join('\n') : '      # No folders enabled in .env'}
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
      # Identical Unencrypted Host Folders Mounted into Syncthing
${syncthingVolumeLines.length > 0 ? syncthingVolumeLines.join('\n') : '      # No Syncthing folders enabled'}
    networks:
      - vaultdav_net

networks:
  vaultdav_net:
    driver: bridge
`;

  const dockerfileContent = `FROM node:22-alpine
RUN apk add --no-cache python3 make g++ sqlite
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
RUN mkdir -p /data/db /var/webdav/documents /var/webdav/projects /var/webdav/media /var/webdav/backups
EXPOSE 3000
CMD ["npm", "run", "start"]
`;

  const syncthingXmlContent = fs.existsSync(path.join(SYNCTHING_HOME_DIR, 'config.xml'))
    ? fs.readFileSync(path.join(SYNCTHING_HOME_DIR, 'config.xml'), 'utf8')
    : buildNativeSyncthingConfigXml();

  return { envContent, composeContent, dockerfileContent, syncthingXmlContent };
}

// Generate a complete zip archive ready for `docker compose up -d`
async function createDockerComposeZipBuffer(): Promise<Buffer> {
  const zip = new JSZip();
  const artifacts = generateStackArtifacts();
  const { webdavHost, webdavPort } = parseStackEnv();

  // Root stack orchestration files
  zip.file('docker-compose.yml', artifacts.composeContent);
  zip.file('.env', artifacts.envContent);
  zip.file('.env.example', artifacts.envContent);
  zip.file('Dockerfile', artifacts.dockerfileContent);

  // App build files
  if (fs.existsSync(path.join(__dirname, 'package.json'))) {
    zip.file('package.json', fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  }
  if (fs.existsSync(path.join(__dirname, 'tsconfig.json'))) {
    zip.file('tsconfig.json', fs.readFileSync(path.join(__dirname, 'tsconfig.json'), 'utf8'));
  }
  if (fs.existsSync(path.join(__dirname, 'vite.config.ts'))) {
    zip.file('vite.config.ts', fs.readFileSync(path.join(__dirname, 'vite.config.ts'), 'utf8'));
  }
  if (fs.existsSync(path.join(__dirname, 'index.html'))) {
    zip.file('index.html', fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'));
  }
  if (fs.existsSync(path.join(__dirname, 'server.ts'))) {
    zip.file('server.ts', fs.readFileSync(path.join(__dirname, 'server.ts'), 'utf8'));
  }

  // App source code directory
  const srcDir = path.join(__dirname, 'src');
  if (fs.existsSync(srcDir)) {
    const srcFiles = fs.readdirSync(srcDir);
    for (const sf of srcFiles) {
      const sfPath = path.join(srcDir, sf);
      if (fs.statSync(sfPath).isFile()) {
        zip.file(`src/${sf}`, fs.readFileSync(sfPath, 'utf8'));
      }
    }
  }

  // Syncthing initial configuration
  zip.file('data/syncthing-config/config.xml', artifacts.syncthingXmlContent);

  // Pre-created host volume mount folders
  const sampleVolumes = ['documents', 'projects', 'media', 'backups'];
  for (const v of sampleVolumes) {
    zip.file(
      `host_volumes/${v}/README.md`,
      `# Host Volume: ${v}\n\nExposed unencrypted and bridged between VaultDAV WebDAV and Syncthing.\n`
    );
  }

  // Ready-to-run instructions
  const readme = `# VaultDAV + Syncthing Docker Compose Package

This archive contains the complete, ready-to-run Docker Compose stack for **VaultDAV** and **Syncthing**.

## How to Run

\`\`\`bash
# 1. Unzip the archive
unzip vaultdav-docker-compose.zip
cd vaultdav-docker-compose

# 2. Start the stack in the background
docker compose up -d
\`\`\`

## Access Endpoints

- **VaultDAV & WebDAV**:
  - Web UI: http://localhost:${webdavPort} (or http://${webdavHost}:${webdavPort})
  - WebDAV Endpoint: http://localhost:${webdavPort}/dav/
- **Native Syncthing Web GUI**:
  - Web UI: http://localhost:8384
  - Synchronization Port: 22000 (TCP/UDP)

## Security Architecture

1. **SQLite Used Strictly for Encrypted Credentials**:
   Account passwords, TOTP secret, and auto-generated safe WebDAV passwords are stored in \`./data/db/vaultdav.sqlite\` encrypted with AES-256-GCM.
2. **Unified Username**:
   Your WebDAV username is identical to the login username you set during account setup.
3. **Optional TOTP 2FA**:
   2FA can be enabled or disabled at any time from the Account & Security menu on the main dashboard.
4. **Unencrypted Host Files**:
   Files in \`./host_volumes/\` remain unencrypted on disk and are mounted directly into both containers.
`;
  zip.file('README.md', readme);

  const buf = await zip.generateAsync({ type: 'nodebuffer', compression: 'DEFLATE' });
  try {
    fs.writeFileSync(STATIC_ZIP_FILE, buf);
  } catch {}
  return buf;
}

function renderWebdavBrowserHtml(
  currentHref: string,
  title: string,
  parentHref: string | null,
  items: { name: string; href: string; isDir: boolean; size: number; mtime: string }[]
): string {
  const rows = items
    .map(
      (item) => `<tr class="border-b border-zinc-800/70 hover:bg-zinc-900/60">
        <td class="py-2.5 px-4 font-mono text-xs">
          <a href="${item.href}" class="text-blue-400 hover:underline font-medium">${item.name}${item.isDir ? '/' : ''}</a>
        </td>
        <td class="py-2.5 px-4 font-mono text-xs text-zinc-400">${item.isDir ? 'Directory' : `${item.size} B`}</td>
        <td class="py-2.5 px-4 font-mono text-xs text-zinc-500">${item.mtime}</td>
      </tr>`
    )
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VaultDAV — ${title}</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-[#050507] text-zinc-100 min-h-screen p-8 font-sans">
  <div class="max-w-4xl mx-auto bg-[#0c0d10] border border-zinc-800 rounded-lg overflow-hidden">
    <div class="px-6 py-4 border-b border-zinc-800 flex items-center justify-between">
      <div>
        <h1 class="text-sm font-semibold text-zinc-100 font-mono">${currentHref}</h1>
        <p class="text-xs text-zinc-500 mt-0.5">VaultDAV Direct Domain / IP WebDAV Endpoint</p>
      </div>
      <a href="/" class="px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-md">Main App</a>
    </div>
    <table class="w-full text-left border-collapse">
      <thead>
        <tr class="border-b border-zinc-800 text-[11px] font-mono uppercase text-zinc-500 bg-[#07080a]">
          <th class="py-2 px-4">Name</th>
          <th class="py-2 px-4">Size</th>
          <th class="py-2 px-4">Modified</th>
        </tr>
      </thead>
      <tbody>
        ${
          parentHref
            ? `<tr class="border-b border-zinc-800/70 hover:bg-zinc-900/60">
                <td class="py-2.5 px-4 font-mono text-xs" colspan="3">
                  <a href="${parentHref}" class="text-zinc-300 hover:text-blue-400">.. (Parent Directory)</a>
                </td>
              </tr>`
            : ''
        }
        ${rows || `<tr><td colspan="3" class="py-6 px-4 text-xs font-mono text-zinc-500">Empty directory</td></tr>`}
      </tbody>
    </table>
  </div>
</body>
</html>`;
}

function requireAppAuth(req: Request, res: Response, next: NextFunction) {
  const token = String(req.headers['x-session-token'] || '');
  if (token && activeSessions.has(token)) {
    next();
    return;
  }
  res.status(401).json({ error: 'Authentication required' });
}

async function startServer() {
  startNativeSyncthingDaemon();

  // Pre-generate Docker zip file so it's ready on disk
  try {
    await createDockerComposeZipBuffer();
  } catch (err) {
    console.warn('Initial zip generation notice:', err);
  }

  const app = express();

  // ============================================================================
  // 1. Reverse Proxy to the REAL Native Syncthing Process on 127.0.0.1:8384
  // ============================================================================
  app.use(
    '/syncthing',
    createProxyMiddleware({
      target: 'http://127.0.0.1:8384',
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

  app.use(express.json({ limit: '10mb' }));
  app.use(express.text({ type: ['text/*', 'application/xml', 'application/yaml', 'application/octet-stream'], limit: '10mb' }));

  // ============================================================================
  // 2. Single-Account SQLite Auth Endpoints (/api/auth/*)
  // Registration requires ONLY Username & Password (TOTP 2FA can be added later)
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

  // Account creation: Only username and password required! TOTP 2FA is added later in account menu
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

    // Auto-generate safe WebDAV 24-character password (username is strictly the same as login!)
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
  // 3. Real RFC 4918 WebDAV Server (/dav and /dav/:slug/*)
  // WebDAV username is STRICTLY the SAME as login username.
  // All credentials saved in SQLite.
  // ============================================================================
  const applyWebdavHeadersAndAuth = (req: Request, res: Response) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, Depth, Overwrite, Destination, Content-Type, X-Requested-With, *');
    res.setHeader('Access-Control-Expose-Headers', 'DAV, Allow, X-Received-Custom-Headers');

    const { folders, headers } = parseStackEnv();
    for (const h of headers.filter((x) => x.enabled)) {
      try {
        res.setHeader(h.header_name, h.header_value);
      } catch {}
    }

    const echoedClientHeaders: string[] = [];
    for (const [k, v] of Object.entries(req.headers)) {
      if (k.startsWith('x-') || ['depth', 'overwrite', 'if-match'].includes(k.toLowerCase())) {
        echoedClientHeaders.push(`${k}: ${String(v)}`);
      }
    }
    if (echoedClientHeaders.length > 0) {
      res.setHeader('X-Received-Custom-Headers', echoedClientHeaders.join(' | '));
    }

    if (req.method.toUpperCase() === 'OPTIONS') {
      res.setHeader('DAV', '1, 2');
      res.setHeader('Allow', 'OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE');
      res.status(200).end();
      return { handled: true, folders };
    }

    const auth = verifyWebdavBasicAuth(req.headers.authorization);
    if (!auth.ok) {
      res.setHeader('WWW-Authenticate', 'Basic realm="VaultDAV Server"');
      res.status(401).send(auth.error || 'Unauthorized: WebDAV username (same as login) and safe password required');
      return { handled: true, folders };
    }

    return { handled: false, folders };
  };

  // Root /dav and /dav/ endpoint
  app.all(['/dav', '/dav/'], (req: Request, res: Response) => {
    const { handled, folders } = applyWebdavHeadersAndAuth(req, res);
    if (handled) return;

    const exposed = folders.filter((f) => f.exposed);
    const method = req.method.toUpperCase();

    if (method === 'PROPFIND') {
      const nowUtc = new Date().toUTCString();
      const responsesXml: string[] = [
        `  <D:response>
    <D:href>/dav/</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>dav</D:displayname>
        <D:getlastmodified>${nowUtc}</D:getlastmodified>
        <D:getcontentlength>0</D:getcontentlength>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`,
      ];

      if (req.headers.depth !== '0') {
        for (const f of exposed) {
          responsesXml.push(`  <D:response>
    <D:href>/dav/${f.slug.toLowerCase()}/</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${f.slug.toLowerCase()}</D:displayname>
        <D:getlastmodified>${nowUtc}</D:getlastmodified>
        <D:getcontentlength>0</D:getcontentlength>
        <D:resourcetype><D:collection/></D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`);
        }
      }

      const xml = `<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">\n${responsesXml.join('\n')}\n</D:multistatus>`;
      res.setHeader('Content-Type', 'application/xml; charset=utf-8');
      res.status(207).send(xml);
      return;
    }

    if (method === 'GET' || method === 'HEAD') {
      const items = exposed.map((f) => ({
        name: f.slug.toLowerCase(),
        href: `/dav/${f.slug.toLowerCase()}/`,
        isDir: true,
        size: 0,
        mtime: new Date().toUTCString(),
      }));
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.status(200).send(renderWebdavBrowserHtml('/dav/', 'WebDAV Root Mounts', null, items));
      return;
    }

    res.status(405).send('Method Not Allowed');
  });

  app.all('/dav/:slug*', (req: Request, res: Response) => {
    const { handled, folders } = applyWebdavHeadersAndAuth(req, res);
    if (handled) return;

    const slug = (req.params.slug || '').toUpperCase();
    const rawSubPath = decodeURIComponent((req.params as any)[0] || '');
    const method = req.method.toUpperCase();

    const folder = folders.find((f) => f.slug === slug);
    if (!folder) {
      res.status(404).send(`WebDAV Mount /dav/${slug.toLowerCase()} not found in .env`);
      return;
    }

    if (!folder.exposed) {
      res.status(403).send(`Folder ${slug} is disabled via EXPOSE_FOLDER_${slug}=false in .env`);
      return;
    }

    const baseMountDir = resolveFolderAbsPath(folder);
    const safeSubPath = path.normalize(rawSubPath).replace(/^(\.\.(\/|\\|$))+/, '').replace(/^\/+/, '');
    const targetFsPath = path.join(baseMountDir, safeSubPath);

    if (!targetFsPath.startsWith(baseMountDir)) {
      res.status(403).send('Forbidden path');
      return;
    }

    if (method === 'PROPFIND') {
      if (!fs.existsSync(targetFsPath)) {
        res.status(404).send('Not Found');
        return;
      }
      const stat = fs.statSync(targetFsPath);
      const responsesXml: string[] = [];

      const escapeXml = (str: string) =>
        str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

      const buildPropXml = (href: string, itemStat: fs.Stats, displayName: string) => {
        const isDir = itemStat.isDirectory();
        return `  <D:response>
    <D:href>${href}</D:href>
    <D:propstat>
      <D:prop>
        <D:displayname>${escapeXml(displayName)}</D:displayname>
        <D:getlastmodified>${itemStat.mtime.toUTCString()}</D:getlastmodified>
        <D:getcontentlength>${isDir ? 0 : itemStat.size}</D:getcontentlength>
        <D:resourcetype>${isDir ? '<D:collection/>' : ''}</D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
      };

      const cleanSub = safeSubPath.replace(/^\/+|\/+$/g, '').replace(/\\/g, '/');
      const encodedSub = cleanSub
        ? cleanSub
            .split('/')
            .map((s) => encodeURIComponent(s))
            .join('/')
        : '';
      const baseHref = `/dav/${slug.toLowerCase()}${encodedSub ? '/' + encodedSub : ''}${stat.isDirectory() ? '/' : ''}`;
      responsesXml.push(buildPropXml(baseHref, stat, path.basename(targetFsPath) || slug.toLowerCase()));

      if (stat.isDirectory() && req.headers.depth !== '0') {
        const children = fs.readdirSync(targetFsPath).filter((c) => c !== '.stfolder');
        for (const child of children) {
          try {
            const childStat = fs.statSync(path.join(targetFsPath, child));
            const childHref = `${baseHref.replace(/\/$/, '')}/${encodeURIComponent(child)}${childStat.isDirectory() ? '/' : ''}`;
            responsesXml.push(buildPropXml(childHref, childStat, child));
          } catch {}
        }
      }

      const xml = `<?xml version="1.0" encoding="utf-8"?>\n<D:multistatus xmlns:D="DAV:">\n${responsesXml.join('\n')}\n</D:multistatus>`;
      res.setHeader('Content-Type', 'application/xml; charset=utf-8');
      res.status(207).send(xml);
      return;
    }

    if (method === 'GET' || method === 'HEAD') {
      if (!fs.existsSync(targetFsPath)) {
        res.status(404).send('File not found');
        return;
      }
      const stat = fs.statSync(targetFsPath);
      if (stat.isDirectory()) {
        const cleanSub = safeSubPath.replace(/^\/+|\/+$/g, '').replace(/\\/g, '/');
        const currentHref = `/dav/${slug.toLowerCase()}/${cleanSub ? cleanSub + '/' : ''}`;
        const parentHref = cleanSub
          ? `/dav/${slug.toLowerCase()}/${cleanSub.split('/').slice(0, -1).join('/')}`
          : '/dav/';
        const children = fs
          .readdirSync(targetFsPath)
          .filter((c) => c !== '.stfolder')
          .map((child) => {
            const cStat = fs.statSync(path.join(targetFsPath, child));
            return {
              name: child,
              href: `${currentHref.replace(/\/$/, '')}/${encodeURIComponent(child)}${cStat.isDirectory() ? '/' : ''}`,
              isDir: cStat.isDirectory(),
              size: cStat.isDirectory() ? 0 : cStat.size,
              mtime: cStat.mtime.toUTCString(),
            };
          });
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.status(200).send(renderWebdavBrowserHtml(currentHref, slug, parentHref, children));
        return;
      }
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.status(200).send(fs.readFileSync(targetFsPath, 'utf8'));
      return;
    }

    if (method === 'PUT') {
      fs.mkdirSync(path.dirname(targetFsPath), { recursive: true });
      const bodyContent = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? '', null, 2);
      fs.writeFileSync(targetFsPath, bodyContent, 'utf8');
      res.status(201).send('Created');
      return;
    }

    if (method === 'MKCOL') {
      fs.mkdirSync(targetFsPath, { recursive: true });
      res.status(201).send('Directory Created');
      return;
    }

    if (method === 'DELETE') {
      if (!fs.existsSync(targetFsPath)) {
        res.status(404).send('Not Found');
        return;
      }
      fs.rmSync(targetFsPath, { recursive: true, force: true });
      res.status(204).end();
      return;
    }

    res.status(405).send('Method Not Allowed');
  });

  // ============================================================================
  // 4. Authenticated App API Routes (/api/*)
  // ============================================================================
  app.use('/api', requireAppAuth);

  // Download ready-to-run Docker Compose ZIP file
  app.get('/api/docker/download-zip', async (_req: Request, res: Response) => {
    try {
      const zipBuffer = await createDockerComposeZipBuffer();
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="vaultdav-docker-compose.zip"');
      res.setHeader('Content-Length', zipBuffer.length);
      res.end(zipBuffer);
    } catch (err: any) {
      console.error('Failed to generate zip:', err);
      res.status(500).json({ error: 'Failed to create docker zip package: ' + err.message });
    }
  });

  // Option to add TOTP 2FA later in Account Menu
  app.post('/api/account/2fa/prepare', async (req: Request, res: Response) => {
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

  app.get('/api/host-browser', (req: Request, res: Response) => {
    const requestedPath = String(req.query.path || './host_volumes').trim();
    let targetDir = path.isAbsolute(requestedPath)
      ? path.normalize(requestedPath)
      : path.resolve(__dirname, requestedPath);

    if (!targetDir.startsWith(__dirname) || !fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
      targetDir = HOST_VOLUMES_DIR;
    }

    const { folders } = parseStackEnv();
    const hiddenSystemDirs = new Set(['node_modules', '.git', 'bin', 'dist', '.stfolder']);

    const entries = fs
      .readdirSync(targetDir, { withFileTypes: true })
      .filter((e) => !hiddenSystemDirs.has(e.name))
      .map((entry) => {
        const entryAbs = path.join(targetDir, entry.name);
        const relPath = toRelativeHostPath(entryAbs);
        let size = 0;
        try {
          if (!entry.isDirectory()) {
            size = fs.statSync(entryAbs).size;
          }
        } catch {}

        const matchedFolder = folders.find(
          (f) => resolveFolderAbsPath(f) === entryAbs
        );

        return {
          name: entry.name,
          path: entryAbs,
          relativePath: relPath,
          isDirectory: entry.isDirectory(),
          size,
          alreadyExposedSlug: matchedFolder ? matchedFolder.slug : null,
        };
      })
      .sort((a, b) => {
        if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

    const parentAbs = path.dirname(targetDir);
    const canGoUp = targetDir !== __dirname && parentAbs.startsWith(__dirname);

    res.json({
      currentPath: targetDir,
      relativePath: toRelativeHostPath(targetDir),
      parentPath: canGoUp ? toRelativeHostPath(parentAbs) : null,
      entries,
    });
  });

  app.post('/api/host-browser/mkdir', (req: Request, res: Response) => {
    const parentRel = String(req.body.parentPath || './host_volumes').trim();
    const folderName = String(req.body.name || '')
      .trim()
      .replace(/[^a-zA-Z0-9._-]/g, '_');
    if (!folderName) {
      res.status(400).json({ error: 'Folder name required' });
      return;
    }

    const parentAbs = path.isAbsolute(parentRel)
      ? path.normalize(parentRel)
      : path.resolve(__dirname, parentRel);

    if (!parentAbs.startsWith(__dirname)) {
      res.status(403).json({ error: 'Invalid host directory' });
      return;
    }

    const newDirAbs = path.join(parentAbs, folderName);
    fs.mkdirSync(newDirAbs, { recursive: true });
    res.status(201).json({
      ok: true,
      relativePath: toRelativeHostPath(newDirAbs),
      name: folderName,
    });
  });

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

    const folders = readFilesystemFoldersWithStats();
    const { headers, webdavHost, webdavPort } = parseStackEnv();
    const artifacts = generateStackArtifacts();
    const detectedIp = getDetectedLocalIp();
    const detectedHost = String(req.headers.host || `${detectedIp}:3000`);

    res.json({
      account,
      webdavCredentials: {
        username: account?.username || '', // Strictly the SAME username used for login
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

  // Auto-generate safe WebDAV password on the main app (username remains identical to login username!)
  // All credentials saved in SQLite
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
        username: account.username, // Strictly the same as login username
        password: nextSafePassword,
        ciphertext_hex: encDav.ciphertextHex,
        iv_hex: encDav.ivHex,
        auth_tag_hex: encDav.authTagHex,
      },
    });
  });

  // Configure Domain Name or IP Address for WebDAV in .env
  app.put('/api/webdav-host', async (req: Request, res: Response) => {
    const domainOrIp = String(req.body?.domainOrIp || '').trim() || getDetectedLocalIp();
    const port = String(req.body?.port || '8080').trim() || '8080';
    const { folders, headers } = parseStackEnv();
    writeStackEnv(folders, headers, domainOrIp, port);
    try {
      await createDockerComposeZipBuffer();
    } catch {}
    res.json({ ok: true, domainOrIp, port });
  });

  app.put('/api/folders/:slug', async (req: Request, res: Response) => {
    const slug = String(req.params.slug || '').toUpperCase();
    const { folders, headers } = parseStackEnv();
    const target = folders.find((f) => f.slug === slug);
    if (!target) {
      res.status(404).json({ error: 'Folder not found in .env' });
      return;
    }

    if (req.body.exposed !== undefined) target.exposed = Boolean(req.body.exposed);
    if (req.body.syncthing_enabled !== undefined) target.syncthing_enabled = Boolean(req.body.syncthing_enabled);

    writeStackEnv(folders, headers);
    await syncFoldersToRunningSyncthing();
    try {
      await createDockerComposeZipBuffer();
    } catch {}
    res.json({ ok: true });
  });

  app.post('/api/folders', async (req: Request, res: Response) => {
    const rawSlug = String(req.body.slug || '')
      .trim()
      .toUpperCase()
      .replace(/[^A-Z0-9_]/g, '_');
    if (!rawSlug) {
      res.status(400).json({ error: 'Folder name required' });
      return;
    }

    const { folders, headers } = parseStackEnv();
    if (folders.some((f) => f.slug === rawSlug)) {
      res.status(400).json({ error: 'Folder already exists in .env' });
      return;
    }

    const rawHostPath = String(req.body.host_path || `./host_volumes/${rawSlug.toLowerCase()}`).trim();

    folders.push({
      slug: rawSlug,
      exposed: true,
      syncthing_enabled: true,
      host_path: rawHostPath,
      container_path: `/var/webdav/${rawSlug.toLowerCase()}`,
    });

    writeStackEnv(folders, headers);
    ensureFilesystemFolders();
    await syncFoldersToRunningSyncthing();
    try {
      await createDockerComposeZipBuffer();
    } catch {}
    res.status(201).json({ ok: true });
  });

  app.delete('/api/folders/:slug', async (req: Request, res: Response) => {
    const slug = String(req.params.slug || '').toUpperCase();
    const { folders, headers } = parseStackEnv();
    const filtered = folders.filter((f) => f.slug !== slug);
    writeStackEnv(filtered, headers);
    await syncFoldersToRunningSyncthing();
    try {
      await createDockerComposeZipBuffer();
    } catch {}
    res.json({ ok: true });
  });

  app.post('/api/headers', async (req: Request, res: Response) => {
    const headerName = String(req.body.header_name || '').trim();
    const headerValue = String(req.body.header_value || '').trim();
    if (!headerName || !headerValue) {
      res.status(400).json({ error: 'Header name and value required' });
      return;
    }
    const { folders, headers } = parseStackEnv();
    headers.push({ header_name: headerName, header_value: headerValue, enabled: true });
    writeStackEnv(folders, headers);
    try {
      await createDockerComposeZipBuffer();
    } catch {}
    res.status(201).json({ ok: true });
  });

  app.put('/api/headers/:index', async (req: Request, res: Response) => {
    const idx = Number(req.params.index);
    const { folders, headers } = parseStackEnv();
    if (headers[idx]) {
      headers[idx].enabled = Boolean(req.body.enabled);
      writeStackEnv(folders, headers);
      try {
        await createDockerComposeZipBuffer();
      } catch {}
    }
    res.json({ ok: true });
  });

  app.delete('/api/headers/:index', async (req: Request, res: Response) => {
    const idx = Number(req.params.index);
    const { folders, headers } = parseStackEnv();
    headers.splice(idx, 1);
    writeStackEnv(folders, headers);
    try {
      await createDockerComposeZipBuffer();
    } catch {}
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
  });
}

startServer();
