import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import { createProxyMiddleware } from 'http-proxy-middleware';
import Database from 'better-sqlite3';
import { spawn, ChildProcess, execSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
process.env.DISABLE_HMR = 'true';

const DATA_DIR = path.join(__dirname, 'data', 'db');
const SYNCTHING_HOME_DIR = path.join(__dirname, 'data', 'syncthing-home');
const SYNCTHING_BIN = path.join(__dirname, 'bin', 'syncthing');
const HOST_VOLUMES_DIR = path.join(__dirname, 'host_volumes');
const ENV_STACK_FILE = path.join(__dirname, 'data', '.env.stack');

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(SYNCTHING_HOME_DIR, { recursive: true });
fs.mkdirSync(HOST_VOLUMES_DIR, { recursive: true });

// ============================================================================
// 1. SQLITE DATABASE: STRICTLY & EXCLUSIVELY FOR ENCRYPTED CREDENTIALS
// ============================================================================
const DB_PATH = path.join(DATA_DIR, 'vaultdav.sqlite');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

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
    kdf_spec TEXT NOT NULL DEFAULT 'PBKDF2-SHA256 (100k) -> AES-256-GCM',
    created_at TEXT NOT NULL,
    last_used_at TEXT
  );
`);

const MASTER_SECRET = process.env.SQLITE_MASTER_KEY || 'vaultdav-aes256-gcm-master-secret-key-2026';
const KDF_SALT = 'vaultdav-sqlite-kdf-salt-v1';
const SYNCTHING_API_KEY = 'vaultdav-syncthing-local-api-key';

const activeSessions = new Map<string, { username: string; createdAt: number }>();

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

function verifyCredentials(username: string, password: string): { ok: boolean; account?: any; error?: string } {
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
    db.prepare('UPDATE credentials SET last_used_at = ? WHERE id = 1').run(new Date().toISOString());
    return { ok: true, account: row };
  } catch {
    return { ok: false, error: 'Failed to decrypt SQLite credential' };
  }
}

function verifyBasicAuthHeader(authHeader: string | undefined): { ok: boolean; username: string; error?: string } {
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return { ok: false, username: 'anonymous', error: 'Authentication required' };
  }
  const decoded = Buffer.from(authHeader.slice(6).trim(), 'base64').toString('utf8');
  const colonIdx = decoded.indexOf(':');
  if (colonIdx === -1) {
    return { ok: false, username: 'invalid', error: 'Malformed Basic Auth header' };
  }
  const username = decoded.slice(0, colonIdx);
  const password = decoded.slice(colonIdx + 1);
  const result = verifyCredentials(username, password);
  return { ok: result.ok, username, error: result.error };
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
  // Keep within workspace root for safety
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
  // Also create some sample host folders inside host_volumes for the Host File Browser
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
    const defaultEnv = [
      '# VaultDAV & Syncthing Container Environment (.env)',
      'PUID=1000',
      'PGID=1000',
      'TZ=UTC',
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

function parseStackEnv(): { folders: FolderConfigItem[]; headers: CustomHeaderItem[] } {
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

  return { folders, headers };
}

function writeStackEnv(folders: FolderConfigItem[], headers: CustomHeaderItem[]) {
  const serializedHeaders = headers
    .map((h) => `${h.header_name}:${h.header_value}|${h.enabled ? '1' : '0'}`)
    .join(';');

  const lines: string[] = [
    '# VaultDAV & Syncthing Container Environment (.env)',
    'PUID=1000',
    'PGID=1000',
    'TZ=UTC',
    'WEBDAV_PORT=8080',
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

  syncthingProc.on('exit', (code) => {
    console.log(`Native Syncthing daemon exited with code ${code}`);
  });
}

function generateStackArtifacts() {
  const { folders, headers } = parseStackEnv();
  const envContent = writeStackEnv(folders, headers);
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

  const app = express();

  // ============================================================================
  // 1. Reverse Proxy to the REAL Native Syncthing Process on 127.0.0.1:8384
  // Mounted BEFORE body parsers so POST/PUT bodies stream directly to Syncthing!
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
  // ============================================================================
  app.get('/api/auth/status', (req: Request, res: Response) => {
    const account = db.prepare('SELECT username FROM credentials WHERE id = 1').get() as { username: string } | undefined;
    const token = String(req.headers['x-session-token'] || '');
    const session = token ? activeSessions.get(token) : undefined;

    res.json({
      hasAccount: Boolean(account),
      authenticated: Boolean(session && account && session.username === account.username),
      username: session?.username || null,
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

    const enc = encryptSecret(password);
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO credentials (id, username, ciphertext_hex, iv_hex, auth_tag_hex, created_at, last_used_at)
      VALUES (1, ?, ?, ?, ?, ?, ?)
    `).run(username, enc.ciphertextHex, enc.ivHex, enc.authTagHex, now, now);

    const token = crypto.randomBytes(24).toString('hex');
    activeSessions.set(token, { username, createdAt: Date.now() });

    res.status(201).json({ ok: true, token, username });
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    const username = String(req.body.username || '').trim();
    const password = String(req.body.password || '');

    const check = verifyCredentials(username, password);
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
  // 3. Real RFC 4918 WebDAV Server (/dav/:slug/*)
  // Protected by Basic Auth Login/Password Prompt against SQLite Credentials
  // ============================================================================
  app.all('/dav/:slug*', (req: Request, res: Response) => {
    const slug = (req.params.slug || '').toUpperCase();
    const rawSubPath = decodeURIComponent((req.params as any)[0] || '');
    const method = req.method.toUpperCase();

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

    const auth = verifyBasicAuthHeader(req.headers.authorization);
    if (!auth.ok) {
      res.setHeader('WWW-Authenticate', 'Basic realm="VaultDAV Server"');
      res.status(401).send(auth.error || 'Unauthorized: WebDAV login and password required');
      return;
    }

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

    if (method === 'OPTIONS') {
      res.setHeader('DAV', '1, 2');
      res.setHeader('Allow', 'OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE');
      res.status(200).end();
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
      if (!fs.existsSync(targetFsPath) || fs.statSync(targetFsPath).isDirectory()) {
        res.status(404).send('File not found');
        return;
      }
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      res.status(200).send(fs.readFileSync(targetFsPath, 'utf8'));
      return;
    }

    if (method === 'PUT') {
      fs.mkdirSync(path.dirname(targetFsPath), { recursive: true });
      const bodyContent = typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? '', null, 2);
      // Save unencrypted directly to the shared host folder
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

  // Simple Host File Browser API to choose host folders to expose in .env
  app.get('/api/host-browser', (req: Request, res: Response) => {
    const requestedPath = String(req.query.path || './host_volumes').trim();
    let targetDir = path.isAbsolute(requestedPath)
      ? path.normalize(requestedPath)
      : path.resolve(__dirname, requestedPath);

    // Keep browsing rooted inside the workspace directory for safety
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

  app.get('/api/state', (_req: Request, res: Response) => {
    const account = db.prepare('SELECT * FROM credentials WHERE id = 1').get() as any;
    const sqliteTables = (
      db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all() as {
        name: string;
      }[]
    ).map((t) => t.name);

    const folders = readFilesystemFoldersWithStats();
    const { headers } = parseStackEnv();
    const artifacts = generateStackArtifacts();

    res.json({
      account,
      sqliteTables,
      folders,
      customHeaders: headers,
      webdavUrl: '/dav/',
      syncthingUrl: '/syncthing/',
      artifacts,
    });
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
    res.status(201).json({ ok: true });
  });

  app.delete('/api/folders/:slug', async (req: Request, res: Response) => {
    const slug = String(req.params.slug || '').toUpperCase();
    const { folders, headers } = parseStackEnv();
    const filtered = folders.filter((f) => f.slug !== slug);
    writeStackEnv(filtered, headers);
    await syncFoldersToRunningSyncthing();
    res.json({ ok: true });
  });

  app.post('/api/headers', (req: Request, res: Response) => {
    const headerName = String(req.body.header_name || '').trim();
    const headerValue = String(req.body.header_value || '').trim();
    if (!headerName || !headerValue) {
      res.status(400).json({ error: 'Header name and value required' });
      return;
    }
    const { folders, headers } = parseStackEnv();
    headers.push({ header_name: headerName, header_value: headerValue, enabled: true });
    writeStackEnv(folders, headers);
    res.status(201).json({ ok: true });
  });

  app.put('/api/headers/:index', (req: Request, res: Response) => {
    const idx = Number(req.params.index);
    const { folders, headers } = parseStackEnv();
    if (headers[idx]) {
      headers[idx].enabled = Boolean(req.body.enabled);
      writeStackEnv(folders, headers);
    }
    res.json({ ok: true });
  });

  app.delete('/api/headers/:index', (req: Request, res: Response) => {
    const idx = Number(req.params.index);
    const { folders, headers } = parseStackEnv();
    headers.splice(idx, 1);
    writeStackEnv(folders, headers);
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
