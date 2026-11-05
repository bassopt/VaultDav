import React, { useEffect, useState, useCallback } from 'react';
import {
  Download,
  Plus,
  Trash2,
  Copy,
  Check,
  LogOut,
  Folder,
  FileText,
  FolderPlus,
  FilePlus,
  Upload,
  RefreshCw,
  ArrowUp,
  Save,
  Sliders,
  ExternalLink,
  KeyRound,
  Eye,
  EyeOff,
  Globe,
  Archive,
  ShieldCheck,
  ShieldAlert,
  Shield,
  X,
} from 'lucide-react';
import type {
  AppStateResponse,
  AuthStatusResponse,
  EnvFolderMount,
  HostBrowserResponse,
  WebdavCustomHeader,
  WebdavEntry,
} from './types';

type ActiveTab = 'folders' | 'webdav_app' | 'syncthing_app' | 'docker';
type DockerFileKey = 'compose' | 'env' | 'dockerfile' | 'syncthing';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

function parseWebdavPropfindXml(xmlText: string, currentHref: string): WebdavEntry[] {
  try {
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, 'application/xml');
    const responses = Array.from(doc.getElementsByTagNameNS('*', 'response'));
    const items: WebdavEntry[] = [];
    const normCurrent = decodeURIComponent(currentHref).replace(/\/+$/, '');

    for (const resp of responses) {
      const hrefNode = resp.getElementsByTagNameNS('*', 'href')[0];
      const nameNode = resp.getElementsByTagNameNS('*', 'displayname')[0];
      const lenNode = resp.getElementsByTagNameNS('*', 'getcontentlength')[0];
      const modNode = resp.getElementsByTagNameNS('*', 'getlastmodified')[0];
      const colNode = resp.getElementsByTagNameNS('*', 'collection')[0];

      const rawHref = hrefNode?.textContent || '';
      const decodedHref = decodeURIComponent(rawHref).replace(/\/+$/, '');
      if (!rawHref || decodedHref === normCurrent) continue;

      const isDirectory = Boolean(colNode) || rawHref.endsWith('/');
      const name =
        nameNode?.textContent ||
        decodeURIComponent(rawHref.replace(/\/+$/, '').split('/').pop() || '');

      items.push({
        href: rawHref,
        name,
        isDirectory,
        size: Number(lenNode?.textContent || 0),
        lastModified: modNode?.textContent || '',
      });
    }

    return items.sort((a, b) => {
      if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
  } catch {
    return [];
  }
}

export default function App() {
  const [sessionToken, setSessionToken] = useState<string>(
    () => localStorage.getItem('vaultdav_token') || ''
  );
  const [authStatus, setAuthStatus] = useState<AuthStatusResponse | null>(null);
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authTotpCode, setAuthTotpCode] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSubmitting, setAuthSubmitting] = useState(false);

  const [activeTab, setActiveTab] = useState<ActiveTab>('folders');
  const [state, setState] = useState<AppStateResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Main App Auto-Generated WebDAV Credentials & Domain/IP state
  const [showSafePassword, setShowSafePassword] = useState<boolean>(true);
  const [regeneratingCreds, setRegeneratingCreds] = useState<boolean>(false);
  const [hostInput, setHostInput] = useState<string>('');
  const [portInput, setPortInput] = useState<string>('8080');
  const [savingHost, setSavingHost] = useState<boolean>(false);
  const [downloadingZip, setDownloadingZip] = useState<boolean>(false);

  // Account Menu & Optional TOTP 2FA Modal / Panel
  const [showAccountModal, setShowAccountModal] = useState<boolean>(false);
  const [setup2faSecret, setSetup2faSecret] = useState<string>('');
  const [setup2faQrSvg, setSetup2faQrSvg] = useState<string>('');
  const [setup2faVerifyCode, setSetup2faVerifyCode] = useState<string>('');
  const [setup2faLoading, setSetup2faLoading] = useState<boolean>(false);
  const [setup2faError, setSetup2faError] = useState<string | null>(null);
  const [setup2faSuccess, setSetup2faSuccess] = useState<string | null>(null);
  const [disable2faPassword, setDisable2faPassword] = useState<string>('');
  const [showDisable2faForm, setShowDisable2faForm] = useState<boolean>(false);

  // 1. Small Host Folder Picker state (when adding a new folder to .env)
  const [showHostBrowser, setShowHostBrowser] = useState<boolean>(false);
  const [hostBrowserData, setHostBrowserData] = useState<HostBrowserResponse | null>(null);
  const [hostBrowserLoading, setHostBrowserLoading] = useState<boolean>(false);
  const [newHostDirName, setNewHostDirName] = useState<string>('');
  const [newSlug, setNewSlug] = useState('');
  const [newHostPath, setNewHostPath] = useState('');

  // 2. Real WebDAV File Manager App state (Requires WebDAV User & Safe Password)
  const [davAuthed, setDavAuthed] = useState<boolean>(false);
  const [davLoginUser, setDavLoginUser] = useState<string>('');
  const [davLoginPass, setDavLoginPass] = useState<string>('');
  const [davAuthError, setDavAuthError] = useState<string | null>(null);
  const [davMountSlug, setDavMountSlug] = useState<string>('DOCUMENTS');
  const [davSubPath, setDavSubPath] = useState<string>('');
  const [davEntries, setDavEntries] = useState<WebdavEntry[]>([]);
  const [davLoading, setDavLoading] = useState<boolean>(false);
  const [davLastHeaders, setDavLastHeaders] = useState<Record<string, string>>({});

  // WebDAV File Viewer / Editor / Creation state
  const [selectedFile, setSelectedFile] = useState<{ name: string; content: string } | null>(null);
  const [creatingFolder, setCreatingFolder] = useState<boolean>(false);
  const [newDavFolderName, setNewDavFolderName] = useState<string>('');
  const [creatingFile, setCreatingFile] = useState<boolean>(false);
  const [newDavFileName, setNewDavFileName] = useState<string>('');

  // Simple Custom HTTP Headers inside WebDAV App
  const [showDavHeadersPanel, setShowDavHeadersPanel] = useState<boolean>(false);
  const [headerName, setHeaderName] = useState('');
  const [headerValue, setHeaderValue] = useState('');
  const [clientHeaderName, setClientHeaderName] = useState('');
  const [clientHeaderValue, setClientHeaderValue] = useState('');

  // 3. Docker Compose Files Viewer state
  const [selectedDockerFile, setSelectedDockerFile] = useState<DockerFileKey>('compose');

  const apiFetch = useCallback(
    (url: string, options: RequestInit = {}) => {
      return fetch(url, {
        ...options,
        headers: {
          ...(options.headers || {}),
          'x-session-token': sessionToken,
        },
      });
    },
    [sessionToken]
  );

  const loadHostBrowser = useCallback(
    async (targetPath = './host_volumes') => {
      setHostBrowserLoading(true);
      try {
        const res = await apiFetch(
          `/api/host-browser?path=${encodeURIComponent(targetPath)}`
        );
        if (res.ok) {
          const data: HostBrowserResponse = await res.json();
          setHostBrowserData(data);
        }
      } catch {
        // ignore
      } finally {
        setHostBrowserLoading(false);
      }
    },
    [apiFetch]
  );

  const checkAuthAndLoad = useCallback(async () => {
    try {
      const statusRes = await fetch('/api/auth/status', {
        headers: { 'x-session-token': sessionToken },
      });
      const statusData: AuthStatusResponse = await statusRes.json();
      setAuthStatus(statusData);

      if (statusData.authenticated) {
        const stateRes = await apiFetch('/api/state');
        if (stateRes.ok) {
          const data: AppStateResponse = await stateRes.json();
          setState(data);
          // WebDAV username is strictly the same as login username
          setDavLoginUser(data.account.username);
          setDavLoginPass((prev) => prev || data.webdavCredentials.password);
          setHostInput((prev) => prev || data.webdavHostConfig.domainOrIp);
          setPortInput((prev) => prev || data.webdavHostConfig.webAppPort || data.webdavHostConfig.port || '8080');
          const firstExposed = data.folders.find((f) => f.exposed);
          if (firstExposed) {
            setDavMountSlug((prev) =>
              data.folders.some((f) => f.slug === prev && f.exposed)
                ? prev
                : firstExposed.slug
            );
          }
        }
      } else {
        setState(null);
      }
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  }, [sessionToken, apiFetch]);

  useEffect(() => {
    checkAuthAndLoad();
  }, [checkAuthAndLoad]);

  // Perform real WebDAV request with Basic Auth (WebDAV User + Safe Password) + optional custom client header
  const fetchWebdav = useCallback(
    async (
      pathUrl: string,
      method: string,
      body?: BodyInit | null,
      overrideUser?: string,
      overridePass?: string,
      contentType?: string
    ) => {
      const user = overrideUser !== undefined ? overrideUser : davLoginUser;
      const pass = overridePass !== undefined ? overridePass : davLoginPass;
      const headers: Record<string, string> = {
        Authorization: `Basic ${btoa(`${user}:${pass}`)}`,
      };
      if (contentType) {
        headers['Content-Type'] = contentType;
      }
      if (method === 'PROPFIND') {
        headers['Depth'] = '1';
      }
      if (clientHeaderName.trim() && clientHeaderValue.trim()) {
        headers[clientHeaderName.trim()] = clientHeaderValue.trim();
      }

      const res = await fetch(pathUrl, {
        method,
        headers,
        body,
      });

      const capturedHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => {
        capturedHeaders[k] = v;
      });
      setDavLastHeaders(capturedHeaders);
      return res;
    },
    [davLoginUser, davLoginPass, clientHeaderName, clientHeaderValue]
  );

  const loadWebdavDirectory = useCallback(
    async (
      sub = davSubPath,
      user?: string,
      pass?: string
    ) => {
      setDavLoading(true);
      setDavAuthError(null);
      try {
        const cleanSub = sub.replace(/^\/+|\/+$/g, '');
        const encodedSub = cleanSub
          ? cleanSub
              .split('/')
              .filter(Boolean)
              .map((s) => encodeURIComponent(s))
              .join('/') + '/'
          : '';
        const href = `/dav/${encodedSub}`;
        const res = await fetchWebdav(href, 'PROPFIND', undefined, user, pass);

        if (res.status === 401) {
          const errText = await res.text();
          setDavAuthed(false);
          setDavAuthError(errText || 'Invalid WebDAV username or password');
          return false;
        }
        if (!res.ok && res.status !== 207) {
          const errText = await res.text();
          setDavAuthError(errText || `WebDAV Error (${res.status})`);
          return false;
        }

        const xml = await res.text();
        const parsed = parseWebdavPropfindXml(xml, href);
        setDavEntries(parsed);
        setDavAuthed(true);
        return true;
      } catch (err: any) {
        setDavAuthError(err.message || 'Failed to connect to WebDAV server');
        return false;
      } finally {
        setDavLoading(false);
      }
    },
    [davSubPath, fetchWebdav]
  );

  useEffect(() => {
    if (activeTab === 'webdav_app' && davAuthed) {
      loadWebdavDirectory(davSubPath);
    }
  }, [activeTab, davAuthed, davSubPath, loadWebdavDirectory]);

  // Auth Submission: Register requires ONLY Username and Password.
  // Sign In requires TOTP only if 2FA has been enabled on the account.
  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authUsername.trim() || !authPassword) return;
    if (authStatus?.hasAccount && authStatus.totpEnabled && !authTotpCode.trim()) {
      setAuthError('Please enter your 6-digit TOTP code');
      return;
    }

    setAuthSubmitting(true);
    setAuthError(null);

    const isSetup = !authStatus?.hasAccount;
    const endpoint = isSetup ? '/api/auth/setup' : '/api/auth/login';
    try {
      const payload: any = {
        username: authUsername.trim(),
        password: authPassword,
      };
      if (!isSetup && authStatus?.totpEnabled) {
        payload.totpCode = authTotpCode.trim();
      }

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setAuthError(data.error || 'Authentication failed');
      } else {
        localStorage.setItem('vaultdav_token', data.token);
        setSessionToken(data.token);
        setAuthPassword('');
        setAuthTotpCode('');
      }
    } catch (err: any) {
      setAuthError(err.message || 'Network error');
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleLogout = async () => {
    await apiFetch('/api/auth/logout', { method: 'POST' });
    localStorage.removeItem('vaultdav_token');
    setSessionToken('');
    setState(null);
    setDavAuthed(false);
    setDavLoginPass('');
    setShowAccountModal(false);
    setAuthStatus((prev) => (prev ? { ...prev, authenticated: false, username: null } : null));
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1600);
  };

  // Auto-generate safe WebDAV password on the main app
  const handleRegenerateWebdavCredentials = async () => {
    setRegeneratingCreds(true);
    try {
      const res = await apiFetch('/api/webdav-credentials/regenerate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        setDavLoginUser(data.webdavCredentials.username);
        setDavLoginPass(data.webdavCredentials.password);
        await checkAuthAndLoad();
      }
    } finally {
      setRegeneratingCreds(false);
    }
  };

  const handleSaveWebdavHost = async (e: React.FormEvent) => {
    e.preventDefault();
    setSavingHost(true);
    try {
      const res = await apiFetch('/api/webdav-host', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domainOrIp: hostInput.trim(),
          webAppPort: portInput.trim() || '8080',
          port: portInput.trim() || '8080',
        }),
      });
      if (res.ok) {
        await checkAuthAndLoad();
      }
    } finally {
      setSavingHost(false);
    }
  };

  // Download ready-to-run Docker Compose ZIP file
  const handleDownloadDockerZip = async () => {
    setDownloadingZip(true);
    try {
      const res = await apiFetch('/api/docker/download-zip');
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'vaultdav-docker-compose.zip';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);
      }
    } finally {
      setDownloadingZip(false);
    }
  };

  // =========================================================================
  // ACCOUNT & SECURITY (TOTP 2FA MANAGEMENT)
  // =========================================================================
  const handleStartSetup2FA = async () => {
    setSetup2faLoading(true);
    setSetup2faError(null);
    setSetup2faSuccess(null);
    setSetup2faVerifyCode('');
    try {
      const res = await apiFetch('/api/account/2fa/prepare', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setSetup2faSecret(data.secret);
        setSetup2faQrSvg(data.qrSvg);
      } else {
        setSetup2faError('Failed to prepare TOTP setup');
      }
    } catch (err: any) {
      setSetup2faError(err.message || 'Network error');
    } finally {
      setSetup2faLoading(false);
    }
  };

  const handleActivate2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!setup2faVerifyCode.trim() || !setup2faSecret) return;
    setSetup2faLoading(true);
    setSetup2faError(null);
    setSetup2faSuccess(null);
    try {
      const res = await apiFetch('/api/account/2fa/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret: setup2faSecret,
          code: setup2faVerifyCode.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setSetup2faError(data.error || 'Failed to activate 2FA');
      } else {
        setSetup2faSuccess('Two-Factor Authentication is now active on your account!');
        setSetup2faSecret('');
        setSetup2faQrSvg('');
        setSetup2faVerifyCode('');
        await checkAuthAndLoad();
      }
    } catch (err: any) {
      setSetup2faError(err.message || 'Network error');
    } finally {
      setSetup2faLoading(false);
    }
  };

  const handleDisable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!disable2faPassword) return;
    setSetup2faLoading(true);
    setSetup2faError(null);
    setSetup2faSuccess(null);
    try {
      const res = await apiFetch('/api/account/2fa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: disable2faPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setSetup2faError(data.error || 'Failed to disable 2FA');
      } else {
        setSetup2faSuccess('Two-Factor Authentication has been disabled.');
        setShowDisable2faForm(false);
        setDisable2faPassword('');
        await checkAuthAndLoad();
      }
    } catch (err: any) {
      setSetup2faError(err.message || 'Network error');
    } finally {
      setSetup2faLoading(false);
    }
  };

  // =========================================================================
  // HOST FOLDERS (.ENV) & INLINE FOLDER BROWSER ACTIONS
  // =========================================================================
  const handleToggleFolder = async (
    folder: EnvFolderMount,
    field: 'exposed' | 'syncthing_enabled'
  ) => {
    await apiFetch(`/api/folders/${folder.slug}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [field]: !folder[field] }),
    });
    await checkAuthAndLoad();
  };

  const handleAddFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSlug.trim()) return;
    const res = await apiFetch('/api/folders', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        slug: newSlug.trim(),
        host_path: newHostPath.trim(),
      }),
    });
    if (res.ok) {
      setNewSlug('');
      setNewHostPath('');
      await checkAuthAndLoad();
    }
  };

  const handleCreateHostDirectoryInBrowser = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHostDirName.trim() || !hostBrowserData) return;
    const res = await apiFetch('/api/host-browser/mkdir', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        parentPath: hostBrowserData.relativePath,
        name: newHostDirName.trim(),
      }),
    });
    if (res.ok) {
      const created = await res.json();
      setNewHostDirName('');
      await loadHostBrowser(hostBrowserData.relativePath);
      if (created.relativePath) {
        setNewHostPath(created.relativePath);
        if (!newSlug.trim() && created.name) {
          setNewSlug(String(created.name).toUpperCase().replace(/[^A-Z0-9_]/g, '_'));
        }
      }
    }
  };

  const handleDeleteFolder = async (slug: string) => {
    await apiFetch(`/api/folders/${slug}`, { method: 'DELETE' });
    await checkAuthAndLoad();
  };

  // =========================================================================
  // REAL WEBDAV FILE MANAGER APP ACTIONS
  // =========================================================================
  const handleWebdavLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    await loadWebdavDirectory(davSubPath, davLoginUser, davLoginPass);
  };

  const buildDavTargetUrl = (itemName?: string, isDir = false) => {
    const cleanSub = davSubPath.replace(/^\/+|\/+$/g, '');
    const parts = cleanSub ? cleanSub.split('/').filter(Boolean) : [];
    if (itemName) parts.push(itemName);
    const encoded = parts.map((p) => encodeURIComponent(p)).join('/');
    return `/dav/${encoded}${isDir && encoded ? '/' : ''}`;
  };

  const handleOpenDavEntry = async (entry: WebdavEntry) => {
    if (entry.isDirectory) {
      const nextSub = davSubPath ? `${davSubPath}/${entry.name}` : entry.name;
      setSelectedFile(null);
      setDavSubPath(nextSub);
      return;
    }

    const res = await fetchWebdav(buildDavTargetUrl(entry.name), 'GET');
    if (res.ok) {
      const contentType = (res.headers.get('content-type') || '').toLowerCase();
      const isTextLike =
        contentType.startsWith('text/') ||
        contentType.includes('json') ||
        contentType.includes('xml') ||
        contentType.includes('yaml') ||
        contentType.includes('javascript') ||
        /\.(txt|md|json|xml|yml|yaml|csv|html|css|js|ts|tsx|env|conf|ini|sh)$/i.test(entry.name);

      if (isTextLike) {
        const content = await res.text();
        setSelectedFile({ name: entry.name, content });
      } else {
        // Binary file: trigger direct binary download without UTF-8 text corruption
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = entry.name;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 10000);
      }
    }
  };

  const handleSaveDavFile = async () => {
    if (!selectedFile) return;
    const res = await fetchWebdav(
      buildDavTargetUrl(selectedFile.name),
      'PUT',
      selectedFile.content,
      undefined,
      undefined,
      'text/plain; charset=utf-8'
    );
    if (res.ok) {
      await loadWebdavDirectory();
      await checkAuthAndLoad();
    }
  };

  const handleCreateDavFile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDavFileName.trim()) return;
    const fileName = newDavFileName.trim();
    const initialContent = `# ${fileName}\n\n`;
    const res = await fetchWebdav(
      buildDavTargetUrl(fileName),
      'PUT',
      initialContent,
      undefined,
      undefined,
      'text/plain; charset=utf-8'
    );
    if (res.ok) {
      setNewDavFileName('');
      setCreatingFile(false);
      await loadWebdavDirectory();
      await checkAuthAndLoad();
      setSelectedFile({ name: fileName, content: initialContent });
    }
  };

  const handleCreateDavFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDavFolderName.trim()) return;
    const res = await fetchWebdav(buildDavTargetUrl(newDavFolderName.trim(), true), 'MKCOL');
    if (res.ok) {
      setNewDavFolderName('');
      setCreatingFolder(false);
      await loadWebdavDirectory();
      await checkAuthAndLoad();
    }
  };

  const handleDeleteDavEntry = async (entry: WebdavEntry) => {
    const res = await fetchWebdav(buildDavTargetUrl(entry.name, entry.isDirectory), 'DELETE');
    if (res.ok || res.status === 204) {
      if (selectedFile?.name === entry.name) {
        setSelectedFile(null);
      }
      await loadWebdavDirectory();
      await checkAuthAndLoad();
    }
  };

  const handleUploadDavFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const rawBuffer = await file.arrayBuffer();
    const res = await fetchWebdav(
      buildDavTargetUrl(file.name),
      'PUT',
      rawBuffer,
      undefined,
      undefined,
      file.type || 'application/octet-stream'
    );
    if (res.ok) {
      await loadWebdavDirectory();
      await checkAuthAndLoad();
    }
    e.target.value = '';
  };

  // =========================================================================
  // SIMPLE CUSTOM HTTP HEADERS (FOR WEBDAV ONLY)
  // =========================================================================
  const handleAddCustomHeader = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!headerName.trim() || !headerValue.trim()) return;
    const res = await apiFetch('/api/headers', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        header_name: headerName.trim(),
        header_value: headerValue.trim(),
      }),
    });
    if (res.ok) {
      setHeaderName('');
      setHeaderValue('');
      await checkAuthAndLoad();
      if (davAuthed) {
        await loadWebdavDirectory();
      }
    }
  };

  const handleToggleHeader = async (index: number, header: WebdavCustomHeader) => {
    await apiFetch(`/api/headers/${index}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !header.enabled }),
    });
    await checkAuthAndLoad();
    if (davAuthed) {
      await loadWebdavDirectory();
    }
  };

  const handleDeleteHeader = async (index: number) => {
    await apiFetch(`/api/headers/${index}`, { method: 'DELETE' });
    await checkAuthAndLoad();
    if (davAuthed) {
      await loadWebdavDirectory();
    }
  };

  const handleDownloadSingleFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#050507] text-zinc-100 flex items-center justify-center">
        <div className="text-sm font-mono text-zinc-400">Loading...</div>
      </div>
    );
  }

  // =========================================================================
  // LOGIN OR INITIAL ACCOUNT CREATION SCREEN
  // Registration requires ONLY Username & Password (TOTP 2FA can be added later)
  // =========================================================================
  if (!authStatus?.authenticated || !state) {
    const isSetupMode = !authStatus?.hasAccount;
    return (
      <div className="min-h-screen bg-[#050507] text-zinc-100 flex items-center justify-center p-6">
        <div className="max-w-sm w-full bg-[#0c0d10] border border-zinc-800/80 rounded-lg p-6 space-y-5">
          <div>
            <h1 className="text-xl font-bold tracking-tight text-zinc-100">
              {isSetupMode ? 'Create Single Account' : 'Sign In'}
            </h1>
            <p className="text-xs text-zinc-400 mt-1">
              {isSetupMode
                ? 'Choose a username and password to initialize VaultDAV. (2FA can be added later in account menu)'
                : 'Enter your credentials to access the VaultDAV dashboard.'}
            </p>
          </div>

          {authError && (
            <div className="p-3 bg-red-950/60 border border-red-800 rounded-md text-xs text-red-300">
              {authError}
            </div>
          )}

          <form onSubmit={handleAuthSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">Username</label>
              <input
                type="text"
                required
                autoFocus
                placeholder="admin"
                value={authUsername}
                onChange={(e) => setAuthUsername(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#050507] border border-zinc-800 rounded-md text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
              />
              {isSetupMode && (
                <p className="text-[11px] text-zinc-500 mt-1">
                  This username will also be used for your WebDAV mount access.
                </p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">Password</label>
              <input
                type="password"
                required
                placeholder="••••••••••••"
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono bg-[#050507] border border-zinc-800 rounded-md text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* TOTP 2FA input is ONLY displayed during Sign In if 2FA was enabled on the account */}
            {!isSetupMode && authStatus?.totpEnabled && (
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-medium text-zinc-300">
                    TOTP 2FA Code (6 digits)
                  </label>
                  <span className="text-[10px] text-blue-400 font-mono">2FA Active</span>
                </div>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  required
                  placeholder="000000"
                  value={authTotpCode}
                  onChange={(e) => setAuthTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="w-full px-3 py-2 text-xs font-mono tracking-widest bg-[#050507] border border-zinc-800 rounded-md text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500 tabular-nums"
                />
              </div>
            )}

            <button
              type="submit"
              disabled={authSubmitting}
              className="w-full py-2.5 px-4 text-xs font-semibold bg-blue-600 text-white rounded-md hover:bg-blue-500 transition-colors"
            >
              {authSubmitting
                ? 'Processing...'
                : isSetupMode
                ? 'Create Account'
                : 'Sign In'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  const getDockerFileDetails = (key: DockerFileKey) => {
    switch (key) {
      case 'compose':
        return { filename: 'docker-compose.yml', content: state.artifacts.composeContent };
      case 'env':
        return { filename: '.env', content: state.artifacts.envContent };
      case 'dockerfile':
        return { filename: 'Dockerfile', content: state.artifacts.dockerfileContent };
      case 'syncthing':
        return { filename: 'config.xml', content: state.artifacts.syncthingXmlContent };
    }
  };

  const activeDockerFile = getDockerFileDetails(selectedDockerFile);
  const exposedFolders = state.folders.filter((f) => f.exposed);

  const browserOrigin = typeof window !== 'undefined' ? window.location.origin : `http://${state.webdavHostConfig.detectedHost}`;
  const activeMountPath = '/dav/';
  const domainDavUrl = `${browserOrigin}${activeMountPath}`;
  const configuredHost = state.webdavHostConfig.domainOrIp || state.webdavHostConfig.detectedIp;
  const configuredPort = state.webdavHostConfig.webAppPort || state.webdavHostConfig.port || '8080';
  const ipOrCustomDomainDavUrl = configuredHost.startsWith('http')
    ? `${configuredHost.replace(/\/+$/, '')}/dav/`
    : `http://${configuredHost}:${configuredPort}/dav/`;

  const is2faActive = Boolean(state.account.totp_enabled);

  return (
    <div className="min-h-screen bg-[#050507] text-zinc-100 flex flex-col">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-8 py-4 bg-[#0c0d10] border-b border-zinc-800/80 sticky top-0 z-20">
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('folders');
          }}
          className="text-lg font-bold tracking-tight text-zinc-100 whitespace-nowrap shrink-0"
        >
          VaultDAV
        </a>

        <nav className="flex items-center gap-6 text-sm font-medium text-zinc-400 overflow-x-auto">
          <button
            onClick={() => setActiveTab('folders')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'folders'
                ? 'border-blue-500 text-zinc-100 font-semibold'
                : 'border-transparent hover:text-zinc-200'
            }`}
          >
            Host Folders (.env)
          </button>
          <button
            onClick={() => setActiveTab('webdav_app')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'webdav_app'
                ? 'border-blue-500 text-zinc-100 font-semibold'
                : 'border-transparent hover:text-zinc-200'
            }`}
          >
            WebDAV App
          </button>
          <button
            onClick={() => setActiveTab('syncthing_app')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'syncthing_app'
                ? 'border-blue-500 text-zinc-100 font-semibold'
                : 'border-transparent hover:text-zinc-200'
            }`}
          >
            Syncthing App
          </button>
          <button
            onClick={() => setActiveTab('docker')}
            className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
              activeTab === 'docker'
                ? 'border-blue-500 text-zinc-100 font-semibold'
                : 'border-transparent hover:text-zinc-200'
            }`}
          >
            Docker Compose Files
          </button>
        </nav>

        <div className="flex items-center shrink-0">
          <button
            onClick={handleDownloadDockerZip}
            disabled={downloadingZip}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 shadow-sm"
          >
            <Archive className="w-3.5 h-3.5" />
            {downloadingZip ? 'Creating ZIP...' : 'Download Docker Compose (.zip)'}
          </button>
        </div>
      </header>

      <main className="max-w-[1140px] w-full mx-auto px-8 py-6 space-y-6 flex-1">
        {/* Quick App Access & Account Bar */}
        <section className="bg-[#0c0d10] border border-zinc-800/80 rounded-lg px-5 py-3 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3 text-xs font-mono text-zinc-300">
            <span>Signed in as:</span>
            <strong className="text-zinc-100">{state.account.username}</strong>
            <button
              onClick={() => {
                setShowAccountModal(true);
                setSetup2faError(null);
                setSetup2faSuccess(null);
              }}
              className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-sans font-medium border transition-colors ${
                is2faActive
                  ? 'bg-blue-950/40 text-blue-300 border-blue-800 hover:bg-blue-900/40'
                  : 'bg-zinc-900 text-zinc-400 border-zinc-800 hover:text-zinc-200'
              }`}
            >
              {is2faActive ? (
                <>
                  <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
                  <span>2FA Active</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-3.5 h-3.5 text-zinc-500" />
                  <span>Add 2FA</span>
                </>
              )}
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              onClick={() => {
                setShowAccountModal(true);
                setSetup2faError(null);
                setSetup2faSuccess(null);
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md whitespace-nowrap"
            >
              <Shield className="w-3.5 h-3.5 text-blue-400" />
              Account &amp; 2FA Menu
            </button>

            <button
              onClick={() => setActiveTab('webdav_app')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap ${
                activeTab === 'webdav_app'
                  ? 'bg-blue-500 text-white'
                  : 'bg-blue-600 text-white hover:bg-blue-500'
              }`}
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Access WebDAV App
            </button>

            <button
              onClick={() => setActiveTab('syncthing_app')}
              className={`inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-md transition-colors whitespace-nowrap ${
                activeTab === 'syncthing_app'
                  ? 'bg-zinc-800 text-white border border-zinc-700'
                  : 'bg-zinc-900 text-zinc-200 hover:bg-zinc-800 border border-zinc-800'
              }`}
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Access Syncthing App
            </button>

            <button
              onClick={handleLogout}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md whitespace-nowrap"
            >
              <LogOut className="w-3.5 h-3.5" />
              Sign Out
            </button>
          </div>
        </section>

        {/* Modal: Account & Optional TOTP 2FA Management */}
        {showAccountModal && (
          <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
            <div className="bg-[#0c0d10] border border-zinc-800 rounded-lg max-w-md w-full p-6 space-y-5">
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-semibold text-zinc-100">
                    Account Security &amp; TOTP 2FA
                  </h3>
                </div>
                <button
                  onClick={() => setShowAccountModal(false)}
                  className="text-zinc-500 hover:text-white"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              {setup2faError && (
                <div className="p-3 bg-red-950/60 border border-red-800 rounded text-xs text-red-300">
                  {setup2faError}
                </div>
              )}

              {setup2faSuccess && (
                <div className="p-3 bg-blue-950/60 border border-blue-800 rounded text-xs text-blue-300">
                  {setup2faSuccess}
                </div>
              )}

              {/* Account Info */}
              <div className="space-y-2 p-3 bg-[#050507] border border-zinc-800 rounded-md text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Account Username:</span>
                  <span className="text-zinc-100 font-bold">{state.account.username}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">2FA Status:</span>
                  <span className={is2faActive ? 'text-blue-400 font-bold' : 'text-zinc-400'}>
                    {is2faActive ? 'Enabled (Active)' : 'Disabled (Optional)'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Credential Store:</span>
                  <span className="text-zinc-300">SQLite (AES-256-GCM)</span>
                </div>
              </div>

              {/* If 2FA is currently NOT active: option to setup */}
              {!is2faActive && !setup2faSecret && (
                <div className="space-y-3">
                  <p className="text-xs text-zinc-400 leading-relaxed">
                    Protect your account with Two-Factor Authentication (TOTP RFC 6238). When enabled, signing in will require a 6-digit code from Google Authenticator, 1Password, or Authy.
                  </p>
                  <button
                    type="button"
                    disabled={setup2faLoading}
                    onClick={handleStartSetup2FA}
                    className="w-full py-2 px-4 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-md transition-colors"
                  >
                    {setup2faLoading ? 'Generating Secret...' : 'Set Up TOTP 2FA Now'}
                  </button>
                </div>
              )}

              {/* Active 2FA Setup Flow with QR Code & Base32 secret */}
              {!is2faActive && setup2faSecret && (
                <form onSubmit={handleActivate2FA} className="space-y-4">
                  <div className="p-3 bg-[#050507] border border-zinc-800 rounded-md space-y-3">
                    <div className="text-xs font-medium text-zinc-300 text-center">
                      1. Scan with Authenticator App
                    </div>
                    {setup2faQrSvg && (
                      <div
                        className="w-36 h-36 mx-auto p-2 bg-[#050507] border border-zinc-800 rounded flex items-center justify-center [&>svg]:w-full [&>svg]:h-full"
                        dangerouslySetInnerHTML={{ __html: setup2faQrSvg }}
                      />
                    )}
                    <div className="space-y-1">
                      <div className="text-[11px] text-zinc-500">TOTP Secret Key (Base32)</div>
                      <div className="flex items-center justify-between gap-2 px-2.5 py-1.5 bg-[#0c0d10] border border-zinc-800 rounded text-xs font-mono text-blue-400">
                        <span className="truncate">{setup2faSecret}</span>
                        <button
                          type="button"
                          onClick={() => handleCopy('account-totp-secret', setup2faSecret)}
                          className="text-zinc-400 hover:text-white shrink-0"
                          title="Copy TOTP Secret"
                        >
                          {copiedId === 'account-totp-secret' ? (
                            <Check className="w-3.5 h-3.5 text-blue-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-zinc-300 mb-1">
                      2. Enter 6-digit verification code
                    </label>
                    <input
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]{6}"
                      maxLength={6}
                      required
                      autoFocus
                      placeholder="000000"
                      value={setup2faVerifyCode}
                      onChange={(e) =>
                        setSetup2faVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))
                      }
                      className="w-full px-3 py-2 text-xs font-mono tracking-widest bg-[#050507] border border-zinc-800 rounded text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500 tabular-nums"
                    />
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setSetup2faSecret('');
                        setSetup2faQrSvg('');
                      }}
                      className="w-1/3 py-2 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={setup2faLoading || setup2faVerifyCode.length !== 6}
                      className="flex-1 py-2 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded disabled:opacity-50"
                    >
                      {setup2faLoading ? 'Verifying...' : 'Verify & Enable 2FA'}
                    </button>
                  </div>
                </form>
              )}

              {/* If 2FA is currently ACTIVE: option to disable or reconfigure */}
              {is2faActive && (
                <div className="space-y-3">
                  {!showDisable2faForm ? (
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={handleStartSetup2FA}
                        className="flex-1 py-2 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded"
                      >
                        Reconfigure 2FA
                      </button>
                      <button
                        type="button"
                        onClick={() => setShowDisable2faForm(true)}
                        className="py-2 px-3 text-xs font-medium bg-red-950/40 hover:bg-red-900/40 text-red-300 border border-red-800/80 rounded"
                      >
                        Disable 2FA
                      </button>
                    </div>
                  ) : (
                    <form onSubmit={handleDisable2FA} className="space-y-3 p-3 bg-[#050507] border border-zinc-800 rounded-md">
                      <div className="text-xs font-medium text-zinc-300">
                        Confirm Account Password to Disable 2FA
                      </div>
                      <input
                        type="password"
                        required
                        autoFocus
                        placeholder="Account Password"
                        value={disable2faPassword}
                        onChange={(e) => setDisable2faPassword(e.target.value)}
                        className="w-full px-3 py-2 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100 focus:outline-none focus:border-red-500"
                      />
                      <div className="flex gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            setShowDisable2faForm(false);
                            setDisable2faPassword('');
                          }}
                          className="w-1/2 py-1.5 text-xs font-medium bg-zinc-900 text-zinc-300 rounded border border-zinc-800"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={setup2faLoading || !disable2faPassword}
                          className="w-1/2 py-1.5 text-xs font-semibold bg-red-600 hover:bg-red-500 text-white rounded"
                        >
                          {setup2faLoading ? 'Disabling...' : 'Confirm Disable'}
                        </button>
                      </div>
                    </form>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Auto-Generated Safe WebDAV Credentials & Domain/IP Endpoint Card on Main App */}
        <section className="bg-[#0c0d10] border border-zinc-800/80 rounded-lg p-5 space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Safe WebDAV Credentials (Strictly same username as login, saved on SQLite) */}
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-semibold text-zinc-100">
                    WebDAV Credentials (Saved in SQLite)
                  </h3>
                </div>
                <button
                  type="button"
                  disabled={regeneratingCreds}
                  onClick={handleRegenerateWebdavCredentials}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded-md hover:bg-blue-500 transition-colors shrink-0"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${regeneratingCreds ? 'animate-spin' : ''}`} />
                  Auto-Generate Safe Password
                </button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* WebDAV Username (Same as Login Username) */}
                <div className="p-2.5 bg-[#050507] border border-zinc-800 rounded-md space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-zinc-500">
                    <span>WebDAV Username</span>
                    <span className="text-[10px] text-blue-400/90 font-mono">Same as Login</span>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono font-bold text-zinc-100 truncate">
                      {state.account.username}
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy('dav-user', state.account.username)}
                      className="text-zinc-400 hover:text-white shrink-0"
                      title="Copy WebDAV Username"
                    >
                      {copiedId === 'dav-user' ? (
                        <Check className="w-3.5 h-3.5 text-blue-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Safe Auto-Generated WebDAV Password */}
                <div className="p-2.5 bg-[#050507] border border-zinc-800 rounded-md space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-zinc-500">
                    <span>Safe Password (24 chars)</span>
                    <button
                      type="button"
                      onClick={() => setShowSafePassword((v) => !v)}
                      className="text-zinc-400 hover:text-zinc-200 inline-flex items-center gap-1"
                    >
                      {showSafePassword ? (
                        <EyeOff className="w-3 h-3" />
                      ) : (
                        <Eye className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-blue-400 truncate select-all">
                      {showSafePassword
                        ? state.webdavCredentials.password
                        : '••••••••••••••••••••••••'}
                    </span>
                    <button
                      type="button"
                      onClick={() => handleCopy('dav-pass', state.webdavCredentials.password)}
                      className="text-zinc-400 hover:text-white shrink-0"
                      title="Copy Safe WebDAV Password"
                    >
                      {copiedId === 'dav-pass' ? (
                        <Check className="w-3.5 h-3.5 text-blue-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
              </div>

              <div className="text-[11px] text-zinc-500 font-mono flex items-center gap-1.5 pt-0.5">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500 inline-block"></span>
                <span>Stored in SQLite (<code>data/db/vaultdav.sqlite</code>) with AES-256-GCM encryption.</span>
              </div>
            </div>

            {/* Right: Domain Name & IP Address WebDAV Access */}
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-semibold text-zinc-100">
                    WebDAV Domain Name &amp; IP Address Access
                  </h3>
                </div>
                <a
                  href={activeMountPath}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs font-mono text-blue-400 hover:underline"
                >
                  Open {activeMountPath}
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2 px-3 py-1.5 bg-[#050507] border border-zinc-800 rounded-md text-xs font-mono">
                  <span className="text-zinc-400 shrink-0">Domain URL:</span>
                  <span className="text-zinc-100 truncate flex-1">{domainDavUrl}</span>
                  <button
                    type="button"
                    onClick={() => handleCopy('dav-domain-url', domainDavUrl)}
                    className="text-zinc-400 hover:text-white shrink-0"
                    title="Copy Domain WebDAV URL"
                  >
                    {copiedId === 'dav-domain-url' ? (
                      <Check className="w-3.5 h-3.5 text-blue-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>

                <form onSubmit={handleSaveWebdavHost} className="flex flex-wrap items-center gap-2">
                  <div className="flex-1 min-w-[200px]">
                    <label className="block text-[10px] text-zinc-500 font-mono mb-1">HOST / IP</label>
                    <input
                      type="text"
                      placeholder="e.g. 192.168.1.50 or dav.example.com"
                      value={hostInput}
                      onChange={(e) => setHostInput(e.target.value)}
                      className="w-full px-2.5 py-1.5 text-xs font-mono bg-[#050507] border border-zinc-800 rounded-md text-zinc-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div className="w-28">
                    <label className="block text-[10px] text-zinc-500 font-mono mb-1">PORT</label>
                    <input
                      type="text"
                      placeholder="8080"
                      value={portInput}
                      onChange={(e) => setPortInput(e.target.value)}
                      className="w-full px-2.5 py-1.5 text-xs font-mono bg-[#050507] border border-zinc-800 rounded-md text-zinc-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div className="flex items-end gap-2 pt-4">
                    <button
                      type="submit"
                      disabled={savingHost}
                      className="px-3 py-1.5 text-xs font-semibold bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md shrink-0"
                    >
                      {savingHost ? 'Saving...' : 'Save Host & Port'}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy('dav-ip-url', ipOrCustomDomainDavUrl)}
                      className="px-2.5 py-1.5 text-xs font-mono bg-zinc-900 hover:bg-zinc-800 text-blue-400 border border-zinc-800 rounded-md shrink-0 inline-flex items-center gap-1"
                      title={ipOrCustomDomainDavUrl}
                    >
                      {copiedId === 'dav-ip-url' ? (
                        <Check className="w-3.5 h-3.5 text-blue-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                      Copy WebDAV URL
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </div>
        </section>

        {/* ===================================================================
            TAB 1: HOST FOLDERS (.ENV) WITH SMALL FOLDER PICKER ON ADD FORM
           =================================================================== */}
        {activeTab === 'folders' && (
          <section className="bg-[#0c0d10] border border-zinc-800/80 rounded-lg p-6 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-zinc-800/80">
              <div>
                <h2 className="text-base font-semibold text-zinc-100">
                  Host Volumes Folder (./host_volumes)
                </h2>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Only <code className="font-mono text-blue-400">./host_volumes</code> is exposed in <code className="font-mono">.env</code> &amp; <code className="font-mono">docker-compose.yml</code>. All subfolders and files live inside <code className="font-mono text-zinc-300">./host_volumes</code>.
                </p>
              </div>
              <div className="px-3 py-1.5 bg-[#050507] border border-zinc-800 rounded text-xs font-mono text-zinc-300 shrink-0">
                Mount: <span className="text-blue-400">./host_volumes → /var/webdav</span>
              </div>
            </div>

            <div className="divide-y divide-zinc-800/80">
              {state.folders.map((folder) => (
                <div
                  key={folder.slug}
                  className="py-3.5 first:pt-0 last:pb-0 flex items-center justify-between gap-4"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-zinc-100">{folder.slug}</span>
                      <span className="text-xs text-zinc-600">·</span>
                      <code className="text-xs font-mono text-zinc-400 truncate">
                        {folder.host_path} → {folder.container_path}
                      </code>
                    </div>
                    <div className="text-xs text-zinc-500 font-mono tabular-nums mt-0.5">
                      ./host_volumes/{folder.slug} ·{' '}
                      {folder.fileCount} file(s) ({formatBytes(folder.totalBytes)})
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => {
                        setDavSubPath(folder.slug.toLowerCase());
                        setActiveTab('webdav_app');
                      }}
                      className="px-3 py-1.5 text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white rounded-md transition-colors"
                    >
                      Open in WebDAV
                    </button>

                    <button
                      onClick={() => handleDeleteFolder(folder.slug.toLowerCase())}
                      className="p-1.5 text-zinc-500 hover:text-red-400 rounded-md"
                      title="Delete folder from ./host_volumes"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Create Folder inside ./host_volumes Form */}
            <div className="pt-4 border-t border-zinc-800/80 space-y-3">
              <form
                onSubmit={handleAddFolder}
                className="flex gap-2"
              >
                <input
                  type="text"
                  required
                  placeholder="New Folder Name inside ./host_volumes (e.g. my_files)"
                  value={newSlug}
                  onChange={(e) => setNewSlug(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs font-mono bg-[#050507] border border-zinc-800 rounded-md text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-blue-500"
                />
                <button
                  type="submit"
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 text-xs font-semibold bg-blue-600 text-white rounded-md hover:bg-blue-500 whitespace-nowrap shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Create Folder
                </button>
              </form>
            </div>
          </section>
        )}

        {/* ===================================================================
            TAB 2: REAL INTERACTIVE WEBDAV FILE MANAGER APP + SIMPLE CUSTOM HEADERS
           =================================================================== */}
        {activeTab === 'webdav_app' && (
          <section className="bg-[#0c0d10] border border-zinc-800/80 rounded-lg overflow-hidden">
            {/* WebDAV App Header Bar */}
            <div className="px-6 py-4 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-semibold text-zinc-100">
                  WebDAV File Manager (/dav/)
                </h2>
                <p className="text-xs font-mono text-zinc-400 mt-0.5">
                  Endpoint: <span className="text-blue-400">{domainDavUrl}</span> ·{' '}
                  <span className="text-zinc-300">{ipOrCustomDomainDavUrl}</span>
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowDavHeadersPanel((v) => !v)}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                    showDavHeadersPanel
                      ? 'bg-blue-600/20 text-blue-300 border-blue-500/50'
                      : 'bg-zinc-900 text-zinc-200 border-zinc-800 hover:bg-zinc-800'
                  }`}
                >
                  <Sliders className="w-3.5 h-3.5" />
                  Custom Headers ({state.customHeaders.filter((h) => h.enabled).length})
                </button>
              </div>
            </div>

            {/* Simple Collapsible Custom HTTP Headers Bar (Strictly for WebDAV Features) */}
            {showDavHeadersPanel && (
              <div className="px-6 py-4 bg-[#07080a] border-b border-zinc-800/80 space-y-4">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Server Response Custom Headers (.env) */}
                  <div className="space-y-2.5">
                    <div className="text-xs font-semibold text-zinc-200">
                      WebDAV Response Headers (.env)
                    </div>
                    {state.customHeaders.length > 0 && (
                      <div className="space-y-1.5">
                        {state.customHeaders.map((hdr, idx) => (
                          <div
                            key={`${hdr.header_name}-${idx}`}
                            className="flex items-center justify-between gap-2 px-3 py-1.5 bg-[#0c0d10] border border-zinc-800 rounded text-xs font-mono"
                          >
                            <div className="truncate">
                              <span className="text-zinc-200">{hdr.header_name}: </span>
                              <span className="text-blue-400">{hdr.header_value}</span>
                            </div>
                            <div className="flex items-center gap-1.5 shrink-0">
                              <button
                                onClick={() => handleToggleHeader(idx, hdr)}
                                className={`px-2 py-0.5 text-[11px] rounded ${
                                  hdr.enabled
                                    ? 'bg-blue-600 text-white font-semibold'
                                    : 'bg-zinc-900 text-zinc-400 border border-zinc-800'
                                }`}
                              >
                                {hdr.enabled ? 'On' : 'Off'}
                              </button>
                              <button
                                onClick={() => handleDeleteHeader(idx)}
                                className="text-zinc-500 hover:text-red-400"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    <form onSubmit={handleAddCustomHeader} className="flex gap-2">
                      <input
                        type="text"
                        required
                        placeholder="Header Name"
                        value={headerName}
                        onChange={(e) => setHeaderName(e.target.value)}
                        className="w-1/2 px-2.5 py-1.5 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100"
                      />
                      <input
                        type="text"
                        required
                        placeholder="Header Value"
                        value={headerValue}
                        onChange={(e) => setHeaderValue(e.target.value)}
                        className="flex-1 px-2.5 py-1.5 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100"
                      />
                      <button
                        type="submit"
                        className="px-3 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-500 shrink-0"
                      >
                        Add
                      </button>
                    </form>
                  </div>

                  {/* Client Request Header & Live WebDAV Response Header Inspector */}
                  <div className="space-y-2.5">
                    <div className="text-xs font-semibold text-zinc-200">
                      Client Request Header &amp; Last Response Headers
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder="Request Header (e.g. X-Client-ID)"
                        value={clientHeaderName}
                        onChange={(e) => setClientHeaderName(e.target.value)}
                        className="w-1/2 px-2.5 py-1.5 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100"
                      />
                      <input
                        type="text"
                        placeholder="Request Value"
                        value={clientHeaderValue}
                        onChange={(e) => setClientHeaderValue(e.target.value)}
                        className="w-1/2 px-2.5 py-1.5 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100"
                      />
                    </div>
                    <div className="p-2.5 bg-[#0c0d10] border border-zinc-800 rounded text-[11px] font-mono text-zinc-400 max-h-28 overflow-y-auto space-y-0.5">
                      {Object.keys(davLastHeaders).length === 0 ? (
                        <div>Perform any WebDAV action to view response headers.</div>
                      ) : (
                        Object.entries(davLastHeaders).map(([k, v]) => (
                          <div key={k}>
                            <span className="text-zinc-300">{k}:</span>{' '}
                            <span className="text-blue-400">{v}</span>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* WebDAV Basic Auth Login Prompt (Username is same as login, password is safe auto-generated password) */}
            {!davAuthed ? (
              <div className="p-8 flex justify-center">
                <form
                  onSubmit={handleWebdavLogin}
                  className="max-w-sm w-full bg-[#050507] border border-zinc-800 rounded-lg p-6 space-y-4"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-base font-semibold text-zinc-100">
                      Sign In to WebDAV
                    </h3>
                    <button
                      type="button"
                      onClick={() => {
                        setDavLoginUser(state.account.username);
                        setDavLoginPass(state.webdavCredentials.password);
                      }}
                      className="text-xs font-mono text-blue-400 hover:underline"
                    >
                      Use SQLite Credentials
                    </button>
                  </div>

                  {davAuthError && (
                    <div className="p-2.5 bg-red-950/60 border border-red-800 rounded text-xs text-red-300">
                      {davAuthError}
                    </div>
                  )}

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="text-xs text-zinc-300">WebDAV Username</label>
                      <span className="text-[10px] text-blue-400 font-mono">Same as Login</span>
                    </div>
                    <input
                      type="text"
                      required
                      value={davLoginUser}
                      onChange={(e) => setDavLoginUser(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-zinc-300 mb-1">
                      WebDAV Safe Password
                    </label>
                    <input
                      type="password"
                      required
                      autoFocus
                      placeholder="••••••••••••••••••••••••"
                      value={davLoginPass}
                      onChange={(e) => setDavLoginPass(e.target.value)}
                      className="w-full px-3 py-2 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    className="w-full py-2 px-4 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-500"
                  >
                    Connect to WebDAV
                  </button>
                </form>
              </div>
            ) : (
              /* Real Authenticated WebDAV File Manager UI */
              <div className="grid grid-cols-1 md:grid-cols-12 min-h-[480px]">
                {/* Left Sidebar: Host Volumes Subfolders */}
                <aside className="md:col-span-3 border-r border-zinc-800/80 bg-[#07080a] p-4 space-y-3">
                  <div className="text-xs font-mono uppercase tracking-wider text-zinc-500">
                    Host Volumes
                  </div>
                  <div className="space-y-1">
                    <button
                      onClick={() => {
                        setDavSubPath('');
                        setSelectedFile(null);
                      }}
                      className={`w-full px-3 py-2 rounded-md text-left text-xs font-mono flex items-center justify-between transition-colors ${
                        davSubPath === ''
                          ? 'bg-blue-600 text-white font-semibold'
                          : 'text-zinc-300 hover:bg-zinc-900'
                      }`}
                    >
                      <span className="truncate">📁 /dav/ (Root)</span>
                    </button>
                    {state.folders.map((f) => (
                      <button
                        key={f.slug}
                        onClick={() => {
                          setDavSubPath(f.slug.toLowerCase());
                          setSelectedFile(null);
                        }}
                        className={`w-full px-3 py-2 rounded-md text-left text-xs font-mono flex items-center justify-between transition-colors ${
                          davSubPath === f.slug.toLowerCase() || davSubPath.startsWith(f.slug.toLowerCase() + '/')
                            ? 'bg-blue-600/30 text-blue-300 border border-blue-500/40 font-semibold'
                            : 'text-zinc-400 hover:bg-zinc-900'
                        }`}
                      >
                        <span className="truncate">/{f.slug.toLowerCase()}/</span>
                        <span className="text-[11px] opacity-80">{f.fileCount}</span>
                      </button>
                    ))}
                  </div>
                </aside>

                {/* Right Main Area: WebDAV Directory Browser + File Editor */}
                <div className="md:col-span-9 p-5 flex flex-col justify-between space-y-4">
                  <div className="space-y-4">
                    {/* Path Bar + File Operations Toolbar */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-zinc-800/80">
                      <div className="flex items-center gap-2 text-xs font-mono text-zinc-200">
                        {davSubPath && (
                          <button
                            onClick={() => {
                              const parts = davSubPath.split('/').filter(Boolean);
                              parts.pop();
                              setDavSubPath(parts.join('/'));
                              setSelectedFile(null);
                            }}
                            className="inline-flex items-center gap-1 px-2 py-1 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 rounded text-zinc-200"
                          >
                            <ArrowUp className="w-3.5 h-3.5" />
                            Up
                          </button>
                        )}
                        <span className="text-blue-400">
                          /dav/{davSubPath ? `${davSubPath}/` : ''}
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          onClick={() => {
                            setCreatingFile((v) => !v);
                            setCreatingFolder(false);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md"
                        >
                          <FilePlus className="w-3.5 h-3.5" />
                          New File
                        </button>

                        <button
                          onClick={() => {
                            setCreatingFolder((v) => !v);
                            setCreatingFile(false);
                          }}
                          className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md"
                        >
                          <FolderPlus className="w-3.5 h-3.5" />
                          New Folder
                        </button>

                        <label className="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md cursor-pointer">
                          <Upload className="w-3.5 h-3.5" />
                          Upload
                          <input
                            type="file"
                            onChange={handleUploadDavFile}
                            className="hidden"
                          />
                        </label>

                        <button
                          onClick={() => loadWebdavDirectory()}
                          className="p-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 rounded-md"
                          title="Refresh"
                        >
                          <RefreshCw className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>

                    {/* Inline Create File or Folder Input */}
                    {creatingFile && (
                      <form onSubmit={handleCreateDavFile} className="flex gap-2">
                        <input
                          type="text"
                          required
                          autoFocus
                          placeholder="New filename (e.g. notes.md)"
                          value={newDavFileName}
                          onChange={(e) => setNewDavFileName(e.target.value)}
                          className="flex-1 px-3 py-1.5 text-xs font-mono bg-[#050507] border border-zinc-800 rounded text-zinc-100"
                        />
                        <button
                          type="submit"
                          className="px-3 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-500"
                        >
                          Create
                        </button>
                      </form>
                    )}

                    {creatingFolder && (
                      <form onSubmit={handleCreateDavFolder} className="flex gap-2">
                        <input
                          type="text"
                          required
                          autoFocus
                          placeholder="New directory name"
                          value={newDavFolderName}
                          onChange={(e) => setNewDavFolderName(e.target.value)}
                          className="flex-1 px-3 py-1.5 text-xs font-mono bg-[#050507] border border-zinc-800 rounded text-zinc-100"
                        />
                        <button
                          type="submit"
                          className="px-3 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-500"
                        >
                          Create
                        </button>
                      </form>
                    )}

                    {/* WebDAV Directory Table */}
                    <div className="bg-[#050507] border border-zinc-800 rounded-lg divide-y divide-zinc-800/80">
                      {davLoading ? (
                        <div className="p-6 text-xs font-mono text-zinc-500">
                          Loading...
                        </div>
                      ) : davEntries.length === 0 ? (
                        <div className="p-6 text-xs font-mono text-zinc-500">
                          No files in this folder yet.
                        </div>
                      ) : (
                        davEntries.map((entry) => (
                          <div
                            key={entry.href}
                            className="px-4 py-2.5 flex items-center justify-between gap-4 hover:bg-zinc-900/60 transition-colors"
                          >
                            <button
                              onClick={() => handleOpenDavEntry(entry)}
                              className="flex items-center gap-2.5 min-w-0 text-left flex-1"
                            >
                              {entry.isDirectory ? (
                                <Folder className="w-4 h-4 text-blue-400 shrink-0" />
                              ) : (
                                <FileText className="w-4 h-4 text-zinc-400 shrink-0" />
                              )}
                              <span className="text-xs font-mono text-zinc-100 hover:text-blue-400 truncate">
                                {entry.name}
                                {entry.isDirectory ? '/' : ''}
                              </span>
                            </button>

                            <div className="flex items-center gap-4 shrink-0 text-xs font-mono text-zinc-500 tabular-nums">
                              {!entry.isDirectory && <span>{formatBytes(entry.size)}</span>}
                              <button
                                onClick={() => handleDeleteDavEntry(entry)}
                                className="text-zinc-500 hover:text-red-400"
                                title="Delete"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                        ))
                      )}
                    </div>

                    {/* Built-in File Editor (GET / PUT) */}
                    {selectedFile && (
                      <div className="p-4 bg-[#050507] border border-zinc-800 rounded-lg space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono font-semibold text-blue-400">
                            {selectedFile.name}
                          </span>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() =>
                                handleDownloadSingleFile(selectedFile.name, selectedFile.content)
                              }
                              className="px-2.5 py-1 text-xs font-mono bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded"
                            >
                              Download
                            </button>
                            <button
                              onClick={handleSaveDavFile}
                              className="inline-flex items-center gap-1 px-3 py-1 text-xs font-semibold bg-blue-600 text-white rounded hover:bg-blue-500"
                            >
                              <Save className="w-3.5 h-3.5" />
                              Save
                            </button>
                          </div>
                        </div>
                        <textarea
                          rows={5}
                          value={selectedFile.content}
                          onChange={(e) =>
                            setSelectedFile({ ...selectedFile, content: e.target.value })
                          }
                          className="w-full p-3 text-xs font-mono bg-[#0c0d10] border border-zinc-800 rounded text-zinc-100 focus:outline-none focus:border-blue-500"
                        />
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* ===================================================================
            TAB 3: NATIVE SYNCTHING APP (LIVE OFFICIAL BINARY ON :8384)
           =================================================================== */}
        {activeTab === 'syncthing_app' && (
          <section className="bg-[#0c0d10] border border-zinc-800/80 rounded-lg overflow-hidden">
            <div className="px-6 py-3.5 border-b border-zinc-800/80 flex items-center justify-between">
              <h2 className="text-base font-semibold text-zinc-100">
                Syncthing
              </h2>
              <button
                onClick={() => setActiveTab('folders')}
                className="px-3 py-1.5 text-xs font-medium bg-zinc-900 hover:bg-zinc-800 text-zinc-200 border border-zinc-800 rounded-md"
              >
                Host Folders (.env)
              </button>
            </div>
            <iframe
              src={state.syncthingUrl}
              title="Native Syncthing Web GUI"
              className="w-full h-[640px] border-0 bg-[#050507]"
            />
          </section>
        )}

        {/* ===================================================================
            TAB 4: DOCKER COMPOSE & READY-TO-RUN ZIP PACKAGE
           =================================================================== */}
        {activeTab === 'docker' && (
          <section className="bg-[#0c0d10] border border-zinc-800/80 rounded-lg p-6 space-y-5">
            {/* Download Docker ZIP Banner */}
            <div className="p-4 bg-[#050507] border border-zinc-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Archive className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-semibold text-zinc-100">
                    Ready-to-Run Docker Compose ZIP Archive
                  </h3>
                </div>
                <p className="text-xs text-zinc-400">
                  Includes pre-configured <code className="font-mono text-zinc-200">docker-compose.yml</code>, <code className="font-mono text-zinc-200">.env</code>, <code className="font-mono text-zinc-200">Dockerfile</code>, source code, and host volume structure.
                </p>
                <div className="text-[11px] font-mono text-zinc-500 pt-1">
                  Run command: <code className="text-blue-400">unzip vaultdav-docker-compose.zip && cd vaultdav-docker-compose && docker compose up -d</code>
                </div>
              </div>

              <button
                onClick={handleDownloadDockerZip}
                disabled={downloadingZip}
                className="inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0 shadow-sm"
              >
                <Download className="w-3.5 h-3.5" />
                {downloadingZip ? 'Generating ZIP...' : 'Download Docker ZIP'}
              </button>
            </div>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-3 border-b border-zinc-800/80">
              <div>
                <h2 className="text-sm font-semibold text-zinc-100">
                  Individual Compose Stack Files
                </h2>
              </div>

              <div className="flex flex-wrap items-center gap-1 p-1 bg-[#050507] border border-zinc-800 rounded-lg">
                <button
                  onClick={() => setSelectedDockerFile('compose')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedDockerFile === 'compose'
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  docker-compose.yml
                </button>
                <button
                  onClick={() => setSelectedDockerFile('env')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedDockerFile === 'env'
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  .env
                </button>
                <button
                  onClick={() => setSelectedDockerFile('dockerfile')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedDockerFile === 'dockerfile'
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Dockerfile
                </button>
                <button
                  onClick={() => setSelectedDockerFile('syncthing')}
                  className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors ${
                    selectedDockerFile === 'syncthing'
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  syncthing/config.xml
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between text-xs font-mono text-zinc-400">
              <span>File: {activeDockerFile.filename}</span>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleCopy('docker-file', activeDockerFile.content)}
                  className="inline-flex items-center gap-1.5 text-zinc-300 hover:text-white"
                >
                  {copiedId === 'docker-file' ? (
                    <Check className="w-3.5 h-3.5 text-blue-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5" />
                  )}
                  Copy
                </button>
                <button
                  onClick={() =>
                    handleDownloadSingleFile(
                      activeDockerFile.filename,
                      activeDockerFile.content
                    )
                  }
                  className="inline-flex items-center gap-1.5 text-blue-400 hover:text-blue-300"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download File
                </button>
              </div>
            </div>

            <pre className="p-4 bg-[#050507] border border-zinc-800 rounded-lg text-xs font-mono text-zinc-200 overflow-x-auto max-h-[480px] leading-relaxed">
              {activeDockerFile.content}
            </pre>
          </section>
        )}
      </main>
    </div>
  );
}
