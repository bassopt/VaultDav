export interface EnvFolderMount {
  slug: string;
  env_expose_key: string;
  env_host_key: string;
  env_container_key: string;
  host_path: string;
  container_path: string;
  exposed: boolean;
  syncthing_enabled: boolean;
  fileCount: number;
  totalBytes: number;
  files: string[];
}

export interface SingleAccountInfo {
  id: number;
  username: string;
  ciphertext_hex: string;
  iv_hex: string;
  auth_tag_hex: string;
  kdf_spec: string;
  created_at: string;
  last_used_at: string | null;
}

export interface AuthStatusResponse {
  hasAccount: boolean;
  authenticated: boolean;
  username: string | null;
}

export interface WebdavCustomHeader {
  header_name: string;
  header_value: string;
  enabled: boolean;
}

export interface StackArtifacts {
  envContent: string;
  composeContent: string;
  dockerfileContent: string;
  syncthingXmlContent: string;
}

export interface HostBrowserEntry {
  name: string;
  path: string;
  relativePath: string;
  isDirectory: boolean;
  size: number;
  alreadyExposedSlug: string | null;
}

export interface HostBrowserResponse {
  currentPath: string;
  relativePath: string;
  parentPath: string | null;
  entries: HostBrowserEntry[];
}

export interface WebdavEntry {
  href: string;
  name: string;
  isDirectory: boolean;
  size: number;
  lastModified: string;
}

export interface AppStateResponse {
  account: SingleAccountInfo;
  sqliteTables: string[];
  folders: EnvFolderMount[];
  customHeaders: WebdavCustomHeader[];
  syncthingUrl: string;
  webdavUrl: string;
  artifacts: StackArtifacts;
}
