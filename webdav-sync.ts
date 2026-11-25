/**
 * End-to-end encrypted, sharded WebDAV synchronization for AliasMode Local mode.
 *
 * Remote layout under the configured WebDAV base URL:
 *   <base>/manifest.json.enc       Encrypted index (profile hashes, timestamps, tombstones, proxy pool hash)
 *   <base>/proxy-pool.enc          Encrypted subscriptions + proxy pool nodes (incl. sing-box & chains)
 *   <base>/profiles/<id>.enc       Encrypted single-profile archive (profile metadata + portable session JSON)
 *
 * All payloads are gzip-compressed and encrypted client-side using
 * scrypt + AES-256-GCM before upload, so the WebDAV server (e.g. a personal VPS
 * running Caddy/Nginx/Docker WebDAV or any standard WebDAV provider) only ever
 * sees authenticated ciphertext.
 */

import { createCipheriv, createDecipheriv, createHash, randomBytes, scryptSync } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { dirname, join, resolve } from "node:path";
import { gunzipSync, gzipSync } from "node:zlib";
import { isSafeProfileId } from "./profile-id.ts";
import type { Profile, ProxyPoolNode, ProxySubscription } from "./types.ts";
import type { ProfileStore } from "./store.ts";

export interface WebDavSyncConfig {
  enabled: boolean;
  url: string;
  username: string;
  password: string;
  passphrase: string;
  deviceName: string;
  lastSyncAt: number;
  lastSyncMessage: string;
}

export interface WebDavSyncPublicConfig {
  enabled: boolean;
  configured: boolean;
  url: string;
  username: string;
  hasPassword: boolean;
  hasPassphrase: boolean;
  deviceName: string;
  lastSyncAt: number;
  lastSyncMessage: string;
}

export interface WebDavSyncConfigPatch {
  enabled?: boolean;
  url?: string;
  username?: string;
  password?: string;
  passphrase?: string;
  deviceName?: string;
  clearCredentials?: boolean;
}

export interface WebDavSyncState {
  version: 1;
  baseProfiles: Record<string, { hash: string; syncedAt: number; deleted?: boolean }>;
  baseProxyPoolHash: string;
}

export interface WebDavManifestProfileEntry {
  id: string;
  name: string;
  group: string;
  hash: string;
  updatedAt: number;
  deviceName: string;
  deletedAt?: number;
}

export interface WebDavManifest {
  version: 1;
  updatedAt: number;
  updatedBy: string;
  profiles: Record<string, WebDavManifestProfileEntry>;
  proxyPool?: {
    hash: string;
    updatedAt: number;
    deviceName: string;
    subscriptionCount: number;
    nodeCount: number;
  };
}

export interface WebDavSyncedProfileRecord {
  version: 1;
  profile: Profile;
  sessionBundle: string;
  updatedAt: number;
  deviceName: string;
}

export interface WebDavSyncedProxyPoolRecord {
  version: 1;
  subscriptions: ProxySubscription[];
  nodes: ProxyPoolNode[];
  updatedAt: number;
  deviceName: string;
}

export type SyncItemAction =
  | "push_create"
  | "push_update"
  | "push_delete"
  | "pull_create"
  | "pull_update"
  | "pull_delete"
  | "conflict"
  | "unchanged";

export interface SyncProfileDiffItem {
  id: string;
  name: string;
  group: string;
  action: SyncItemAction;
  localExists: boolean;
  remoteExists: boolean;
  remoteDeleted?: boolean;
  localOpen?: boolean;
  remoteName?: string;
  remoteUpdatedAt?: number;
  remoteDevice?: string;
}

export interface SyncProxyPoolDiff {
  action: "push" | "pull" | "conflict" | "unchanged";
  localSubscriptions: number;
  localNodes: number;
  remoteSubscriptions: number;
  remoteNodes: number;
  remoteUpdatedAt?: number;
  remoteDevice?: string;
}

export interface WebDavSyncPreview {
  ok: true;
  remoteInitialized: boolean;
  remoteUpdatedAt: number;
  remoteUpdatedBy: string;
  profiles: SyncProfileDiffItem[];
  proxyPool: SyncProxyPoolDiff;
  summary: {
    push: number;
    pull: number;
    conflicts: number;
    unchanged: number;
  };
}

export type SyncConflictChoice = "local" | "remote" | "skip";
export type WebDavSyncMode = "merge" | "push" | "pull";

export interface WebDavSyncRunResult {
  ok: true;
  mode: WebDavSyncMode;
  pushed: number;
  pulled: number;
  deletedLocal: number;
  deletedRemote: number;
  proxyPoolAction: "pushed" | "pulled" | "unchanged" | "skipped";
  skippedOpen: string[];
  unresolvedConflicts: string[];
  syncedAt: number;
  message: string;
}

export interface WebDavSyncDependencies {
  fetchFn?: typeof fetch;
  captureLiveSession?: (profileId: string) => Promise<boolean>;
  now?: () => number;
}

interface EncryptedEnvelope {
  v: 1;
  alg: "scrypt-aes-256-gcm-gzip";
  salt: string;
  iv: string;
  tag: string;
  data: string;
}

const DEFAULT_DEVICE_NAME = () => {
  try {
    return hostname().trim() || "AliasMode-PC";
  } catch {
    return "AliasMode-PC";
  }
};

export function defaultWebDavConfig(): WebDavSyncConfig {
  return {
    enabled: false,
    url: "",
    username: "",
    password: "",
    passphrase: "",
    deviceName: DEFAULT_DEVICE_NAME(),
    lastSyncAt: 0,
    lastSyncMessage: "",
  };
}

export function normalizeWebDavUrl(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("WebDAV URL is invalid (expected https://... or http://...)");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("WebDAV URL must start with https:// or http://");
  }
  if (parsed.username || parsed.password) {
    throw new Error("Put WebDAV credentials in the Username / Password fields instead of the URL");
  }
  return parsed.toString().replace(/\/+$/, "");
}

export function toPublicWebDavConfig(config: WebDavSyncConfig): WebDavSyncPublicConfig {
  return {
    enabled: config.enabled,
    configured: !!config.url && !!config.passphrase,
    url: config.url,
    username: config.username,
    hasPassword: !!config.password,
    hasPassphrase: !!config.passphrase,
    deviceName: config.deviceName || DEFAULT_DEVICE_NAME(),
    lastSyncAt: config.lastSyncAt,
    lastSyncMessage: config.lastSyncMessage,
  };
}

export function webDavConfigPath(stateRoot: string): string {
  return join(resolve(stateRoot), "webdav-sync.json");
}

export function webDavStatePath(stateRoot: string): string {
  return join(resolve(stateRoot), "webdav-sync-state.json");
}

function writeJsonAtomic(filePath: string, value: unknown): void {
  mkdirSync(dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  renameSync(tmp, filePath);
}

export function readWebDavConfig(stateRoot: string): WebDavSyncConfig {
  const filePath = webDavConfigPath(stateRoot);
  const fallback = defaultWebDavConfig();
  if (!existsSync(filePath)) return fallback;
  try {
    const raw = JSON.parse(readFileSync(filePath, "utf8")) as Record<string, unknown>;
    return {
      enabled: raw.enabled === true,
      url: typeof raw.url === "string" ? raw.url : "",
      username: typeof raw.username === "string" ? raw.username : "",
      password: typeof raw.password === "string" ? raw.password : "",
      passphrase: typeof raw.passphrase === "string" ? raw.passphrase : "",
      deviceName: typeof raw.deviceName === "string" && raw.deviceName.trim() ? raw.deviceName.trim() : fallback.deviceName,
      lastSyncAt: typeof raw.lastSyncAt === "number" && Number.isFinite(raw.lastSyncAt) ? raw.lastSyncAt : 0,
      lastSyncMessage: typeof raw.lastSyncMessage === "string" ? raw.lastSyncMessage : "",
    };
  } catch {
    return fallback;
  }
}

export function saveWebDavConfig(stateRoot: string, patch: WebDavSyncConfigPatch): WebDavSyncConfig {
  const current = readWebDavConfig(stateRoot);
  if (patch.clearCredentials) {
    const cleared: WebDavSyncConfig = {
      ...defaultWebDavConfig(),
      deviceName: current.deviceName,
    };
    writeJsonAtomic(webDavConfigPath(stateRoot), cleared);
    return cleared;
  }
  const url = patch.url !== undefined ? normalizeWebDavUrl(patch.url) : current.url;
  const username = patch.username !== undefined ? patch.username.trim() : current.username;
  const password = patch.password !== undefined && patch.password !== "" ? patch.password : current.password;
  const passphrase = patch.passphrase !== undefined && patch.passphrase !== "" ? patch.passphrase : current.passphrase;
  const deviceName = patch.deviceName !== undefined && patch.deviceName.trim()
    ? patch.deviceName.trim().slice(0, 64)
    : current.deviceName;
  const enabled = patch.enabled !== undefined ? patch.enabled : (!!url && !!passphrase);
  const next: WebDavSyncConfig = {
    ...current,
    enabled,
    url,
    username,
    password,
    passphrase,
    deviceName,
  };
  writeJsonAtomic(webDavConfigPath(stateRoot), next);
  return next;
}

function updateWebDavSyncStatus(stateRoot: string, lastSyncAt: number, lastSyncMessage: string): void {
  const current = readWebDavConfig(stateRoot);
  writeJsonAtomic(webDavConfigPath(stateRoot), {
    ...current,
    lastSyncAt,
    lastSyncMessage,
  });
}

export function readWebDavState(stateRoot: string): WebDavSyncState {
  const filePath = webDavStatePath(stateRoot);
  if (!existsSync(filePath)) return { version: 1, baseProfiles: {}, baseProxyPoolHash: "" };
  try {
    const raw = JSON.parse(readFileSync(filePath, "utf8")) as Partial<WebDavSyncState>;
    return {
      version: 1,
      baseProfiles: raw.baseProfiles && typeof raw.baseProfiles === "object" ? raw.baseProfiles : {},
      baseProxyPoolHash: typeof raw.baseProxyPoolHash === "string" ? raw.baseProxyPoolHash : "",
    };
  } catch {
    return { version: 1, baseProfiles: {}, baseProxyPoolHash: "" };
  }
}

export function saveWebDavState(stateRoot: string, state: WebDavSyncState): void {
  writeJsonAtomic(webDavStatePath(stateRoot), state);
}

/** Stable JSON serialization with sorted keys for deterministic hashing. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function computeProfileSyncHash(profile: Profile, sessionBundle: string): string {
  // Exclude volatile per-machine displayScale / fingerprint observation logs from conflict hashing
  // while keeping all identity, proxy, credential, cookie, and portable session fields.
  const { fpObserved: _o, fpExpected: _e, fpVerdict: _v, ...stableProfile } = profile;
  return createHash("sha256")
    .update(canonicalJson({ profile: stableProfile, sessionBundle }))
    .digest("hex");
}

export function computeProxyPoolSyncHash(
  subscriptions: readonly ProxySubscription[],
  nodes: readonly ProxyPoolNode[],
): string {
  const stableSubs = [...subscriptions]
    .map((s) => ({ id: s.id, name: s.name, url: s.url }))
    .sort((a, b) => a.id.localeCompare(b.id));
  const stableNodes = [...nodes]
    .map((n) => ({ id: n.id, name: n.name, subscriptionId: n.subscriptionId, proxy: n.proxy, tags: [...n.tags].sort() }))
    .sort((a, b) => a.id.localeCompare(b.id));
  return createHash("sha256")
    .update(canonicalJson({ subscriptions: stableSubs, nodes: stableNodes }))
    .digest("hex");
}

/** Compress and encrypt a JSON payload with scrypt + AES-256-GCM. */
export function encryptSyncPayload(value: unknown, passphrase: string): string {
  if (!passphrase || passphrase.length < 4) {
    throw new Error("Encryption passphrase must be at least 4 characters");
  }
  const plain = gzipSync(Buffer.from(JSON.stringify(value), "utf8"));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope: EncryptedEnvelope = {
    v: 1,
    alg: "scrypt-aes-256-gcm-gzip",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64"),
  };
  return JSON.stringify(envelope);
}

/** Decrypt and decompress an encrypted WebDAV payload. */
export function decryptSyncPayload<T>(rawText: string, passphrase: string): T {
  let envelope: Partial<EncryptedEnvelope>;
  try {
    envelope = JSON.parse(rawText) as Partial<EncryptedEnvelope>;
  } catch {
    throw new Error("Remote WebDAV file is not valid encrypted sync data");
  }
  if (
    envelope.v !== 1
    || envelope.alg !== "scrypt-aes-256-gcm-gzip"
    || typeof envelope.salt !== "string"
    || typeof envelope.iv !== "string"
    || typeof envelope.tag !== "string"
    || typeof envelope.data !== "string"
  ) {
    throw new Error("Unsupported WebDAV sync encryption format");
  }
  try {
    const salt = Buffer.from(envelope.salt, "base64");
    const iv = Buffer.from(envelope.iv, "base64");
    const tag = Buffer.from(envelope.tag, "base64");
    const ciphertext = Buffer.from(envelope.data, "base64");
    const key = scryptSync(passphrase, salt, 32, { N: 16384, r: 8, p: 1 });
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const gzipped = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return JSON.parse(gunzipSync(gzipped).toString("utf8")) as T;
  } catch {
    throw new Error("Failed to decrypt WebDAV sync data — check your encryption passphrase");
  }
}

export class WebDavClient {
  private readonly baseUrl: string;
  private readonly authHeader: string | null;
  private readonly fetchFn: typeof fetch;

  constructor(
    config: Pick<WebDavSyncConfig, "url" | "username" | "password">,
    fetchFn: typeof fetch = fetch,
  ) {
    this.baseUrl = normalizeWebDavUrl(config.url);
    if (!this.baseUrl) throw new Error("WebDAV URL is required");
    this.authHeader = config.username || config.password
      ? `Basic ${Buffer.from(`${config.username}:${config.password}`, "utf8").toString("base64")}`
      : null;
    this.fetchFn = fetchFn;
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      ...(this.authHeader ? { Authorization: this.authHeader } : {}),
      ...extra,
    };
  }

  private target(relPath = ""): string {
    const clean = relPath.replace(/^\/+/, "");
    return clean ? `${this.baseUrl}/${clean}` : `${this.baseUrl}/`;
  }

  async ensureCollection(relDir = ""): Promise<void> {
    const segments = relDir.split("/").filter(Boolean);
    let current = "";
    // First ensure the base sync collection exists (if missing, create it).
    const baseRes = await this.fetchFn(this.target(""), {
      method: "MKCOL",
      headers: this.headers(),
      signal: AbortSignal.timeout(15_000),
    });
    if (baseRes.status === 401 || baseRes.status === 403) {
      throw new Error(`WebDAV authentication failed (${baseRes.status})`);
    }
    for (const seg of segments) {
      current = current ? `${current}/${seg}` : seg;
      const res = await this.fetchFn(this.target(`${current}/`), {
        method: "MKCOL",
        headers: this.headers(),
        signal: AbortSignal.timeout(15_000),
      });
      if (res.status === 401 || res.status === 403) {
        throw new Error(`WebDAV authentication failed (${res.status})`);
      }
      // 201 Created, 200/204 OK, 405 Method Not Allowed (already exists), 301/302 redirect all mean ready.
      if (!res.ok && res.status !== 405 && res.status !== 301 && res.status !== 302 && res.status !== 409) {
        throw new Error(`WebDAV MKCOL ${current} failed (${res.status})`);
      }
    }
  }

  async probe(): Promise<{ status: number }> {
    const res = await this.fetchFn(this.target(""), {
      method: "PROPFIND",
      headers: this.headers({ Depth: "0" }),
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 401 || res.status === 403) {
      throw new Error(`WebDAV authentication failed (${res.status})`);
    }
    if (res.status === 404) {
      await this.ensureCollection("");
      return { status: 201 };
    }
    if (res.status === 405 || res.status === 501) {
      const opt = await this.fetchFn(this.target(""), {
        method: "OPTIONS",
        headers: this.headers(),
        signal: AbortSignal.timeout(15_000),
      });
      if (opt.status === 401 || opt.status === 403) {
        throw new Error(`WebDAV authentication failed (${opt.status})`);
      }
      if (!opt.ok) throw new Error(`WebDAV server returned ${opt.status}`);
      return { status: opt.status };
    }
    if (!res.ok && res.status !== 207) {
      throw new Error(`WebDAV connection failed (${res.status})`);
    }
    return { status: res.status };
  }

  async getText(relPath: string): Promise<string | null> {
    const res = await this.fetchFn(this.target(relPath), {
      method: "GET",
      headers: this.headers(),
      signal: AbortSignal.timeout(30_000),
    });
    if (res.status === 404) return null;
    if (res.status === 401 || res.status === 403) {
      throw new Error(`WebDAV authentication failed (${res.status})`);
    }
    if (!res.ok) throw new Error(`WebDAV GET ${relPath} failed (${res.status})`);
    return await res.text();
  }

  async putText(relPath: string, body: string): Promise<void> {
    const res = await this.fetchFn(this.target(relPath), {
      method: "PUT",
      headers: this.headers({ "Content-Type": "application/octet-stream" }),
      body,
      signal: AbortSignal.timeout(60_000),
    });
    if (res.status === 401 || res.status === 403) {
      throw new Error(`WebDAV authentication failed (${res.status})`);
    }
    if (!res.ok && res.status !== 201 && res.status !== 204) {
      throw new Error(`WebDAV PUT ${relPath} failed (${res.status})`);
    }
  }

  async deleteFile(relPath: string): Promise<void> {
    const res = await this.fetchFn(this.target(relPath), {
      method: "DELETE",
      headers: this.headers(),
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 404) return;
    if (res.status === 401 || res.status === 403) {
      throw new Error(`WebDAV authentication failed (${res.status})`);
    }
    if (!res.ok && res.status !== 204) {
      throw new Error(`WebDAV DELETE ${relPath} failed (${res.status})`);
    }
  }
}

function requireValidSyncConfig(config: WebDavSyncConfig): void {
  if (!config.url) throw new Error("WebDAV URL is not configured");
  if (!config.passphrase) throw new Error("Encryption passphrase is required");
}

async function fetchRemoteManifest(
  client: WebDavClient,
  passphrase: string,
): Promise<WebDavManifest | null> {
  const raw = await client.getText("manifest.json.enc");
  if (raw === null) return null;
  const manifest = decryptSyncPayload<WebDavManifest>(raw, passphrase);
  if (!manifest || manifest.version !== 1 || typeof manifest.profiles !== "object") {
    throw new Error("Remote WebDAV manifest is malformed");
  }
  return manifest;
}

export async function testWebDavConnection(
  config: WebDavSyncConfig,
  deps: WebDavSyncDependencies = {},
): Promise<{
  ok: true;
  remoteInitialized: boolean;
  profileCount: number;
  remoteUpdatedAt: number;
  remoteUpdatedBy: string;
}> {
  requireValidSyncConfig(config);
  const client = new WebDavClient(config, deps.fetchFn);
  await client.probe();
  const manifest = await fetchRemoteManifest(client, config.passphrase);
  if (!manifest) {
    return { ok: true, remoteInitialized: false, profileCount: 0, remoteUpdatedAt: 0, remoteUpdatedBy: "" };
  }
  const activeCount = Object.values(manifest.profiles).filter((entry) => !entry.deletedAt).length;
  return {
    ok: true,
    remoteInitialized: true,
    profileCount: activeCount,
    remoteUpdatedAt: manifest.updatedAt || 0,
    remoteUpdatedBy: manifest.updatedBy || "",
  };
}

async function captureOpenProfiles(
  store: ProfileStore,
  captureLiveSession?: (profileId: string) => Promise<boolean>,
): Promise<void> {
  if (!captureLiveSession) return;
  for (const launch of store.listLaunches()) {
    await captureLiveSession(launch.profileId).catch(() => {});
  }
}

export async function previewWebDavSync(
  stateRoot: string,
  store: ProfileStore,
  deps: WebDavSyncDependencies = {},
  options: { captureLive?: boolean; configOverride?: WebDavSyncConfig } = {},
): Promise<WebDavSyncPreview> {
  const config = options.configOverride ?? readWebDavConfig(stateRoot);
  requireValidSyncConfig(config);
  if (options.captureLive) {
    await captureOpenProfiles(store, deps.captureLiveSession);
  }
  const client = new WebDavClient(config, deps.fetchFn);
  await client.probe();
  const manifest = await fetchRemoteManifest(client, config.passphrase);
  const state = readWebDavState(stateRoot);

  const localProfiles = new Map<string, { profile: Profile; sessionBundle: string; hash: string }>();
  for (const profile of store.listProfiles()) {
    const sessionBundle = store.getSessionBundle(profile.id) ?? "";
    localProfiles.set(profile.id, {
      profile,
      sessionBundle,
      hash: computeProfileSyncHash(profile, sessionBundle),
    });
  }
  const openIds = new Set(store.listLaunches().map((l) => l.profileId));
  const remoteProfiles = manifest?.profiles ?? {};
  const allIds = new Set<string>([...localProfiles.keys(), ...Object.keys(remoteProfiles), ...Object.keys(state.baseProfiles)]);

  const items: SyncProfileDiffItem[] = [];
  for (const id of [...allIds].sort()) {
    if (!isSafeProfileId(id)) continue;
    const local = localProfiles.get(id);
    const remote = remoteProfiles[id];
    const base = state.baseProfiles[id];

    const localHash = local ? local.hash : "";
    const remoteActive = !!remote && !remote.deletedAt;
    const remoteHash = remoteActive ? remote.hash : "";
    const baseHash = base && !base.deleted ? base.hash : "";

    const localChanged = localHash !== baseHash;
    const remoteChanged = remoteHash !== baseHash;

    let action: SyncItemAction = "unchanged";
    if (!local && !remoteActive) {
      continue;
    } else if (local && !remoteActive) {
      if (!remote && !base) action = "push_create";
      else if (remote?.deletedAt && !localChanged) action = "pull_delete";
      else if (remote?.deletedAt && localChanged) action = "conflict";
      else if (base && !remote) action = localChanged ? "conflict" : "pull_delete";
      else action = "push_create";
    } else if (!local && remoteActive) {
      if (base && !base.deleted) {
        action = remoteChanged ? "conflict" : "push_delete";
      } else {
        action = "pull_create";
      }
    } else if (local && remoteActive) {
      if (localHash === remoteHash) action = "unchanged";
      else if (localChanged && !remoteChanged) action = "push_update";
      else if (!localChanged && remoteChanged) action = "pull_update";
      else action = "conflict";
    }

    items.push({
      id,
      name: local?.profile.name || remote?.name || id,
      group: local?.profile.group ?? remote?.group ?? "",
      action,
      localExists: !!local,
      remoteExists: remoteActive,
      ...(remote?.deletedAt ? { remoteDeleted: true } : {}),
      ...(openIds.has(id) ? { localOpen: true } : {}),
      ...(remote?.name ? { remoteName: remote.name } : {}),
      ...(remote?.updatedAt ? { remoteUpdatedAt: remote.updatedAt } : {}),
      ...(remote?.deviceName ? { remoteDevice: remote.deviceName } : {}),
    });
  }

  const localSubs = store.listProxySubscriptions();
  const localNodes = store.listProxyNodes();
  const localPoolEmpty = localSubs.length === 0 && localNodes.length === 0;
  const localPoolHash = localPoolEmpty ? "" : computeProxyPoolSyncHash(localSubs, localNodes);
  const remotePool = manifest?.proxyPool;
  const remotePoolHash = remotePool && (remotePool.subscriptionCount > 0 || remotePool.nodeCount > 0) ? remotePool.hash : "";
  const basePoolHash = state.baseProxyPoolHash;

  let poolAction: SyncProxyPoolDiff["action"] = "unchanged";
  if (localPoolHash === remotePoolHash) {
    poolAction = "unchanged";
  } else {
    const localPoolChanged = localPoolHash !== basePoolHash;
    const remotePoolChanged = remotePoolHash !== basePoolHash;
    if (localPoolChanged && !remotePoolChanged) poolAction = "push";
    else if (!localPoolChanged && remotePoolChanged) poolAction = "pull";
    else poolAction = "conflict";
  }

  const summary = {
    push: items.filter((i) => i.action.startsWith("push_")).length + (poolAction === "push" ? 1 : 0),
    pull: items.filter((i) => i.action.startsWith("pull_")).length + (poolAction === "pull" ? 1 : 0),
    conflicts: items.filter((i) => i.action === "conflict").length + (poolAction === "conflict" ? 1 : 0),
    unchanged: items.filter((i) => i.action === "unchanged").length,
  };

  return {
    ok: true,
    remoteInitialized: manifest !== null,
    remoteUpdatedAt: manifest?.updatedAt ?? 0,
    remoteUpdatedBy: manifest?.updatedBy ?? "",
    profiles: items,
    proxyPool: {
      action: poolAction,
      localSubscriptions: localSubs.length,
      localNodes: localNodes.length,
      remoteSubscriptions: remotePool?.subscriptionCount ?? 0,
      remoteNodes: remotePool?.nodeCount ?? 0,
      ...(remotePool?.updatedAt ? { remoteUpdatedAt: remotePool.updatedAt } : {}),
      ...(remotePool?.deviceName ? { remoteDevice: remotePool.deviceName } : {}),
    },
    summary,
  };
}

export async function executeWebDavSync(
  stateRoot: string,
  store: ProfileStore,
  options: {
    mode: WebDavSyncMode;
    resolutions?: Record<string, SyncConflictChoice>;
    proxyPoolResolution?: SyncConflictChoice;
    configOverride?: WebDavSyncConfig;
  },
  deps: WebDavSyncDependencies = {},
): Promise<WebDavSyncRunResult> {
  const config = options.configOverride ?? readWebDavConfig(stateRoot);
  requireValidSyncConfig(config);
  const now = deps.now ?? Date.now;
  const syncedAt = now();

  if (options.mode === "merge" || options.mode === "push") {
    await captureOpenProfiles(store, deps.captureLiveSession);
  }

  const client = new WebDavClient(config, deps.fetchFn);
  await client.ensureCollection("profiles");

  const existingManifest = await fetchRemoteManifest(client, config.passphrase);
  const manifest: WebDavManifest = existingManifest
    ? structuredClone(existingManifest)
    : { version: 1, updatedAt: 0, updatedBy: config.deviceName, profiles: {} };

  const preview = await previewWebDavSync(stateRoot, store, deps, { captureLive: false, configOverride: config });
  const state = readWebDavState(stateRoot);
  const resolutions = options.resolutions ?? {};
  const openIds = new Set(store.listLaunches().map((l) => l.profileId));

  let pushed = 0;
  let pulled = 0;
  let deletedLocal = 0;
  let deletedRemote = 0;
  let manifestDirty = !existingManifest;
  const skippedOpen: string[] = [];
  const unresolvedConflicts: string[] = [];

  for (const item of preview.profiles) {
    const id = item.id;
    let decision: "push" | "push_delete" | "pull" | "pull_delete" | "skip" = "skip";

    if (options.mode === "push") {
      if (item.localExists) {
        decision = item.action === "unchanged" ? "skip" : "push";
      } else if (item.remoteExists) {
        decision = "push_delete";
      }
    } else if (options.mode === "pull") {
      if (item.remoteExists) {
        decision = item.action === "unchanged" ? "skip" : "pull";
      } else if (item.localExists) {
        decision = "pull_delete";
      }
    } else {
      if (item.action === "push_create" || item.action === "push_update") decision = "push";
      else if (item.action === "push_delete") decision = "push_delete";
      else if (item.action === "pull_create" || item.action === "pull_update") decision = "pull";
      else if (item.action === "pull_delete") decision = "pull_delete";
      else if (item.action === "conflict") {
        const choice = resolutions[id] ?? "skip";
        if (choice === "local") decision = item.localExists ? "push" : "push_delete";
        else if (choice === "remote") decision = item.remoteExists ? "pull" : "pull_delete";
        else {
          unresolvedConflicts.push(id);
          decision = "skip";
        }
      } else if (item.action === "unchanged" && item.localExists) {
        const p = store.getProfile(id);
        if (p) {
          const h = computeProfileSyncHash(p, store.getSessionBundle(id) ?? "");
          state.baseProfiles[id] = { hash: h, syncedAt };
        }
      }
    }

    if (decision === "push") {
      const profile = store.getProfile(id);
      if (!profile) continue;
      const sessionBundle = store.getSessionBundle(id) ?? "";
      const hash = computeProfileSyncHash(profile, sessionBundle);
      const record: WebDavSyncedProfileRecord = {
        version: 1,
        profile,
        sessionBundle,
        updatedAt: syncedAt,
        deviceName: config.deviceName,
      };
      await client.putText(`profiles/${id}.enc`, encryptSyncPayload(record, config.passphrase));
      manifest.profiles[id] = {
        id,
        name: profile.name,
        group: profile.group,
        hash,
        updatedAt: syncedAt,
        deviceName: config.deviceName,
      };
      state.baseProfiles[id] = { hash, syncedAt };
      pushed++;
      manifestDirty = true;
    } else if (decision === "push_delete") {
      await client.deleteFile(`profiles/${id}.enc`);
      manifest.profiles[id] = {
        id,
        name: item.remoteName || item.name,
        group: item.group,
        hash: "",
        updatedAt: syncedAt,
        deviceName: config.deviceName,
        deletedAt: syncedAt,
      };
      state.baseProfiles[id] = { hash: "", syncedAt, deleted: true };
      deletedRemote++;
      manifestDirty = true;
    } else if (decision === "pull") {
      if (openIds.has(id)) {
        skippedOpen.push(id);
        continue;
      }
      const raw = await client.getText(`profiles/${id}.enc`);
      if (!raw) continue;
      const record = decryptSyncPayload<WebDavSyncedProfileRecord>(raw, config.passphrase);
      if (!record?.profile || record.profile.id !== id) {
        throw new Error(`Remote profile record ${id} is invalid`);
      }
      const sessions = record.sessionBundle ? new Map([[id, record.sessionBundle]]) : new Map<string, string>();
      store.upsertProfiles([record.profile], sessions);
      const saved = store.getProfile(id);
      const savedHash = saved ? computeProfileSyncHash(saved, store.getSessionBundle(id) ?? "") : (manifest.profiles[id]?.hash ?? "");
      state.baseProfiles[id] = { hash: savedHash, syncedAt };
      pulled++;
    } else if (decision === "pull_delete") {
      if (openIds.has(id)) {
        skippedOpen.push(id);
        continue;
      }
      if (store.trashProfile(id)) deletedLocal++;
      state.baseProfiles[id] = { hash: "", syncedAt, deleted: true };
    }
  }

  // Proxy pool sync (subscriptions + nodes + chain configs)
  let proxyPoolAction: WebDavSyncRunResult["proxyPoolAction"] = "unchanged";
  const poolDiff = preview.proxyPool;
  let poolDecision: "push" | "pull" | "skip" = "skip";
  if (options.mode === "push") {
    poolDecision = poolDiff.action === "unchanged" && existingManifest?.proxyPool ? "skip" : "push";
  } else if (options.mode === "pull") {
    poolDecision = existingManifest?.proxyPool && poolDiff.action !== "unchanged" ? "pull" : "skip";
  } else {
    if (poolDiff.action === "push") poolDecision = "push";
    else if (poolDiff.action === "pull") poolDecision = "pull";
    else if (poolDiff.action === "conflict") {
      const choice = options.proxyPoolResolution ?? "skip";
      if (choice === "local") poolDecision = "push";
      else if (choice === "remote") poolDecision = "pull";
      else {
        unresolvedConflicts.push("__proxy_pool__");
        proxyPoolAction = "skipped";
      }
    }
  }

  if (poolDecision === "push") {
    const subscriptions = store.listProxySubscriptions();
    const nodes = store.listProxyNodes();
    const hash = subscriptions.length === 0 && nodes.length === 0 ? "" : computeProxyPoolSyncHash(subscriptions, nodes);
    const payload: WebDavSyncedProxyPoolRecord = {
      version: 1,
      subscriptions,
      nodes,
      updatedAt: syncedAt,
      deviceName: config.deviceName,
    };
    await client.putText("proxy-pool.enc", encryptSyncPayload(payload, config.passphrase));
    manifest.proxyPool = {
      hash,
      updatedAt: syncedAt,
      deviceName: config.deviceName,
      subscriptionCount: subscriptions.length,
      nodeCount: nodes.length,
    };
    state.baseProxyPoolHash = hash;
    proxyPoolAction = "pushed";
    manifestDirty = true;
  } else if (poolDecision === "pull") {
    const raw = await client.getText("proxy-pool.enc");
    if (raw) {
      const record = decryptSyncPayload<WebDavSyncedProxyPoolRecord>(raw, config.passphrase);
      store.replaceProxyPool(record.subscriptions ?? [], record.nodes ?? []);
      const subsAfter = store.listProxySubscriptions();
      const nodesAfter = store.listProxyNodes();
      const hash = subsAfter.length === 0 && nodesAfter.length === 0 ? "" : computeProxyPoolSyncHash(subsAfter, nodesAfter);
      state.baseProxyPoolHash = hash;
      proxyPoolAction = "pulled";
    }
  } else if (poolDiff.action === "unchanged") {
    const subsNow = store.listProxySubscriptions();
    const nodesNow = store.listProxyNodes();
    state.baseProxyPoolHash = subsNow.length === 0 && nodesNow.length === 0 ? "" : computeProxyPoolSyncHash(subsNow, nodesNow);
  }

  if (manifestDirty) {
    manifest.updatedAt = syncedAt;
    manifest.updatedBy = config.deviceName;
    await client.putText("manifest.json.enc", encryptSyncPayload(manifest, config.passphrase));
  }

  saveWebDavState(stateRoot, state);
  const parts: string[] = [];
  if (pushed) parts.push(`pushed ${pushed}`);
  if (pulled) parts.push(`pulled ${pulled}`);
  if (deletedRemote) parts.push(`removed ${deletedRemote} remote`);
  if (deletedLocal) parts.push(`trashed ${deletedLocal} local`);
  if (proxyPoolAction === "pushed") parts.push("proxy pool uploaded");
  if (proxyPoolAction === "pulled") parts.push("proxy pool downloaded");
  if (unresolvedConflicts.length) parts.push(`${unresolvedConflicts.length} conflict(s) pending`);
  if (skippedOpen.length) parts.push(`${skippedOpen.length} open skipped`);
  const message = parts.length ? parts.join(" · ") : "Already up to date";
  updateWebDavSyncStatus(stateRoot, syncedAt, message);

  return {
    ok: true,
    mode: options.mode,
    pushed,
    pulled,
    deletedLocal,
    deletedRemote,
    proxyPoolAction,
    skippedOpen,
    unresolvedConflicts,
    syncedAt,
    message,
  };
}

export function buildVpsWebDavDeployGuide(): string {
  return [
    "# Minimal Docker WebDAV server for your VPS (e.g. vps97):",
    "mkdir -p /opt/aliasmode-webdav/data",
    "docker run -d --name aliasmode-webdav --restart unless-stopped \\",
    "  -p 127.0.0.1:8088:80 \\",
    "  -e AUTH_TYPE=Basic \\",
    "  -e USERNAME=aliasmode \\",
    "  -e PASSWORD='CHANGE_ME_STRONG_PASSWORD' \\",
    "  -v /opt/aliasmode-webdav/data:/var/lib/dav/data \\",
    "  bytemark/webdav",
    "",
    "# Put behind Caddy / Nginx HTTPS (or Tailscale IP):",
    "#   URL: https://dav.your-domain.com/aliasmode",
    "#   All files are AES-256-GCM encrypted on your PC before upload.",
  ].join("\n");
}
