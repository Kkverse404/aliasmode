/**
 * Managed sing-box sidecar runtime and loopback relay lifecycle.
 *
 * Locates or auto-downloads a SHA-256 verified sing-box binary, spawns an
 * isolated process per proxied profile/check bound to 127.0.0.1:<port>, and
 * tears down both the process and temporary config file on close or exit.
 */

import net from "node:net";
import { tmpdir } from "node:os";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { renameWhenUnlocked, sha256File, windowsSystemTool } from "./browser-install.ts";
import { buildSingBoxConfig, flattenProxyChain } from "./singbox-config.ts";
import type { ProxyRelay, RelayOptions } from "./proxy-relay.ts";
import type { ProxySpec } from "./types.ts";

export const SINGBOX_VERSION = "1.14.4";
const RELEASE_BASE = `https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}`;

interface SingBoxBuildSpec {
  dir: string;
  archiveRoot: string;
  url: string;
  archiveSha256: string;
  size: number;
  executable: string;
}

const WINDOWS_AMD64_BUILD: SingBoxBuildSpec = {
  dir: `sing-box-${SINGBOX_VERSION}`,
  archiveRoot: `sing-box-${SINGBOX_VERSION}-windows-amd64`,
  url: `${RELEASE_BASE}/sing-box-${SINGBOX_VERSION}-windows-amd64.zip`,
  archiveSha256: "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df",
  size: 32891280,
  executable: "sing-box.exe",
};

const DARWIN_ARM64_BUILD: SingBoxBuildSpec = {
  dir: `sing-box-${SINGBOX_VERSION}`,
  archiveRoot: `sing-box-${SINGBOX_VERSION}-darwin-arm64`,
  url: `${RELEASE_BASE}/sing-box-${SINGBOX_VERSION}-darwin-arm64.tar.gz`,
  archiveSha256: "0d8c7f5ed5d587b0f1a5e9772a708ec3bfa4ac4c9329604b01d8d9c2ba406838",
  size: 29186204,
  executable: "sing-box",
};

const DARWIN_AMD64_BUILD: SingBoxBuildSpec = {
  dir: `sing-box-${SINGBOX_VERSION}`,
  archiveRoot: `sing-box-${SINGBOX_VERSION}-darwin-amd64`,
  url: `${RELEASE_BASE}/sing-box-${SINGBOX_VERSION}-darwin-amd64.tar.gz`,
  archiveSha256: "eae86b9b033bba50b7c44ab719e4bfac0aca05efd28483390ed3aa510f32db25",
  size: 31503132,
  executable: "sing-box",
};

const LINUX_AMD64_BUILD: SingBoxBuildSpec = {
  dir: `sing-box-${SINGBOX_VERSION}`,
  archiveRoot: `sing-box-${SINGBOX_VERSION}-linux-amd64`,
  url: `${RELEASE_BASE}/sing-box-${SINGBOX_VERSION}-linux-amd64.tar.gz`,
  archiveSha256: "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968",
  size: 31710753,
  executable: "sing-box",
};

export function singBoxBuildSpec(
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): SingBoxBuildSpec | null {
  if (platform === "win32" && arch === "x64") return WINDOWS_AMD64_BUILD;
  if (platform === "darwin" && arch === "arm64") return DARWIN_ARM64_BUILD;
  if (platform === "darwin" && arch === "x64") return DARWIN_AMD64_BUILD;
  if (platform === "linux" && arch === "x64") return LINUX_AMD64_BUILD;
  return null;
}

let configuredRuntimeRoot: string | null = null;

/** Configure the directory where downloaded sing-box binaries live (usually `paths.browser`). */
export function setSingBoxRuntimeRoot(root: string): void {
  configuredRuntimeRoot = resolve(root);
}

export function defaultSingBoxRuntimeRoot(): string {
  if (configuredRuntimeRoot) return configuredRuntimeRoot;
  const stateRoot = process.env.ALIASMODE_STATE_ROOT;
  return stateRoot ? resolve(stateRoot, "browser") : resolve("browser");
}

export interface SingBoxKernelStatus {
  installed: boolean;
  version: string;
  path: string | null;
  source: "env" | "managed" | "path" | null;
  supported: boolean;
  installing: boolean;
}

function findInPath(name: string): string | null {
  try {
    return Bun.which(name) ?? null;
  } catch {
    return null;
  }
}

export function resolveSingBoxBinary(
  runtimeRoot = defaultSingBoxRuntimeRoot(),
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): { path: string; source: "env" | "managed" | "path" } | null {
  const envPath = env.ALIASMODE_SINGBOX_PATH?.trim();
  if (envPath && existsSync(envPath)) return { path: resolve(envPath), source: "env" };

  const spec = singBoxBuildSpec(platform, arch);
  if (spec) {
    const managed = join(runtimeRoot, spec.dir, spec.executable);
    if (existsSync(managed)) return { path: managed, source: "managed" };
  }

  const onPath = findInPath(platform === "win32" ? "sing-box.exe" : "sing-box");
  if (onPath) return { path: onPath, source: "path" };
  return null;
}

const installingByRoot = new Map<string, Promise<string>>();

export function singBoxKernelStatus(
  runtimeRoot = defaultSingBoxRuntimeRoot(),
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): SingBoxKernelStatus {
  const found = resolveSingBoxBinary(runtimeRoot, env, platform, arch);
  return {
    installed: !!found,
    version: SINGBOX_VERSION,
    path: found?.path ?? null,
    source: found?.source ?? null,
    supported: !!singBoxBuildSpec(platform, arch),
    installing: installingByRoot.has(resolve(runtimeRoot)),
  };
}

export interface EnsureSingBoxDeps {
  download?: (url: string, output: string) => Promise<void>;
  extract?: (archive: string, directory: string) => Promise<void>;
  hashFile?: (path: string) => Promise<string>;
}

async function runCmd(command: string[]): Promise<void> {
  const child = Bun.spawn(command, { stdout: "ignore", stderr: "ignore" });
  if ((await child.exited) !== 0) throw new Error(`${command[0]} exited with code ${child.exitCode}`);
}

async function curlDownload(url: string, output: string, platform: NodeJS.Platform): Promise<void> {
  const child = Bun.spawn([
    platform === "win32" ? windowsSystemTool("curl.exe") : "curl",
    "--fail", "--location", "--silent", "--show-error",
    "--continue-at", "-", "--connect-timeout", "30",
    "--output", output, url,
  ], { stdout: "ignore", stderr: "pipe" });
  const code = await child.exited;
  if (code === 33) rmSync(output, { force: true });
  if (code !== 0) {
    const stderr = await new Response(child.stderr).text().catch(() => "");
    throw new Error(`sing-box download failed (curl ${code})${stderr ? `: ${stderr.trim()}` : ""}`);
  }
}

function extractArchiveCmd(url: string, archive: string, directory: string, platform: NodeJS.Platform): string[] {
  if (url.endsWith(".tar.gz")) return ["tar", "-xzf", archive, "-C", directory];
  return platform === "darwin"
    ? ["ditto", "-x", "-k", archive, directory]
    : [windowsSystemTool("tar.exe"), "-xf", archive, "-C", directory];
}

/** Ensure a verified sing-box executable exists locally, downloading on demand if absent. */
export async function ensureSingBoxBinary(
  runtimeRoot = defaultSingBoxRuntimeRoot(),
  deps: EnsureSingBoxDeps = {},
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): Promise<string> {
  const existing = resolveSingBoxBinary(runtimeRoot, process.env, platform, arch);
  if (existing) return existing.path;

  const spec = singBoxBuildSpec(platform, arch);
  if (!spec) {
    throw new Error(`sing-box auto-download is unsupported on ${platform} ${arch}; set ALIASMODE_SINGBOX_PATH`);
  }

  const key = resolve(runtimeRoot);
  const inflight = installingByRoot.get(key);
  if (inflight) return inflight;

  const promise = (async () => {
    const targetDir = join(key, spec.dir);
    const executablePath = join(targetDir, spec.executable);
    if (existsSync(executablePath)) return executablePath;

    mkdirSync(key, { recursive: true });
    const partial = join(key, `.${spec.dir}.${spec.archiveSha256.slice(0, 12)}.part`);
    const hashFile = deps.hashFile ?? sha256File;

    let needDownload = true;
    if (existsSync(partial)) {
      const size = statSync(partial, { throwIfNoEntry: false })?.size ?? 0;
      if (size === spec.size && (await hashFile(partial)) === spec.archiveSha256) {
        needDownload = false;
      } else if (size > spec.size) {
        rmSync(partial, { force: true });
      }
    }

    if (needDownload) {
      await (deps.download ?? ((url, out) => curlDownload(url, out, platform)))(spec.url, partial);
      const actualHash = await hashFile(partial);
      if (actualHash !== spec.archiveSha256) {
        rmSync(partial, { force: true });
        throw new Error(`sing-box archive SHA-256 mismatch (expected ${spec.archiveSha256}, got ${actualHash})`);
      }
    }

    const temp = join(key, `.${spec.dir}-${process.pid}-${Date.now()}`);
    const archive = join(temp, spec.url.endsWith(".tar.gz") ? "sing-box.tar.gz" : "sing-box.zip");
    const extracted = join(temp, "extracted");
    mkdirSync(extracted, { recursive: true });
    try {
      await renameWhenUnlocked(partial, archive);
      await (deps.extract ?? ((file, dir) => runCmd(extractArchiveCmd(spec.url, file, dir, platform))))(archive, extracted);
      let sourceDir = join(extracted, spec.archiveRoot);
      if (!existsSync(join(sourceDir, spec.executable))) {
        const sub = readdirSync(extracted).find((name) => existsSync(join(extracted, name, spec.executable)));
        sourceDir = sub ? join(extracted, sub) : extracted;
      }
      if (!existsSync(join(sourceDir, spec.executable))) {
        throw new Error("sing-box archive did not contain the expected executable");
      }
      rmSync(targetDir, { recursive: true, force: true });
      await renameWhenUnlocked(sourceDir, targetDir);
      return executablePath;
    } finally {
      rmSync(temp, { recursive: true, force: true });
    }
  })().finally(() => {
    installingByRoot.delete(key);
  });

  installingByRoot.set(key, promise);
  return promise;
}

// Allocate loopback ports strictly below the OS ephemeral client port range
// (Linux 32768-60999, Windows/macOS 49152-65535). Using `listen(0)` hands out
// sequential ephemeral ports that sibling outbound `fetch`/`net.connect` calls
// immediately steal before `sing-box` binds, causing EADDRINUSE or TCP self-connect.
const LOOPBACK_PORT_MIN = 20_000;
const LOOPBACK_PORT_MAX = 32_000;
const reservedLoopbackPorts = new Set<number>();
let loopbackPortCursor = LOOPBACK_PORT_MIN + (process.pid % 4_000);

function tryBindLoopbackPort(port: number): Promise<number | null> {
  return new Promise((resolvePort) => {
    const server = net.createServer();
    server.unref();
    server.once("error", () => resolvePort(null));
    server.listen(port, "127.0.0.1", () => {
      const addr = server.address();
      const bound = typeof addr === "object" && addr ? addr.port : 0;
      server.close((err) => resolvePort(err || !bound ? null : bound));
    });
  });
}

async function allocateLoopbackPort(): Promise<number> {
  const span = LOOPBACK_PORT_MAX - LOOPBACK_PORT_MIN;
  for (let attempt = 0; attempt < 64; attempt++) {
    const candidate = LOOPBACK_PORT_MIN + ((loopbackPortCursor++ - LOOPBACK_PORT_MIN) % span);
    if (reservedLoopbackPorts.has(candidate)) continue;
    reservedLoopbackPorts.add(candidate);
    const bound = await tryBindLoopbackPort(candidate);
    if (bound !== null) return bound;
    reservedLoopbackPorts.delete(candidate);
  }
  const fallback = await tryBindLoopbackPort(0);
  if (fallback === null) throw new Error("failed to allocate loopback port for sing-box");
  reservedLoopbackPorts.add(fallback);
  return fallback;
}

function probeLoopbackPort(port: number, timeoutMs = 200): Promise<boolean> {
  return new Promise((resolveReady) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolveReady(ok);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      // Guard against TCP simultaneous-open self-connection (`127.0.0.1:P -> 127.0.0.1:P`).
      if (socket.localPort === port) {
        finish(false);
        return;
      }
      finish(true);
    });
    socket.once("error", () => { clearTimeout(timer); finish(false); });
  });
}

const DOH_JSON_RESOLVERS = [
  "https://223.5.5.5/resolve",
  "https://223.6.6.6/resolve",
] as const;

const DOH_CACHE_TTL_MS = 10 * 60_000;
const dohHostCache = new Map<string, { ips: string[]; expiresAt: number }>();
const dohInFlight = new Map<string, Promise<string[]>>();

function isUsableResolvedIpv4(ip: string): boolean {
  if (net.isIP(ip) !== 4) return false;
  // Reject loopback, unspecified, link-local, and Clash/Mihomo Fake-IP (`198.18.0.0/15`).
  if (ip.startsWith("127.") || ip.startsWith("0.") || ip.startsWith("169.254.")) return false;
  if (ip.startsWith("198.18.") || ip.startsWith("198.19.")) return false;
  return true;
}

async function resolveProxyHostIps(host: string): Promise<string[]> {
  const clean = host.trim().replace(/^\[|\]$/g, "").toLowerCase();
  if (!clean || clean === "localhost" || clean.endsWith(".test") || clean.endsWith(".example") || clean.endsWith(".example.com") || clean.endsWith(".invalid") || net.isIP(clean) !== 0) {
    return [];
  }
  const now = Date.now();
  const cached = dohHostCache.get(clean);
  if (cached && cached.expiresAt > now) return cached.ips;

  const existing = dohInFlight.get(clean);
  if (existing) return existing;

  const lookup = (async (): Promise<string[]> => {
    try {
      const ips = await Promise.any(
        DOH_JSON_RESOLVERS.map(async (endpoint) => {
          const url = `${endpoint}?name=${encodeURIComponent(clean)}&type=A`;
          const res = await fetch(url, {
            headers: { Accept: "application/dns-json" },
            signal: AbortSignal.timeout(2_000),
          });
          if (!res.ok) throw new Error(`DoH ${res.status}`);
          const data = (await res.json()) as { Answer?: Array<{ type?: number; data?: string }> };
          const found = (data.Answer ?? [])
            .filter((ans) => ans.type === 1 && typeof ans.data === "string" && isUsableResolvedIpv4(ans.data.trim()))
            .map((ans) => ans.data!.trim());
          if (!found.length) throw new Error("no A record");
          return [...new Set(found)];
        }),
      );
      dohHostCache.set(clean, { ips, expiresAt: Date.now() + DOH_CACHE_TTL_MS });
      return ips;
    } catch {
      return [];
    } finally {
      dohInFlight.delete(clean);
    }
  })();

  dohInFlight.set(clean, lookup);
  return lookup;
}

async function preResolveChainHosts(proxy: ProxySpec): Promise<Record<string, string[]>> {
  if (process.env.ALIASMODE_SINGBOX_PRERESOLVE === "0") return {};
  const hosts = [...new Set(
    flattenProxyChain(proxy)
      .map((hop) => hop.host.trim().replace(/^\[|\]$/g, "").toLowerCase())
      .filter((h) => h && h !== "localhost" && net.isIP(h) === 0),
  )];
  if (!hosts.length) return {};
  const entries = await Promise.all(hosts.map(async (h) => [h, await resolveProxyHostIps(h)] as const));
  const map: Record<string, string[]> = {};
  for (const [h, ips] of entries) {
    if (ips.length) map[h] = ips;
  }
  return map;
}

interface ActiveRelayHandle {
  close(syncExit?: boolean): void;
}

const activeRelays = new Set<ActiveRelayHandle>();
let exitHooksInstalled = false;

function installExitHooks(): void {
  if (exitHooksInstalled) return;
  exitHooksInstalled = true;
  process.once("exit", () => closeAllSingBoxRelays(true));
}

/**
 * Remove a temporary sing-box config directory safely after the child exits.
 * On Windows, `rmSync` immediately after `child.kill()` races with open file
 * handles and fails with EBUSY; waiting for `exitPromise` + retrying prevents
 * `%TEMP%/aliasmode-sb-*` secret config files from leaking on disk.
 */
export function cleanupTempDirAfterExit(
  tempDir: string,
  exitPromise: Promise<unknown>,
  retryDelaysMs: readonly number[] = [250, 800],
): Promise<boolean> {
  const tryRemove = (): boolean => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
      return !existsSync(tempDir);
    } catch {
      return false;
    }
  };
  return Promise.race([
    exitPromise.catch(() => {}),
    new Promise<void>((r) => {
      const t = setTimeout(r, 2_000);
      t.unref?.();
    }),
  ]).then(async () => {
    if (tryRemove()) return true;
    for (const delay of retryDelaysMs) {
      await new Promise<void>((r) => {
        const t = setTimeout(r, delay);
        t.unref?.();
      });
      if (tryRemove()) return true;
    }
    return !existsSync(tempDir);
  });
}

/** Terminate every live sing-box sidecar child process and remove temp configs. */
export function closeAllSingBoxRelays(syncExit = false): void {
  for (const relay of [...activeRelays]) {
    try { relay.close(syncExit); } catch {}
  }
  activeRelays.clear();
}

export interface SingBoxRelayOptions extends RelayOptions {
  runtimeRoot?: string;
  binaryPath?: string;
  startupTimeoutMs?: number;
}

/**
 * Start a managed sing-box sidecar for `proxy` (supports all sing-box protocols
 * and multi-hop `preProxy` chains), exposing a local loopback HTTP+SOCKS5 port.
 */
export async function startSingBoxRelay(
  proxy: ProxySpec,
  opts: SingBoxRelayOptions = {},
): Promise<ProxyRelay> {
  const log = opts.log ?? (() => {});
  const binaryPath = opts.binaryPath ?? await ensureSingBoxBinary(opts.runtimeRoot ?? defaultSingBoxRuntimeRoot());
  const predefinedHosts = await preResolveChainHosts(proxy);
  const ownedPort = !(opts.port && opts.port > 0);
  const port = opts.port && opts.port > 0 ? opts.port : await allocateLoopbackPort();
  const config = buildSingBoxConfig(proxy, port, { predefinedHosts });

  const tempDir = mkdtempSync(join(tmpdir(), "aliasmode-sb-"));
  const configPath = join(tempDir, "config.json");
  writeFileSync(configPath, JSON.stringify(config, null, 2), { encoding: "utf8", mode: 0o600 });

  const child = Bun.spawn([binaryPath, "run", "-c", configPath], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });

  const stderrChunks: string[] = [];
  const collectStream = async (stream: ReadableStream<Uint8Array> | null) => {
    if (!stream) return;
    const reader = stream.getReader();
    const decoder = new TextDecoder();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const text = decoder.decode(value, { stream: true });
        if (text) {
          stderrChunks.push(text);
          if (stderrChunks.length > 20) stderrChunks.shift();
          log(`sing-box: ${text.trim()}`);
        }
      }
    } catch {} finally {
      reader.releaseLock();
    }
  };
  void collectStream(child.stderr);
  void collectStream(child.stdout);

  let exited = false;
  let exitCode: number | null = null;
  const exitPromise = child.exited.then((code) => {
    exited = true;
    exitCode = code;
    return code;
  });

  let closed = false;
  const close = (syncExit = false) => {
    if (closed) return;
    closed = true;
    activeRelays.delete(handle);
    if (ownedPort) reservedLoopbackPorts.delete(port);
    try { child.kill(); } catch {}
    if (syncExit) {
      try { rmSync(tempDir, { recursive: true, force: true }); } catch {}
      return;
    }
    void cleanupTempDirAfterExit(tempDir, exitPromise);
  };
  const handle: ActiveRelayHandle = { close };
  installExitHooks();
  activeRelays.add(handle);

  const deadline = Date.now() + (opts.startupTimeoutMs ?? 8_000);
  try {
    // Allow sing-box ~40ms to initialize before the first TCP probe.
    await Promise.race([Bun.sleep(40), exitPromise]);
    while (Date.now() < deadline) {
      if (exited) {
        const detail = stderrChunks.join("").trim().slice(0, 400);
        throw new Error(`sing-box exited prematurely (code ${exitCode})${detail ? `: ${detail}` : ""}`);
      }
      if (await probeLoopbackPort(port)) {
        return { port, close };
      }
      await Promise.race([Bun.sleep(30), exitPromise]);
    }
    const detail = stderrChunks.join("").trim().slice(0, 400);
    throw new Error(`sing-box did not listen on 127.0.0.1:${port} in time${detail ? `: ${detail}` : ""}`);
  } catch (error) {
    close();
    throw error;
  }
}
