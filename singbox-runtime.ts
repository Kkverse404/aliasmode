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
import { buildSingBoxConfig } from "./singbox-config.ts";
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

function allocateLoopbackPort(): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const server = net.createServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      server.close((err) => (err ? reject(err) : resolvePort(port)));
    });
  });
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
    socket.once("connect", () => { clearTimeout(timer); finish(true); });
    socket.once("error", () => { clearTimeout(timer); finish(false); });
  });
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
  const port = opts.port && opts.port > 0 ? opts.port : await allocateLoopbackPort();
  const config = buildSingBoxConfig(proxy, port);

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
