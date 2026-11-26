/**
 * Local network routing settings for AliasMode's 3-mode profile proxy model:
 *   1. Direct (`proxy === null`): launches browsers with `--no-proxy-server`.
 *   2. Local Clash (`proxy.mode === "local-clash"`): routes via the host's local
 *      Clash / Mihomo / v2rayN loopback proxy (e.g. http://127.0.0.1:7897).
 *   3. Proxy Node (`proxy != null && proxy.mode !== "local-clash"`): routes
 *      independent proxies (and chained pre-proxies) through `sing-box.exe` so
 *      a single Clash TUN DIRECT rule for `sing-box.exe` cleanly bypasses TUN
 *      without double-tunneling.
 */

import net from "node:net";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseProxySpec } from "./proxy.ts";
import { defaultSingBoxRuntimeRoot, resolveSingBoxBinary } from "./singbox-runtime.ts";
import type { ProxySpec } from "./types.ts";

export interface LocalNetworkSettings {
  /** Local Clash / Mihomo / v2rayN proxy URL (e.g. "http://127.0.0.1:7897"). */
  localClashUrl: string;
  /** Route single-hop HTTP/SOCKS5 proxy nodes through sing-box.exe when installed so Clash TUN rules stay uniform. */
  routeNodesViaSingBox: boolean;
}

export const DEFAULT_LOCAL_CLASH_URL = "http://127.0.0.1:7897";

export const DEFAULT_LOCAL_NETWORK_SETTINGS: LocalNetworkSettings = {
  localClashUrl: DEFAULT_LOCAL_CLASH_URL,
  routeNodesViaSingBox: true,
};

let configuredSettingsPath: string | null = null;
let configuredStateRoot: string | null = null;

/** Initialize persisted local network settings under `<stateRoot>/network-settings.json`. */
export function setLocalNetworkStateRoot(stateRoot: string): void {
  configuredStateRoot = resolve(stateRoot);
  configuredSettingsPath = join(configuredStateRoot, "network-settings.json");
}

export function isLocalNetworkRuntimeConfigured(): boolean {
  return configuredSettingsPath !== null;
}

/** Normalize a local Clash / proxy URL (accepts `http://127.0.0.1:7897`, `socks5://127.0.0.1:10808`, or `127.0.0.1:7897`). */
export function normalizeLocalClashUrl(raw: unknown): string {
  const value = String(raw ?? "").trim();
  if (!value) return DEFAULT_LOCAL_CLASH_URL;
  const spec = parseProxySpec("http", value);
  if (!spec) return DEFAULT_LOCAL_CLASH_URL;
  if (spec.type !== "http" && spec.type !== "socks5") {
    throw new Error("Local Clash proxy must use http or socks5");
  }
  const host = spec.host.includes(":") && !spec.host.startsWith("[") ? `[${spec.host}]` : spec.host;
  const auth = spec.user
    ? `${encodeURIComponent(spec.user)}:${encodeURIComponent(spec.pass)}@`
    : "";
  return `${spec.type}://${auth}${host}:${spec.port}`;
}

export function readLocalNetworkSettings(settingsPath: string | null = configuredSettingsPath): LocalNetworkSettings {
  if (!settingsPath || !existsSync(settingsPath)) return { ...DEFAULT_LOCAL_NETWORK_SETTINGS };
  try {
    const raw = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
    return {
      localClashUrl: normalizeLocalClashUrl(raw.localClashUrl),
      routeNodesViaSingBox: raw.routeNodesViaSingBox !== false,
    };
  } catch {
    return { ...DEFAULT_LOCAL_NETWORK_SETTINGS };
  }
}

export function writeLocalNetworkSettings(
  patch: Partial<LocalNetworkSettings>,
  settingsPath: string | null = configuredSettingsPath,
): LocalNetworkSettings {
  const current = readLocalNetworkSettings(settingsPath);
  const next: LocalNetworkSettings = {
    localClashUrl: patch.localClashUrl !== undefined ? normalizeLocalClashUrl(patch.localClashUrl) : current.localClashUrl,
    routeNodesViaSingBox: patch.routeNodesViaSingBox !== undefined ? patch.routeNodesViaSingBox === true : current.routeNodesViaSingBox,
  };
  if (settingsPath) {
    mkdirSync(dirname(settingsPath), { recursive: true });
    const tmp = `${settingsPath}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(next, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
    renameSync(tmp, settingsPath);
  }
  return next;
}

/** Build a canonical Local Clash ProxySpec from the configured local Clash URL. */
export function buildLocalClashProxySpec(localClashUrl?: string): ProxySpec {
  const normalizedUrl = normalizeLocalClashUrl(localClashUrl ?? readLocalNetworkSettings().localClashUrl);
  const parsed = parseProxySpec("http", normalizedUrl);
  if (!parsed) throw new Error("Local Clash proxy URL is invalid");
  return {
    ...parsed,
    label: "Local Clash",
    mode: "local-clash",
  };
}

/**
 * Resolve any `mode: "local-clash"` proxy (top-level or chained `preProxy`) to
 * this computer's currently configured local Clash address.
 */
export function resolveRuntimeProxy(
  proxy: ProxySpec | null | undefined,
  settings?: LocalNetworkSettings,
): ProxySpec | null {
  if (!proxy) return null;
  const effectiveSettings = settings ?? readLocalNetworkSettings();
  if (proxy.mode === "local-clash") {
    const base = buildLocalClashProxySpec(effectiveSettings.localClashUrl);
    if (proxy.preProxy) {
      const resolvedPre = resolveRuntimeProxy(proxy.preProxy, effectiveSettings);
      return resolvedPre ? { ...base, preProxy: resolvedPre } : base;
    }
    return base;
  }
  if (proxy.preProxy) {
    const resolvedPre = resolveRuntimeProxy(proxy.preProxy, effectiveSettings);
    if (resolvedPre !== proxy.preProxy) {
      return { ...proxy, ...(resolvedPre ? { preProxy: resolvedPre } : { preProxy: undefined }) };
    }
  }
  return proxy;
}

/**
 * True when independent single-hop HTTP/SOCKS5 nodes should route through
 * `sing-box.exe` in this runtime (enabled by default in CLI/desktop runtime
 * whenever `sing-box` is installed).
 */
export function shouldRouteNodesViaSingBox(proxy?: ProxySpec | null): boolean {
  if (!configuredSettingsPath) return false;
  if (proxy?.mode === "local-clash") return false;
  const settings = readLocalNetworkSettings();
  if (!settings.routeNodesViaSingBox) return false;
  return resolveSingBoxBinary() !== null;
}

export interface DetectedLocalProxy {
  port: number;
  url: string;
  hint: string;
}

const COMMON_LOCAL_PROXY_PORTS: ReadonlyArray<{ port: number; scheme: "http" | "socks5"; hint: string }> = [
  { port: 7897, scheme: "http", hint: "Clash Verge / Mihomo (mixed)" },
  { port: 7890, scheme: "http", hint: "Clash / FlClash (mixed)" },
  { port: 7891, scheme: "socks5", hint: "Clash (socks)" },
  { port: 10809, scheme: "http", hint: "v2rayN (http)" },
  { port: 10808, scheme: "socks5", hint: "v2rayN (mixed/socks)" },
  { port: 2080, scheme: "http", hint: "sing-box / Nekoray" },
  { port: 20171, scheme: "http", hint: "v2rayA (http)" },
  { port: 1080, scheme: "socks5", hint: "Generic SOCKS5" },
];

function probeLoopbackPort(port: number, timeoutMs = 200): Promise<boolean> {
  return new Promise((resolveProbe) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    let done = false;
    const finish = (open: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolveProbe(open);
    };
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

/** Fast loopback probe for common Clash / Mihomo / v2rayN local proxy ports. */
export async function detectLocalClashProxies(): Promise<DetectedLocalProxy[]> {
  const results = await Promise.all(
    COMMON_LOCAL_PROXY_PORTS.map(async (item) => ({
      ...item,
      open: await probeLoopbackPort(item.port),
    })),
  );
  return results
    .filter((item) => item.open)
    .map((item) => ({
      port: item.port,
      url: `${item.scheme}://127.0.0.1:${item.port}`,
      hint: item.hint,
    }));
}

function escapeRegexPath(value: string): string {
  // Never emit literal "(" or ")" inside PROCESS-PATH-REGEX because Mihomo's
  // AND,((...),(...)),DIRECT rule parser splits on nested parentheses.
  return value
    .replace(/[.*+?^${}|[\]\\]/g, "\\$&")
    .replace(/\(/g, "\\x28")
    .replace(/\)/g, "\\x29")
    .replace(/`/g, "\\x60");
}

function escapeWindowsRegexPath(value: string): string {
  const driveMatch = value.match(/^([A-Za-z]):(.*)$/);
  if (driveMatch) {
    const letter = driveMatch[1]!;
    const driveClass = `[${letter.toUpperCase()}${letter.toLowerCase()}]:`;
    return `${driveClass}${escapeRegexPath(driveMatch[2]!)}`;
  }
  return escapeRegexPath(value);
}

function formatYamlRuleItem(rule: string): string {
  // Plain YAML scalar is standard for Mihomo rules unless the path contains
  // YAML comment or mapping sequences (" #" or ": ").
  if (/(?:^|\s)#|:\s/.test(rule)) {
    return `- '${rule.replace(/'/g, "''")}'`;
  }
  return `- ${rule}`;
}

export interface ClashTunRulesOptions {
  browserRoot?: string;
  runtimesRoot?: string;
  platform?: NodeJS.Platform;
}

/**
 * Build raw Mihomo `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,...)),DIRECT` rules.
 *
 * Scoped strictly to `IN-TYPE,TUN` so traffic sent to the local Clash mixed/HTTP
 * port (e.g. `127.0.0.1:7897`) is never forced back to DIRECT even under
 * `find-process-mode: strict`. Regexes avoid any nested parentheses (`(?i)` or
 * alternation groups) so Mihomo's `AND` sub-rule parser parses them cleanly.
 */
export function buildClashTunRuleList(
  stateRoot: string = configuredStateRoot ?? resolve("."),
  options: ClashTunRulesOptions = {},
): string[] {
  const platform = options.platform ?? process.platform;
  const joinTargetPath = (root: string, leaf: string): string =>
    platform === "win32" && process.platform !== "win32"
      ? `${root.replace(/[\\/]+$/, "")}\\${leaf}`
      : join(resolve(root), leaf);
  const browserRoot = options.browserRoot
    ?? (configuredStateRoot && resolve(stateRoot) === configuredStateRoot
      ? defaultSingBoxRuntimeRoot()
      : joinTargetPath(stateRoot, "browser"));
  const runtimesRoot = options.runtimesRoot ?? joinTargetPath(stateRoot, "runtimes");
  if (platform === "win32") {
    const singBoxRegex = `^${escapeWindowsRegexPath(browserRoot)}\\\\.*\\\\sing-box\\.exe$`;
    const chromeRegex = `^${escapeWindowsRegexPath(runtimesRoot)}\\\\.*\\\\chrome\\.exe$`;
    const firefoxRegex = `^${escapeWindowsRegexPath(runtimesRoot)}\\\\.*\\\\firefox\\.exe$`;
    return [
      `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${singBoxRegex})),DIRECT`,
      `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${chromeRegex})),DIRECT`,
      `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${firefoxRegex})),DIRECT`,
    ];
  }
  const singBoxRegex = `^${escapeRegexPath(browserRoot)}/.*/sing-box$`;
  const chromeRegex = `^${escapeRegexPath(runtimesRoot)}/.*/chrome$`;
  const chromiumRegex = `^${escapeRegexPath(runtimesRoot)}/.*/Chromium$`;
  const firefoxRegex = `^${escapeRegexPath(runtimesRoot)}/.*/firefox$`;
  return [
    `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${singBoxRegex})),DIRECT`,
    `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${chromeRegex})),DIRECT`,
    `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${chromiumRegex})),DIRECT`,
    `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,${firefoxRegex})),DIRECT`,
  ];
}

/** Ready-to-paste Clash / Mihomo YAML TUN rules matching this installation's real paths. */
export function buildClashTunRules(
  stateRoot: string = configuredStateRoot ?? resolve("."),
  options: ClashTunRulesOptions = {},
): string {
  const platform = options.platform ?? process.platform;
  const rules = buildClashTunRuleList(stateRoot, options);
  const lines = [
    "# Paste at the TOP of your Clash / Mihomo rules (TUN mode).",
    "# Scoped to IN-TYPE,TUN so Local Clash (127.0.0.1) traffic is never forced back to DIRECT:",
    ...rules.map(formatYamlRuleItem),
  ];
  if (platform === "win32") {
    lines.push(
      "# Fallback if your client only supports PROCESS-NAME (still scoped to TUN):",
      "# - AND,((IN-TYPE,TUN),(PROCESS-NAME,sing-box.exe)),DIRECT",
    );
  }
  return lines.join("\n");
}

/** Ready-to-paste Clash Verge Rev JS override script using `String.raw` to preserve regex backslashes. */
export function buildClashVergeScript(
  stateRoot: string = configuredStateRoot ?? resolve("."),
  options: ClashTunRulesOptions = {},
): string {
  const rules = buildClashTunRuleList(stateRoot, options);
  const entries = rules.map((rule) => `    String.raw\`${rule}\`,`);
  return [
    "// Clash Verge Rev 扩展覆写脚本（订阅右键 → 编辑扩展脚本 / 全局扩展脚本）",
    "// 仅放行 IN-TYPE,TUN 入站流量，不影响「本地 Clash」经由 127.0.0.1 入站的流量",
    "function main(config) {",
    "  const aliasModeRules = [",
    ...entries,
    "  ];",
    "  const existing = Array.isArray(config.rules) ? config.rules : [];",
    "  config.rules = [",
    "    ...aliasModeRules,",
    "    ...existing.filter((rule) => !aliasModeRules.includes(rule)),",
    "  ];",
    "  return config;",
    "}",
  ].join("\n");
}
