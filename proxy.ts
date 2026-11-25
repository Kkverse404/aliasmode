/**
 * Canonical proxy parsing and rendering.
 *
 * Every proxy ingress (UI, AdsPower import/API, hub, proxy pool, and persisted
 * profiles) must pass through this module. Launch routing must never guess a
 * protocol from an arbitrary string: a malformed/unknown type is rejected
 * before any account traffic can start.
 */

import type { ProxySpec, ProxyType } from "./types.ts";
import { isIP } from "node:net";
import { isSingBoxProxyType, normalizeSingBoxScheme, parseSingBoxUri } from "./singbox-uri.ts";

export type ProxyInput = {
  type?: unknown;
  host?: unknown;
  port?: unknown;
  user?: unknown;
  pass?: unknown;
  uri?: unknown;
  label?: unknown;
  mode?: unknown;
  preProxy?: ProxyInput | ProxySpec | null;
};

const MAX_PRE_PROXY_DEPTH = 3;
const STANDARD_PROXY_TYPES = new Set<ProxyType>(["http", "https", "socks5"]);

export function normalizeProxyType(value: unknown, fallback: ProxyType = "http"): ProxyType {
  const raw = String(value ?? "").trim().toLowerCase();
  if (!raw) return fallback;
  if (raw === "socks") return "socks5";
  if (STANDARD_PROXY_TYPES.has(raw as ProxyType)) return raw as ProxyType;
  const singbox = normalizeSingBoxScheme(raw);
  if (singbox) return singbox;
  throw new Error(`unsupported proxy type: ${raw} (use http, https, socks5, vless, vmess, trojan, ss, hysteria2, tuic, or wireguard)`);
}

export function isSocksProxyType(type: ProxyType): boolean {
  return type === "socks5";
}

export function isHttpProxyType(type: ProxyType): boolean {
  return type === "http" || type === "https";
}

/** True when this proxy must be routed through the embedded sing-box sidecar. */
export function isSingBoxProxy(proxy: ProxySpec | null | undefined): boolean {
  return !!proxy && (isSingBoxProxyType(proxy.type) || !!proxy.preProxy);
}

function normalizeHost(value: unknown): string {
  const raw = String(value ?? "").trim();
  const hasOpeningBracket = raw.startsWith("[");
  const hasClosingBracket = raw.endsWith("]");
  if (hasOpeningBracket !== hasClosingBracket) throw new Error("proxy host has invalid bracket syntax");
  const host = hasOpeningBracket && hasClosingBracket ? raw.slice(1, -1) : raw;
  if (!host) throw new Error("proxy host is empty");
  if (hasOpeningBracket && isIP(host) !== 6) {
    throw new Error("proxy host brackets are only valid around an IPv6 address");
  }
  if (/[\s\u0000-\u001f\u007f]/.test(host)) throw new Error("proxy host contains whitespace or control characters");
  if (/[\[\]\\/@?#%]/.test(host)) throw new Error("proxy host contains a URL delimiter or invalid bracket");
  if (host.includes(":")) {
    if (isIP(host) !== 6) throw new Error("proxy host contains an invalid IPv6 address");
  } else {
    try {
      const parsed = new URL(`http://${host}/`);
      if (!parsed.hostname || parsed.username || parsed.password || parsed.port || parsed.pathname !== "/") {
        throw new Error("invalid");
      }
    } catch {
      throw new Error("proxy host is not a valid hostname or IP address");
    }
  }
  return host;
}

function normalizePort(value: unknown): string {
  const port = String(value ?? "").trim();
  const portNumber = Number(port);
  if (!/^\d+$/.test(port) || !Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    throw new Error(`invalid proxy port: ${port || "(empty)"}`);
  }
  return String(portNumber);
}

/** Normalize an object-shaped proxy (including optional sing-box URI, local-clash mode & preProxy chain). A fully blank object means no proxy. */
export function normalizeProxySpec(input: ProxyInput | ProxySpec | null | undefined, depth = 0): ProxySpec | null {
  if (!input) return null;
  if (depth > MAX_PRE_PROXY_DEPTH) throw new Error("proxy chain is too deep");

  const uriRaw = typeof input.uri === "string" ? input.uri.trim() : "";
  const labelRaw = typeof input.label === "string" ? input.label.trim() : "";
  const modeRaw = String(input.mode ?? "").trim().toLowerCase();
  const isLocalClash = modeRaw === "local-clash"
    || String(input.type ?? "").trim().toLowerCase() === "local-clash"
    || uriRaw.toLowerCase() === "local-clash://";
  const preProxy = input.preProxy ? normalizeProxySpec(input.preProxy, depth + 1) : null;

  if (isLocalClash) {
    const hostRaw = String(input.host ?? "").trim();
    const portRaw = String(input.port ?? "").trim();
    const fallbackType = String(input.type ?? "").trim().toLowerCase();
    const clashType = fallbackType === "socks5" ? "socks5" : "http";
    const user = String(input.user ?? "").trim();
    const pass = String(input.pass ?? "");
    return {
      type: clashType,
      host: hostRaw ? normalizeHost(hostRaw) : "127.0.0.1",
      port: portRaw ? normalizePort(portRaw) : "7897",
      user,
      pass,
      label: labelRaw || "Local Clash",
      mode: "local-clash",
      ...(preProxy ? { preProxy } : {}),
    };
  }

  if (uriRaw) {
    const schemeMatch = uriRaw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
    if (schemeMatch && normalizeSingBoxScheme(schemeMatch[1]!)) {
      const parsed = parseSingBoxUri(uriRaw);
      const label = labelRaw || parsed.label;
      return {
        type: parsed.type,
        host: parsed.host,
        port: String(parsed.port),
        user: "",
        pass: "",
        uri: parsed.uri,
        ...(label ? { label } : {}),
        ...(preProxy ? { preProxy } : {}),
      };
    }
    const parsedStd = parseProxyUrl(uriRaw);
    const label = labelRaw || parsedStd.label;
    return {
      ...parsedStd,
      ...(label ? { label } : {}),
      ...(preProxy ? { preProxy } : {}),
    };
  }

  const hostRaw = String(input.host ?? "").trim();
  const portRaw = String(input.port ?? "").trim();
  if (!hostRaw && !portRaw) {
    if (preProxy) throw new Error("pre-proxy requires a primary proxy");
    return null;
  }

  // Convenience: if caller put a full sing-box URI into host with blank port, parse it cleanly.
  if (hostRaw && !portRaw && /^[a-z][a-z0-9+.-]*:\/\//i.test(hostRaw)) {
    const scheme = hostRaw.match(/^([a-z][a-z0-9+.-]*):\/\//i)?.[1] ?? "";
    if (normalizeSingBoxScheme(scheme)) {
      const parsed = parseSingBoxUri(hostRaw);
      const label = labelRaw || parsed.label;
      return {
        type: parsed.type,
        host: parsed.host,
        port: String(parsed.port),
        user: "",
        pass: "",
        uri: parsed.uri,
        ...(label ? { label } : {}),
        ...(preProxy ? { preProxy } : {}),
      };
    }
  }

  const normalizedType = normalizeProxyType(input.type);
  if (isSingBoxProxyType(normalizedType)) {
    throw new Error(`${normalizedType} proxy requires a full share URI`);
  }

  if (!hostRaw) throw new Error("proxy host is empty");
  if (!portRaw) throw new Error("invalid proxy port: (empty)");
  const user = String(input.user ?? "").trim();
  const pass = String(input.pass ?? "");
  if (!user && pass) throw new Error("proxy password requires a non-empty username");
  return {
    type: normalizedType,
    host: normalizeHost(hostRaw),
    port: normalizePort(portRaw),
    user,
    pass,
    ...(labelRaw ? { label: labelRaw } : {}),
    ...(preProxy ? { preProxy } : {}),
  };
}

function decodeCredential(value: string, label: "username" | "password"): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error(`proxy ${label} has invalid percent-encoding`);
  }
}

function parseProxyUrl(raw: string): ProxySpec {
  const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (schemeMatch && normalizeSingBoxScheme(schemeMatch[1]!)) {
    const parsed = parseSingBoxUri(raw);
    return {
      type: parsed.type,
      host: parsed.host,
      port: String(parsed.port),
      user: "",
      pass: "",
      uri: parsed.uri,
      ...(parsed.label ? { label: parsed.label } : {}),
    };
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("invalid proxy URL");
  }
  if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
    throw new Error("proxy URL must not contain a path, query, or fragment");
  }
  return normalizeProxySpec({
    type: url.protocol.replace(/:$/, ""),
    host: url.hostname,
    port: url.port,
    user: decodeCredential(url.username, "username"),
    pass: decodeCredential(url.password, "password"),
  })!;
}

/**
 * Parse either a standard proxy URL, a sing-box share URI (vless/vmess/trojan/ss/hy2/tuic/wg),
 * or AdsPower's legacy `host:port[:user:password]` representation.
 */
export function parseProxySpec(type: unknown, value: unknown): ProxySpec | null {
  const raw = String(value ?? "").trim();
  if (String(type ?? "").trim().toLowerCase() === "local-clash" || raw.toLowerCase() === "local-clash" || raw.toLowerCase() === "local-clash://") {
    return normalizeProxySpec({ mode: "local-clash" });
  }
  if (!raw) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) return parseProxyUrl(raw);

  // Bracketed IPv6 legacy form: [2001:db8::1]:1080:user:password.
  const ipv6 = raw.match(/^\[([^\]]+)]:(\d+)(?::([^:]*)(?::(.*))?)?$/);
  if (ipv6) {
    return normalizeProxySpec({
      type,
      host: ipv6[1],
      port: ipv6[2],
      user: ipv6[3] ?? "",
      pass: ipv6[4] ?? "",
    });
  }

  const parts = raw.split(":");
  if (parts.length < 2) throw new Error("proxy must be host:port[:user:password] or a proxy URL");
  // Unbracketed IPv6 host: the port sits before user:password or at the end.
  let portIndex = 1;
  for (const index of [parts.length - 3, parts.length - 1]) {
    if (index >= 2 && /^\d+$/.test(parts[index]!) && isIP(parts.slice(0, index).join(":")) === 6) {
      portIndex = index;
      break;
    }
  }
  return normalizeProxySpec({
    type,
    host: parts.slice(0, portIndex).join(":"),
    port: parts[portIndex],
    user: parts[portIndex + 1] ?? "",
    // Passwords may contain colons; preserve everything after the user field.
    pass: parts.slice(portIndex + 2).join(":"),
  });
}

function authorityHost(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/** Host/port form for redacted displays; brackets make IPv6 unambiguous. */
export function proxyHostPort(proxy: ProxySpec): string {
  return `${authorityHost(proxy.host)}:${proxy.port}`;
}

/** Redacted display string showing protocol, host:port, and chain indicator (never secrets). */
export function proxyDisplaySummary(proxy: ProxySpec): string {
  const head = proxy.mode === "local-clash"
    ? `Local Clash (${proxyHostPort(proxy)})`
    : `${proxy.type}://${proxyHostPort(proxy)}`;
  if (!proxy.preProxy) return head;
  const preHead = proxy.preProxy.mode === "local-clash"
    ? "Local Clash"
    : `${proxy.preProxy.type}://${proxyHostPort(proxy.preProxy)}`;
  return `${head} via ${preHead}`;
}

function canonicalIdentityUri(type: ProxySpec["type"], uri: string): string {
  const trimmed = uri.trim();
  if (!trimmed) return "";
  if (type === "vmess" && /^vmess:\/\//i.test(trimmed)) {
    try {
      const parsed = parseSingBoxUri(trimmed);
      if (parsed.type === "vmess") {
        const { label: _label, uri: _uri, ...rest } = parsed;
        return JSON.stringify(rest);
      }
    } catch {
      // Fall back to raw URI string.
    }
  }
  const hashIdx = trimmed.indexOf("#");
  return hashIdx >= 0 ? trimmed.slice(0, hashIdx) : trimmed;
}

/** In-memory identity only; never include this credential-bearing key in responses. */
export function proxyIdentityKey(input: ProxyInput | ProxySpec | null): string {
  const proxy = normalizeProxySpec(input);
  if (!proxy) return "null";
  const host = new URL(`http://${authorityHost(proxy.host)}/`).hostname.toLowerCase();
  const base = [proxy.type, host, proxy.port, proxy.user, proxy.pass];
  if (!proxy.uri && !proxy.preProxy && !proxy.mode) return JSON.stringify(base);
  return JSON.stringify([
    ...base,
    proxy.uri ? canonicalIdentityUri(proxy.type, proxy.uri) : "",
    proxy.preProxy ? proxyIdentityKey(proxy.preProxy) : "",
    ...(proxy.mode ? [proxy.mode] : []),
  ]);
}

/** Editable/export form, including optional credentials or full sing-box URI. */
export function proxyLegacyString(proxy: ProxySpec): string {
  if (proxy.mode === "local-clash") return "local-clash://";
  if (proxy.uri) return proxy.uri;
  const base = proxyHostPort(proxy);
  return proxy.user ? `${base}:${proxy.user}:${proxy.pass}` : base;
}

/** Render a canonical proxy URL suitable for CloakBrowser's --proxy-server (standard types only). */
export function proxyUrl(proxy: ProxySpec): string {
  if (proxy.uri) return proxy.uri;
  const auth = proxy.user
    ? `${encodeURIComponent(proxy.user)}:${encodeURIComponent(proxy.pass)}@`
    : "";
  return `${proxy.type}://${auth}${proxyHostPort(proxy)}`;
}
