/**
 * Parser and normalizer for sing-box proxy share URIs.
 *
 * Supports: vless, vmess, trojan, ss (shadowsocks incl. SS-2022),
 * hysteria2 / hy2, tuic, wireguard / wg.
 */

import { isIP } from "node:net";
import type { SingBoxProxyType } from "./types.ts";

export const SINGBOX_PROXY_TYPES = new Set<SingBoxProxyType>([
  "vless",
  "vmess",
  "trojan",
  "ss",
  "hysteria2",
  "tuic",
  "wireguard",
]);

export function isSingBoxProxyType(value: unknown): value is SingBoxProxyType {
  return typeof value === "string" && SINGBOX_PROXY_TYPES.has(value as SingBoxProxyType);
}

export function normalizeSingBoxScheme(scheme: string): SingBoxProxyType | null {
  const s = scheme.trim().toLowerCase().replace(/:$/, "");
  if (s === "vless") return "vless";
  if (s === "vmess") return "vmess";
  if (s === "trojan") return "trojan";
  if (s === "ss" || s === "shadowsocks") return "ss";
  if (s === "hysteria2" || s === "hy2") return "hysteria2";
  if (s === "tuic") return "tuic";
  if (s === "wireguard" || s === "wg") return "wireguard";
  return null;
}

export interface SingBoxTlsConfig {
  enabled: boolean;
  serverName?: string;
  insecure?: boolean;
  alpn?: string[];
  fingerprint?: string;
  reality?: {
    enabled: boolean;
    publicKey: string;
    shortId?: string;
  };
}

export interface SingBoxTransportConfig {
  type: "ws" | "grpc" | "http" | "httpupgrade";
  path?: string;
  host?: string;
  headers?: Record<string, string>;
  serviceName?: string;
}

export interface ParsedVlessNode {
  type: "vless";
  host: string;
  port: number;
  label: string;
  uri: string;
  uuid: string;
  flow?: string;
  packetEncoding?: string;
  tls?: SingBoxTlsConfig;
  transport?: SingBoxTransportConfig;
}

export interface ParsedVmessNode {
  type: "vmess";
  host: string;
  port: number;
  label: string;
  uri: string;
  uuid: string;
  alterId: number;
  security: string;
  tls?: SingBoxTlsConfig;
  transport?: SingBoxTransportConfig;
}

export interface ParsedTrojanNode {
  type: "trojan";
  host: string;
  port: number;
  label: string;
  uri: string;
  password: string;
  tls?: SingBoxTlsConfig;
  transport?: SingBoxTransportConfig;
}

export interface ParsedShadowsocksNode {
  type: "ss";
  host: string;
  port: number;
  label: string;
  uri: string;
  method: string;
  password: string;
  plugin?: string;
  pluginOpts?: string;
}

export interface ParsedHysteria2Node {
  type: "hysteria2";
  host: string;
  port: number;
  label: string;
  uri: string;
  password: string;
  upMbps?: number;
  downMbps?: number;
  obfs?: { type: string; password: string };
  tls: SingBoxTlsConfig;
}

export interface ParsedTuicNode {
  type: "tuic";
  host: string;
  port: number;
  label: string;
  uri: string;
  uuid: string;
  password: string;
  congestionControl?: string;
  udpRelayMode?: string;
  zeroRttHandshake?: boolean;
  tls: SingBoxTlsConfig;
}

export interface ParsedWireGuardNode {
  type: "wireguard";
  host: string;
  port: number;
  label: string;
  uri: string;
  privateKey: string;
  peerPublicKey: string;
  preSharedKey?: string;
  localAddresses: string[];
  reserved?: number[];
  mtu?: number;
}

export type ParsedSingBoxNode =
  | ParsedVlessNode
  | ParsedVmessNode
  | ParsedTrojanNode
  | ParsedShadowsocksNode
  | ParsedHysteria2Node
  | ParsedTuicNode
  | ParsedWireGuardNode;

export function decodeBase64Flexible(raw: string): string {
  const cleaned = raw.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const padded = cleaned.length % 4 === 0 ? cleaned : cleaned + "=".repeat(4 - (cleaned.length % 4));
  return Buffer.from(padded, "base64").toString("utf8");
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function validateHost(raw: string): string {
  const trimmed = raw.trim();
  const host = trimmed.startsWith("[") && trimmed.endsWith("]") ? trimmed.slice(1, -1) : trimmed;
  if (!host) throw new Error("proxy host is empty");
  if (/[\s\u0000-\u001f\u007f]/.test(host)) throw new Error("proxy host contains whitespace or control characters");
  if (/[\[\]\\/@?#%]/.test(host)) throw new Error("proxy host contains invalid characters");
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

function validatePort(raw: string | number): number {
  const text = String(raw ?? "").trim();
  const port = Number(text);
  if (!/^\d+$/.test(text) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid proxy port: ${text || "(empty)"}`);
  }
  return port;
}

function parseBoolParam(value: string | null): boolean {
  if (!value) return false;
  const v = value.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

function parseAlpn(value: string | null | undefined): string[] | undefined {
  if (!value) return undefined;
  const list = value.split(",").map((s) => s.trim()).filter(Boolean);
  return list.length ? list : undefined;
}

function parseTransportFromParams(params: URLSearchParams): SingBoxTransportConfig | undefined {
  const netType = (params.get("type") ?? params.get("net") ?? "tcp").trim().toLowerCase();
  if (!netType || netType === "tcp" || netType === "raw" || netType === "none") return undefined;
  if (netType === "ws" || netType === "websocket") {
    const path = params.get("path") || "/";
    const host = params.get("host") || undefined;
    return {
      type: "ws",
      path,
      ...(host ? { host, headers: { Host: host } } : {}),
    };
  }
  if (netType === "grpc") {
    const serviceName = params.get("serviceName") || params.get("service_name") || params.get("path") || "";
    return { type: "grpc", ...(serviceName ? { serviceName } : {}) };
  }
  if (netType === "http" || netType === "h2") {
    const path = params.get("path") || "/";
    const host = params.get("host") || undefined;
    return { type: "http", path, ...(host ? { host } : {}) };
  }
  if (netType === "httpupgrade" || netType === "xhttp" || netType === "splithttp") {
    const path = params.get("path") || "/";
    const host = params.get("host") || undefined;
    return { type: "httpupgrade", path, ...(host ? { host } : {}) };
  }
  return undefined;
}

function parseTlsFromParams(
  params: URLSearchParams,
  fallbackHost: string,
  defaultTls: boolean,
): SingBoxTlsConfig | undefined {
  const security = (params.get("security") ?? "").trim().toLowerCase();
  if (security === "none") return undefined;
  const isReality = security === "reality" || !!params.get("pbk");
  const isTls = isReality || security === "tls" || security === "xtls" || defaultTls;
  if (!isTls) return undefined;
  const serverName = (params.get("sni") || params.get("peer") || params.get("host") || fallbackHost).trim();
  const insecure = parseBoolParam(params.get("allowInsecure") ?? params.get("insecure") ?? params.get("skip-cert-verify"));
  const alpn = parseAlpn(params.get("alpn"));
  const fingerprint = (params.get("fp") || params.get("fingerprint") || (isReality ? "chrome" : "")).trim() || undefined;
  const pbk = (params.get("pbk") || "").trim();
  const sid = (params.get("sid") || "").trim();
  if (isReality && !pbk) throw new Error("VLESS/Trojan reality URI is missing public key (pbk)");
  return {
    enabled: true,
    ...(serverName ? { serverName } : {}),
    ...(insecure ? { insecure: true } : {}),
    ...(alpn ? { alpn } : {}),
    ...(fingerprint ? { fingerprint } : {}),
    ...(isReality ? { reality: { enabled: true, publicKey: pbk, ...(sid ? { shortId: sid } : {}) } } : {}),
  };
}

function parseUrlSafe(raw: string): URL {
  try {
    return new URL(raw);
  } catch {
    throw new Error("invalid proxy share URI");
  }
}

function parseVless(raw: string): ParsedVlessNode {
  const url = parseUrlSafe(raw);
  const host = validateHost(url.hostname);
  const port = validatePort(url.port);
  const uuid = safeDecode(url.username).trim();
  if (!uuid) throw new Error("VLESS URI is missing UUID");
  const params = url.searchParams;
  const flow = (params.get("flow") ?? "").trim() || undefined;
  const packetEncoding = (params.get("packetEncoding") ?? params.get("packet_encoding") ?? "").trim() || undefined;
  const tls = parseTlsFromParams(params, host, false);
  const transport = parseTransportFromParams(params);
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return {
    type: "vless",
    host,
    port,
    label,
    uri: raw.trim(),
    uuid,
    ...(flow ? { flow } : {}),
    ...(packetEncoding ? { packetEncoding } : {}),
    ...(tls ? { tls } : {}),
    ...(transport ? { transport } : {}),
  };
}

function parseVmess(raw: string): ParsedVmessNode {
  const trimmed = raw.trim();
  const payload = trimmed.slice("vmess://".length);
  // Standard V2RayN Base64 JSON format: vmess://<base64-json>
  if (!payload.includes("@")) {
    const hashIdx = payload.indexOf("#");
    const b64Part = hashIdx >= 0 ? payload.slice(0, hashIdx) : payload;
    const hashLabel = hashIdx >= 0 ? safeDecode(payload.slice(hashIdx + 1)).trim() : "";
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(decodeBase64Flexible(b64Part)) as Record<string, unknown>;
    } catch {
      throw new Error("invalid VMess base64 JSON URI");
    }
    if (!json || typeof json !== "object" || Array.isArray(json)) {
      throw new Error("invalid VMess JSON payload");
    }
    const host = validateHost(String(json.add ?? ""));
    const port = validatePort(String(json.port ?? ""));
    const uuid = String(json.id ?? "").trim();
    if (!uuid) throw new Error("VMess URI is missing UUID (id)");
    const alterId = Number.isFinite(Number(json.aid)) ? Math.max(0, Math.floor(Number(json.aid))) : 0;
    const security = String(json.scy ?? json.security ?? "auto").trim() || "auto";
    const label = String(json.ps ?? "").trim() || hashLabel;

    const net = String(json.net ?? "tcp").trim().toLowerCase();
    const path = String(json.path ?? "").trim();
    const reqHost = String(json.host ?? "").trim();
    let transport: SingBoxTransportConfig | undefined;
    if (net === "ws" || net === "websocket") {
      transport = { type: "ws", path: path || "/", ...(reqHost ? { host: reqHost, headers: { Host: reqHost } } : {}) };
    } else if (net === "grpc") {
      transport = { type: "grpc", ...(path ? { serviceName: path } : {}) };
    } else if (net === "h2" || net === "http") {
      transport = { type: "http", path: path || "/", ...(reqHost ? { host: reqHost } : {}) };
    } else if (net === "httpupgrade") {
      transport = { type: "httpupgrade", path: path || "/", ...(reqHost ? { host: reqHost } : {}) };
    }

    const tlsRaw = String(json.tls ?? "").trim().toLowerCase();
    let tls: SingBoxTlsConfig | undefined;
    if (tlsRaw === "tls" || tlsRaw === "1" || tlsRaw === "true") {
      const serverName = String(json.sni ?? reqHost ?? host).trim();
      const insecure = parseBoolParam(String(json.skipCertVerify ?? json.allowInsecure ?? ""));
      const alpn = parseAlpn(typeof json.alpn === "string" ? json.alpn : undefined);
      const fingerprint = String(json.fp ?? "").trim() || undefined;
      tls = {
        enabled: true,
        ...(serverName ? { serverName } : {}),
        ...(insecure ? { insecure: true } : {}),
        ...(alpn ? { alpn } : {}),
        ...(fingerprint ? { fingerprint } : {}),
      };
    }

    return {
      type: "vmess",
      host,
      port,
      label,
      uri: trimmed,
      uuid,
      alterId,
      security,
      ...(tls ? { tls } : {}),
      ...(transport ? { transport } : {}),
    };
  }

  // URL-style VMess: vmess://uuid@host:port?...#label
  const url = parseUrlSafe(trimmed);
  const host = validateHost(url.hostname);
  const port = validatePort(url.port);
  const uuid = safeDecode(url.username).trim();
  if (!uuid) throw new Error("VMess URI is missing UUID");
  const params = url.searchParams;
  const alterId = Number.isFinite(Number(params.get("aid") ?? "0")) ? Math.max(0, Math.floor(Number(params.get("aid") ?? "0"))) : 0;
  const security = (params.get("encryption") || params.get("scy") || "auto").trim();
  const tls = parseTlsFromParams(params, host, false);
  const transport = parseTransportFromParams(params);
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return {
    type: "vmess",
    host,
    port,
    label,
    uri: trimmed,
    uuid,
    alterId,
    security,
    ...(tls ? { tls } : {}),
    ...(transport ? { transport } : {}),
  };
}

function parseTrojan(raw: string): ParsedTrojanNode {
  const url = parseUrlSafe(raw);
  const host = validateHost(url.hostname);
  const port = validatePort(url.port);
  const password = safeDecode(url.username);
  if (!password) throw new Error("Trojan URI is missing password");
  const params = url.searchParams;
  const tls = parseTlsFromParams(params, host, true);
  const transport = parseTransportFromParams(params);
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return {
    type: "trojan",
    host,
    port,
    label,
    uri: raw.trim(),
    password,
    ...(tls ? { tls } : {}),
    ...(transport ? { transport } : {}),
  };
}

function parseShadowsocks(raw: string): ParsedShadowsocksNode {
  const trimmed = raw.trim();
  const afterScheme = trimmed.replace(/^(?:ss|shadowsocks):\/\//i, "");
  const hashIdx = afterScheme.indexOf("#");
  const label = hashIdx >= 0 ? safeDecode(afterScheme.slice(hashIdx + 1)).trim() : "";
  const withoutHash = hashIdx >= 0 ? afterScheme.slice(0, hashIdx) : afterScheme;
  const queryIdx = withoutHash.indexOf("?");
  const queryStr = queryIdx >= 0 ? withoutHash.slice(queryIdx + 1) : "";
  const authority = queryIdx >= 0 ? withoutHash.slice(0, queryIdx) : withoutHash;

  let method = "";
  let password = "";
  let host = "";
  let port = 0;

  if (authority.includes("@")) {
    // SIP002: userinfo@host:port (userinfo may be base64(method:password) or plain method:password)
    const atIdx = authority.lastIndexOf("@");
    const userinfoRaw = safeDecode(authority.slice(0, atIdx));
    const hostPort = authority.slice(atIdx + 1);
    const decodedInfo = userinfoRaw.includes(":") ? userinfoRaw : decodeBase64Flexible(userinfoRaw);
    const colonIdx = decodedInfo.indexOf(":");
    if (colonIdx <= 0) throw new Error("Shadowsocks URI has invalid method:password");
    method = decodedInfo.slice(0, colonIdx).trim();
    password = decodedInfo.slice(colonIdx + 1);
    const parsedHostPort = parseUrlSafe(`http://${hostPort}`);
    host = validateHost(parsedHostPort.hostname);
    port = validatePort(parsedHostPort.port);
  } else {
    // Legacy full base64: ss://base64(method:password@host:port)
    const decoded = decodeBase64Flexible(authority);
    const atIdx = decoded.lastIndexOf("@");
    if (atIdx <= 0) throw new Error("invalid Shadowsocks base64 URI");
    const creds = decoded.slice(0, atIdx);
    const hostPort = decoded.slice(atIdx + 1);
    const colonIdx = creds.indexOf(":");
    if (colonIdx <= 0) throw new Error("Shadowsocks URI has invalid method:password");
    method = creds.slice(0, colonIdx).trim();
    password = creds.slice(colonIdx + 1);
    const parsedHostPort = parseUrlSafe(`http://${hostPort}`);
    host = validateHost(parsedHostPort.hostname);
    port = validatePort(parsedHostPort.port);
  }

  if (!method) throw new Error("Shadowsocks URI is missing encryption method");
  let plugin: string | undefined;
  let pluginOpts: string | undefined;
  if (queryStr) {
    const params = new URLSearchParams(queryStr);
    const pluginParam = params.get("plugin");
    if (pluginParam) {
      const semiIdx = pluginParam.indexOf(";");
      if (semiIdx >= 0) {
        plugin = pluginParam.slice(0, semiIdx).trim();
        pluginOpts = pluginParam.slice(semiIdx + 1).trim();
      } else {
        plugin = pluginParam.trim();
      }
    }
  }

  return {
    type: "ss",
    host,
    port,
    label,
    uri: trimmed,
    method,
    password,
    ...(plugin ? { plugin } : {}),
    ...(pluginOpts ? { pluginOpts } : {}),
  };
}

function parseHysteria2(raw: string): ParsedHysteria2Node {
  const trimmed = raw.trim();
  const normalizedForUrl = trimmed.replace(/^hy2:\/\//i, "hysteria2://");
  const url = parseUrlSafe(normalizedForUrl);
  const host = validateHost(url.hostname);
  const port = validatePort(url.port || "443");
  const password = url.password
    ? `${safeDecode(url.username)}:${safeDecode(url.password)}`
    : safeDecode(url.username);
  if (!password) throw new Error("Hysteria2 URI is missing password");
  const params = url.searchParams;
  const serverName = (params.get("sni") || host).trim();
  const insecure = parseBoolParam(params.get("insecure") ?? params.get("allowInsecure") ?? params.get("skip-cert-verify"));
  const alpn = parseAlpn(params.get("alpn"));
  const obfsType = (params.get("obfs") ?? "").trim();
  const obfsPassword = (params.get("obfs-password") ?? "").trim();
  const upMbps = params.get("upmbps") ? Number(params.get("upmbps")) : undefined;
  const downMbps = params.get("downmbps") ? Number(params.get("downmbps")) : undefined;
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return {
    type: "hysteria2",
    host,
    port,
    label,
    uri: trimmed,
    password,
    ...(Number.isFinite(upMbps) && upMbps! > 0 ? { upMbps: Math.floor(upMbps!) } : {}),
    ...(Number.isFinite(downMbps) && downMbps! > 0 ? { downMbps: Math.floor(downMbps!) } : {}),
    ...(obfsType && obfsType !== "none" ? { obfs: { type: obfsType, password: obfsPassword } } : {}),
    tls: {
      enabled: true,
      ...(serverName ? { serverName } : {}),
      ...(insecure ? { insecure: true } : {}),
      ...(alpn ? { alpn } : {}),
    },
  };
}

function parseTuic(raw: string): ParsedTuicNode {
  const url = parseUrlSafe(raw.trim());
  const host = validateHost(url.hostname);
  const port = validatePort(url.port || "443");
  const uuid = safeDecode(url.username).trim();
  const password = safeDecode(url.password);
  if (!uuid) throw new Error("TUIC URI is missing UUID");
  const params = url.searchParams;
  const serverName = (params.get("sni") || host).trim();
  const insecure = parseBoolParam(params.get("allow_insecure") ?? params.get("insecure") ?? params.get("allowInsecure"));
  const alpn = parseAlpn(params.get("alpn"));
  const congestionControl = (params.get("congestion_control") ?? "bbr").trim() || undefined;
  const udpRelayMode = (params.get("udp_relay_mode") ?? "").trim() || undefined;
  const zeroRttHandshake = parseBoolParam(params.get("reduce_rtt") ?? params.get("zero_rtt_handshake"));
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return {
    type: "tuic",
    host,
    port,
    label,
    uri: raw.trim(),
    uuid,
    password,
    ...(congestionControl ? { congestionControl } : {}),
    ...(udpRelayMode ? { udpRelayMode } : {}),
    ...(zeroRttHandshake ? { zeroRttHandshake: true } : {}),
    tls: {
      enabled: true,
      ...(serverName ? { serverName } : {}),
      ...(insecure ? { insecure: true } : {}),
      ...(alpn ? { alpn } : {}),
    },
  };
}

function parseWireGuard(raw: string): ParsedWireGuardNode {
  const trimmed = raw.trim();
  const normalizedForUrl = trimmed.replace(/^wg:\/\//i, "wireguard://");
  const url = parseUrlSafe(normalizedForUrl);
  const host = validateHost(url.hostname);
  const port = validatePort(url.port || "51820");
  const privateKey = safeDecode(url.username).trim();
  const params = url.searchParams;
  const peerPublicKey = (params.get("publickey") || params.get("public_key") || params.get("pubkey") || "").trim();
  if (!privateKey) throw new Error("WireGuard URI is missing private key");
  if (!peerPublicKey) throw new Error("WireGuard URI is missing peer publickey");
  const addressRaw = (params.get("address") || params.get("ip") || "10.0.0.2/32").trim();
  const localAddresses = addressRaw
    .split(",")
    .map((addr) => addr.trim())
    .filter(Boolean)
    .map((addr) => (addr.includes("/") ? addr : addr.includes(":") ? `${addr}/128` : `${addr}/32`));
  const preSharedKey = (params.get("presharedkey") || params.get("pre_shared_key") || params.get("psk") || "").trim() || undefined;
  const mtuVal = params.get("mtu") ? Number(params.get("mtu")) : undefined;
  const reservedRaw = (params.get("reserved") ?? "").trim();
  let reserved: number[] | undefined;
  if (reservedRaw) {
    const nums = reservedRaw.split(",").map((n) => Number(n.trim()));
    if (nums.length === 3 && nums.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      reserved = nums;
    }
  }
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return {
    type: "wireguard",
    host,
    port,
    label,
    uri: trimmed,
    privateKey,
    peerPublicKey,
    ...(preSharedKey ? { preSharedKey } : {}),
    localAddresses,
    ...(reserved ? { reserved } : {}),
    ...(Number.isFinite(mtuVal) && mtuVal! >= 576 && mtuVal! <= 65535 ? { mtu: Math.floor(mtuVal!) } : {}),
  };
}

/** Parse any supported sing-box share URI into a validated structured node. */
export function parseSingBoxUri(raw: string): ParsedSingBoxNode {
  const trimmed = raw.trim();
  const match = trimmed.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (!match) throw new Error("proxy URI must start with a protocol scheme");
  const type = normalizeSingBoxScheme(match[1]!);
  if (!type) throw new Error(`unsupported sing-box proxy scheme: ${match[1]}`);
  switch (type) {
    case "vless": return parseVless(trimmed);
    case "vmess": return parseVmess(trimmed);
    case "trojan": return parseTrojan(trimmed);
    case "ss": return parseShadowsocks(trimmed);
    case "hysteria2": return parseHysteria2(trimmed);
    case "tuic": return parseTuic(trimmed);
    case "wireguard": return parseWireGuard(trimmed);
  }
}
