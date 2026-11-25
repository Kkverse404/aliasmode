/**
 * Subscription fetcher and multi-format proxy node importer.
 *
 * Parses:
 *   1. Plain newline-delimited proxy URIs (vless, vmess, trojan, ss, hy2, tuic, wg, socks5, http, host:port[:u:p])
 *   2. Base64-encoded URI lists (standard V2Ray / airport subscriptions)
 *   3. Clash / Mihomo YAML (`proxies:` section, both block and inline `{ ... }` forms)
 *   4. sing-box JSON (`outbounds` / `endpoints`)
 */

import { parseProxySpec } from "./proxy.ts";
import { decodeBase64Flexible } from "./singbox-uri.ts";
import type { ProxySpec } from "./types.ts";

export interface SubscriptionUserInfo {
  upload?: number;
  download?: number;
  total?: number;
  expire?: number;
}

export interface ParsedPoolNode {
  name: string;
  proxy: ProxySpec;
}

export interface ParsedSubscriptionResult {
  format: "uri" | "base64" | "clash-yaml" | "singbox-json";
  nodes: ParsedPoolNode[];
  skipped: number;
}

const MAX_SUBSCRIPTION_BYTES = 10 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 20_000;

/** Parse airport `subscription-userinfo: upload=...; download=...; total=...; expire=...` header. */
export function parseSubscriptionUserInfo(header: string | null | undefined): SubscriptionUserInfo | undefined {
  if (!header) return undefined;
  const info: SubscriptionUserInfo = {};
  for (const part of header.split(";")) {
    const [k, v] = part.split("=").map((s) => s.trim());
    const num = Number(v);
    if (!k || !Number.isFinite(num) || num < 0) continue;
    const key = k.toLowerCase();
    if (key === "upload") info.upload = num;
    else if (key === "download") info.download = num;
    else if (key === "total") info.total = num;
    else if (key === "expire") info.expire = num;
  }
  return Object.keys(info).length ? info : undefined;
}

function defaultNodeName(proxy: ProxySpec, fallbackIndex: number): string {
  if (proxy.label?.trim()) return proxy.label.trim();
  return `${proxy.type.toUpperCase()} ${proxy.host}:${proxy.port}` || `Node ${fallbackIndex + 1}`;
}

function tryParseUriLines(lines: string[]): { nodes: ParsedPoolNode[]; skipped: number } {
  const nodes: ParsedPoolNode[] = [];
  let skipped = 0;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    try {
      const proxy = parseProxySpec("http", line);
      if (proxy) {
        nodes.push({ name: defaultNodeName(proxy, nodes.length), proxy });
      }
    } catch {
      skipped++;
    }
  }
  return { nodes, skipped };
}

function encodeUriQuery(params: Record<string, string | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") sp.set(k, v);
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

function formatHostForUri(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

/** Convert a Clash / Mihomo proxy entry object into a canonical ProxySpec. */
export function clashProxyToSpec(entry: Record<string, any>): ParsedPoolNode | null {
  const type = String(entry.type ?? "").trim().toLowerCase();
  const server = String(entry.server ?? "").trim();
  const port = String(entry.port ?? "").trim();
  const name = String(entry.name ?? "").trim();
  if (!type || !server || !port) return null;
  const hostUri = formatHostForUri(server);
  const hash = name ? `#${encodeURIComponent(name)}` : "";

  try {
    if (type === "http" || type === "https" || type === "socks5") {
      const user = String(entry.username ?? entry.user ?? "");
      const pass = String(entry.password ?? entry.pass ?? "");
      const proxy = parseProxySpec(type, `${hostUri}:${port}${user ? `:${user}:${pass}` : ""}`);
      if (!proxy) return null;
      if (name) proxy.label = name;
      return { name: defaultNodeName(proxy, 0), proxy };
    }

    if (type === "ss" || type === "shadowsocks") {
      const cipher = String(entry.cipher ?? entry.method ?? "").trim();
      const password = String(entry.password ?? "");
      if (!cipher) return null;
      const userinfo = Buffer.from(`${cipher}:${password}`, "utf8").toString("base64");
      const plugin = entry.plugin ? String(entry.plugin) : "";
      const pluginOpts = entry["plugin-opts"] && typeof entry["plugin-opts"] === "object"
        ? Object.entries(entry["plugin-opts"]).map(([k, v]) => `${k}=${v}`).join(";")
        : "";
      const q = plugin ? encodeUriQuery({ plugin: pluginOpts ? `${plugin};${pluginOpts}` : plugin }) : "";
      const uri = `ss://${userinfo}@${hostUri}:${port}${q}${hash}`;
      const proxy = parseProxySpec("ss", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }

    if (type === "vmess") {
      const uuid = String(entry.uuid ?? "").trim();
      if (!uuid) return null;
      const net = String(entry.network ?? "tcp").toLowerCase();
      const wsOpts = entry["ws-opts"] ?? {};
      const grpcOpts = entry["grpc-opts"] ?? {};
      const h2Opts = entry["h2-opts"] ?? {};
      const path = net === "ws" ? String(wsOpts.path ?? "/")
        : net === "grpc" ? String(grpcOpts["grpc-service-name"] ?? "")
        : net === "h2" ? String(Array.isArray(h2Opts.path) ? h2Opts.path[0] ?? "/" : h2Opts.path ?? "/")
        : "";
      const host = net === "ws" ? String(wsOpts.headers?.Host ?? wsOpts.headers?.host ?? "")
        : net === "h2" ? String(Array.isArray(h2Opts.host) ? h2Opts.host[0] ?? "" : h2Opts.host ?? "")
        : "";
      const payload = {
        v: "2",
        ps: name,
        add: server,
        port: Number(port),
        id: uuid,
        aid: Number(entry.alterId ?? 0) || 0,
        scy: String(entry.cipher ?? "auto"),
        net,
        type: "none",
        host,
        path,
        tls: entry.tls ? "tls" : "",
        sni: String(entry.servername ?? entry.sni ?? ""),
        alpn: Array.isArray(entry.alpn) ? entry.alpn.join(",") : String(entry.alpn ?? ""),
        fp: String(entry["client-fingerprint"] ?? ""),
        allowInsecure: entry["skip-cert-verify"] ? "1" : "",
      };
      const uri = `vmess://${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`;
      const proxy = parseProxySpec("vmess", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }

    if (type === "vless") {
      const uuid = String(entry.uuid ?? "").trim();
      if (!uuid) return null;
      const net = String(entry.network ?? "tcp").toLowerCase();
      const wsOpts = entry["ws-opts"] ?? {};
      const grpcOpts = entry["grpc-opts"] ?? {};
      const realityOpts = entry["reality-opts"] ?? {};
      const isReality = !!realityOpts["public-key"];
      const security = isReality ? "reality" : entry.tls ? "tls" : "none";
      const wsHost = wsOpts.headers?.Host ?? wsOpts.headers?.host;
      const q = encodeUriQuery({
        encryption: "none",
        security,
        type: net,
        flow: entry.flow ? String(entry.flow) : undefined,
        sni: entry.servername ? String(entry.servername) : entry.sni ? String(entry.sni) : undefined,
        fp: entry["client-fingerprint"] ? String(entry["client-fingerprint"]) : undefined,
        pbk: realityOpts["public-key"] ? String(realityOpts["public-key"]) : undefined,
        sid: realityOpts["short-id"] ? String(realityOpts["short-id"]) : undefined,
        alpn: Array.isArray(entry.alpn) ? entry.alpn.join(",") : undefined,
        allowInsecure: entry["skip-cert-verify"] ? "1" : undefined,
        path: net === "ws" ? String(wsOpts.path ?? "/") : undefined,
        host: net === "ws" && wsHost ? String(wsHost) : undefined,
        serviceName: net === "grpc" ? String(grpcOpts["grpc-service-name"] ?? "") : undefined,
      });
      const uri = `vless://${encodeURIComponent(uuid)}@${hostUri}:${port}${q}${hash}`;
      const proxy = parseProxySpec("vless", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }

    if (type === "trojan") {
      const password = String(entry.password ?? "");
      if (!password) return null;
      const net = String(entry.network ?? "tcp").toLowerCase();
      const wsOpts = entry["ws-opts"] ?? {};
      const grpcOpts = entry["grpc-opts"] ?? {};
      const realityOpts = entry["reality-opts"] ?? {};
      const isReality = !!realityOpts["public-key"];
      const wsHost = wsOpts.headers?.Host ?? wsOpts.headers?.host;
      const q = encodeUriQuery({
        security: isReality ? "reality" : "tls",
        type: net,
        sni: entry.sni ? String(entry.sni) : entry.servername ? String(entry.servername) : undefined,
        fp: entry["client-fingerprint"] ? String(entry["client-fingerprint"]) : undefined,
        pbk: realityOpts["public-key"] ? String(realityOpts["public-key"]) : undefined,
        sid: realityOpts["short-id"] ? String(realityOpts["short-id"]) : undefined,
        alpn: Array.isArray(entry.alpn) ? entry.alpn.join(",") : undefined,
        allowInsecure: entry["skip-cert-verify"] ? "1" : undefined,
        path: net === "ws" ? String(wsOpts.path ?? "/") : undefined,
        host: net === "ws" && wsHost ? String(wsHost) : undefined,
        serviceName: net === "grpc" ? String(grpcOpts["grpc-service-name"] ?? "") : undefined,
      });
      const uri = `trojan://${encodeURIComponent(password)}@${hostUri}:${port}${q}${hash}`;
      const proxy = parseProxySpec("trojan", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }

    if (type === "hysteria2" || type === "hy2") {
      const password = String(entry.password ?? "");
      if (!password) return null;
      const q = encodeUriQuery({
        sni: entry.sni ? String(entry.sni) : undefined,
        insecure: entry["skip-cert-verify"] ? "1" : undefined,
        obfs: entry.obfs ? String(entry.obfs) : undefined,
        "obfs-password": entry["obfs-password"] ? String(entry["obfs-password"]) : undefined,
        alpn: Array.isArray(entry.alpn) ? entry.alpn.join(",") : undefined,
      });
      const uri = `hysteria2://${encodeURIComponent(password)}@${hostUri}:${port}${q}${hash}`;
      const proxy = parseProxySpec("hysteria2", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }

    if (type === "tuic") {
      const uuid = String(entry.uuid ?? "").trim();
      const password = String(entry.password ?? "");
      if (!uuid) return null;
      const q = encodeUriQuery({
        sni: entry.sni ? String(entry.sni) : undefined,
        allow_insecure: entry["skip-cert-verify"] ? "1" : undefined,
        congestion_control: entry["congestion-controller"] ? String(entry["congestion-controller"]) : undefined,
        udp_relay_mode: entry["udp-relay-mode"] ? String(entry["udp-relay-mode"]) : undefined,
        alpn: Array.isArray(entry.alpn) ? entry.alpn.join(",") : undefined,
      });
      const uri = `tuic://${encodeURIComponent(uuid)}:${encodeURIComponent(password)}@${hostUri}:${port}${q}${hash}`;
      const proxy = parseProxySpec("tuic", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }

    if (type === "wireguard" || type === "wg") {
      const privateKey = String(entry["private-key"] ?? entry.private_key ?? "").trim();
      const publicKey = String(entry["public-key"] ?? entry["peer-public-key"] ?? entry.public_key ?? "").trim();
      if (!privateKey || !publicKey) return null;
      const addresses = [
        ...(Array.isArray(entry.ip) ? entry.ip : entry.ip ? [entry.ip] : []),
        ...(Array.isArray(entry.ipv6) ? entry.ipv6 : entry.ipv6 ? [entry.ipv6] : []),
      ].map((v) => String(v).trim()).filter(Boolean);
      const psk = String(entry["pre-shared-key"] ?? entry["preshared-key"] ?? entry.preshared_key ?? "").trim();
      const reserved = Array.isArray(entry.reserved)
        ? entry.reserved.map((n: unknown) => String(n).trim()).filter(Boolean).join(",")
        : typeof entry.reserved === "string"
          ? entry.reserved.trim()
          : "";
      const mtu = entry.mtu !== undefined && entry.mtu !== "" ? String(entry.mtu).trim() : "";
      const q = encodeUriQuery({
        publickey: publicKey,
        address: addresses.length ? addresses.join(",") : undefined,
        presharedkey: psk || undefined,
        reserved: reserved || undefined,
        mtu: mtu || undefined,
      });
      const uri = `wireguard://${encodeURIComponent(privateKey)}@${hostUri}:${port}${q}${hash}`;
      const proxy = parseProxySpec("wireguard", uri);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
  } catch {
    return null;
  }
  return null;
}

/** Parse a Clash flow-style inline object `- { name: "US", type: vless, ... }`. */
function parseFlowMap(text: string): Record<string, any> | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null;
  try {
    return JSON.parse(trimmed);
  } catch {
    // Relaxed YAML flow-style parser (unquoted keys / single-quoted strings / nested braces)
    const obj: Record<string, any> = {};
    const inner = trimmed.slice(1, -1);
    let i = 0;
    const skipWs = () => { while (i < inner.length && /[\s,]/.test(inner[i]!)) i++; };
    const readValue = (): any => {
      skipWs();
      if (i >= inner.length) return "";
      const ch = inner[i]!;
      if (ch === "{") {
        let depth = 0, quote = "";
        const start = i;
        while (i < inner.length) {
          const c = inner[i]!;
          if (quote) {
            if (c === "\\" && i + 1 < inner.length) { i += 2; continue; }
            if (c === quote) quote = "";
          } else if (c === "\"" || c === "'") quote = c;
          else if (c === "{") depth++;
          else if (c === "}") { depth--; if (depth === 0) { i++; break; } }
          i++;
        }
        return parseFlowMap(inner.slice(start, i)) ?? {};
      }
      if (ch === "[") {
        let depth = 0, quote = "";
        const start = i + 1;
        while (i < inner.length) {
          const c = inner[i]!;
          if (quote) {
            if (c === "\\" && i + 1 < inner.length) { i += 2; continue; }
            if (c === quote) quote = "";
          } else if (c === "\"" || c === "'") quote = c;
          else if (c === "[") depth++;
          else if (c === "]") { depth--; if (depth === 0) { i++; break; } }
          i++;
        }
        return inner.slice(start, i - 1).split(",").map((s) => unquoteYaml(s.trim())).filter(Boolean);
      }
      if (ch === "\"" || ch === "'") {
        const q = ch;
        i++;
        let out = "";
        while (i < inner.length && inner[i] !== q) {
          if (inner[i] === "\\" && q === "\"" && i + 1 < inner.length) { out += inner[i + 1]; i += 2; }
          else { out += inner[i]; i++; }
        }
        if (inner[i] === q) i++;
        return out;
      }
      const start = i;
      while (i < inner.length && inner[i] !== "," && inner[i] !== "}") i++;
      return coerceYamlScalar(inner.slice(start, i).trim());
    };
    while (i < inner.length) {
      skipWs();
      if (i >= inner.length) break;
      let key = "";
      if (inner[i] === "\"" || inner[i] === "'") {
        key = String(readValue());
      } else {
        const start = i;
        while (i < inner.length && inner[i] !== ":" && inner[i] !== ",") i++;
        key = inner.slice(start, i).trim();
      }
      while (i < inner.length && inner[i] === " ") i++;
      if (inner[i] !== ":") break;
      i++;
      const val = readValue();
      if (key) obj[key] = val;
    }
    return Object.keys(obj).length ? obj : null;
  }
}

function unquoteYaml(raw: string): string {
  const s = raw.trim();
  if ((s.startsWith("\"") && s.endsWith("\"")) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function coerceYamlScalar(raw: string): string | number | boolean {
  const s = raw.trim();
  if (s === "true") return true;
  if (s === "false") return false;
  if (/^-?\d+$/.test(s)) return Number(s);
  return unquoteYaml(s);
}

/** Lightweight parser for Clash/Mihomo YAML `proxies:` lists (inline and block items). */
function parseClashYamlProxies(text: string): Record<string, any>[] {
  const lines = text.split(/\r?\n/);
  const startIdx = lines.findIndex((line) => /^\s*proxies\s*:\s*$/.test(line));
  if (startIdx < 0) return [];
  const rootIndent = lines[startIdx]!.search(/\S/);
  const items: Record<string, any>[] = [];
  let current: Record<string, any> | null = null;
  let itemIndent = -1;
  let nestedKey: string | null = null;
  let nestedIndent = -1;
  let subNestedKey: string | null = null;

  const flush = () => {
    if (current && Object.keys(current).length) items.push(current);
    current = null;
    nestedKey = null;
    subNestedKey = null;
  };

  for (let idx = startIdx + 1; idx < lines.length; idx++) {
    const raw = lines[idx]!;
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const indent = raw.search(/\S/);
    if (indent <= rootIndent && !/^\s*-/.test(raw)) break;

    const dashMatch = raw.match(/^(\s*)-\s*(.*)$/);
    if (dashMatch && (itemIndent < 0 || indent <= itemIndent)) {
      flush();
      itemIndent = indent;
      const rest = dashMatch[2]!.trim();
      if (rest.startsWith("{")) {
        const parsed = parseFlowMap(rest);
        if (parsed) items.push(parsed);
        continue;
      }
      current = {};
      const kv = rest.match(/^([^:]+):\s*(.*)$/);
      if (kv) {
        const k = unquoteYaml(kv[1]!.trim());
        const v = kv[2]!.trim();
        if (v) current[k] = v.startsWith("{") ? (parseFlowMap(v) ?? v) : coerceYamlScalar(v);
        else { current[k] = {}; nestedKey = k; nestedIndent = indent + 2; }
      }
      continue;
    }

    if (!current) continue;
    const listItem = raw.match(/^\s*-\s+(.+)$/);
    if (listItem && nestedKey) {
      if (!Array.isArray(current[nestedKey])) current[nestedKey] = [];
      current[nestedKey].push(coerceYamlScalar(listItem[1]!));
      continue;
    }
    const kv = raw.trim().match(/^([^:]+):\s*(.*)$/);
    if (!kv) continue;
    const k = unquoteYaml(kv[1]!.trim());
    const v = kv[2]!.trim();
    if (nestedKey && indent > nestedIndent && subNestedKey && current[nestedKey]?.[subNestedKey]) {
      current[nestedKey][subNestedKey][k] = coerceYamlScalar(v);
    } else if (nestedKey && indent >= nestedIndent) {
      if (!v) {
        current[nestedKey][k] = {};
        subNestedKey = k;
      } else {
        current[nestedKey][k] = v.startsWith("{") ? (parseFlowMap(v) ?? v) : coerceYamlScalar(v);
        subNestedKey = null;
      }
    } else {
      nestedKey = null;
      subNestedKey = null;
      if (!v) {
        current[k] = {};
        nestedKey = k;
        nestedIndent = indent + 2;
      } else if (v.startsWith("[") && v.endsWith("]")) {
        current[k] = v.slice(1, -1).split(",").map((s) => unquoteYaml(s.trim())).filter(Boolean);
      } else {
        current[k] = v.startsWith("{") ? (parseFlowMap(v) ?? v) : coerceYamlScalar(v);
      }
    }
  }
  flush();
  return items;
}

/** Convert a sing-box outbound JSON entry to a ParsedPoolNode if it is a supported proxy type. */
function singBoxOutboundToNode(ob: Record<string, any>): ParsedPoolNode | null {
  const type = String(ob.type ?? "").trim().toLowerCase();
  const server = String(ob.server ?? "").trim();
  const port = ob.server_port;
  if (!type || !server || !port) return null;
  const name = String(ob.tag ?? "").trim();
  const hostUri = formatHostForUri(server);
  const hash = name ? `#${encodeURIComponent(name)}` : "";
  try {
    if (type === "socks" || type === "http") {
      const scheme = type === "socks" ? "socks5" : ob.tls?.enabled ? "https" : "http";
      const user = String(ob.username ?? "");
      const pass = String(ob.password ?? "");
      const proxy = parseProxySpec(scheme, `${hostUri}:${port}${user ? `:${user}:${pass}` : ""}`);
      if (!proxy) return null;
      if (name) proxy.label = name;
      return { name: defaultNodeName(proxy, 0), proxy };
    }
    if (type === "shadowsocks") {
      const userinfo = Buffer.from(`${ob.method}:${ob.password ?? ""}`, "utf8").toString("base64");
      const proxy = parseProxySpec("ss", `ss://${userinfo}@${hostUri}:${port}${hash}`);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
    if (type === "vless") {
      const tls = ob.tls ?? {};
      const reality = tls.reality ?? {};
      const transport = ob.transport ?? {};
      const security = reality.enabled ? "reality" : tls.enabled ? "tls" : "none";
      const q = encodeUriQuery({
        encryption: "none",
        security,
        type: transport.type || "tcp",
        flow: ob.flow,
        sni: tls.server_name,
        fp: tls.utls?.fingerprint,
        pbk: reality.public_key,
        sid: reality.short_id,
        alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : undefined,
        allowInsecure: tls.insecure ? "1" : undefined,
        path: transport.path,
        host: transport.headers?.Host || (Array.isArray(transport.host) ? transport.host[0] : transport.host),
        serviceName: transport.service_name,
      });
      const proxy = parseProxySpec("vless", `vless://${encodeURIComponent(ob.uuid)}@${hostUri}:${port}${q}${hash}`);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
    if (type === "trojan") {
      const tls = ob.tls ?? {};
      const reality = tls.reality ?? {};
      const transport = ob.transport ?? {};
      const q = encodeUriQuery({
        security: reality.enabled ? "reality" : tls.enabled === false ? "none" : "tls",
        type: transport.type || "tcp",
        sni: tls.server_name,
        fp: tls.utls?.fingerprint,
        pbk: reality.public_key,
        sid: reality.short_id,
        alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : undefined,
        allowInsecure: tls.insecure ? "1" : undefined,
        path: transport.path,
        host: transport.headers?.Host || (Array.isArray(transport.host) ? transport.host[0] : transport.host),
        serviceName: transport.service_name,
      });
      const proxy = parseProxySpec("trojan", `trojan://${encodeURIComponent(ob.password)}@${hostUri}:${port}${q}${hash}`);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
    if (type === "hysteria2") {
      const tls = ob.tls ?? {};
      const q = encodeUriQuery({
        sni: tls.server_name,
        insecure: tls.insecure ? "1" : undefined,
        obfs: ob.obfs?.type,
        "obfs-password": ob.obfs?.password,
        alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : undefined,
      });
      const proxy = parseProxySpec("hysteria2", `hysteria2://${encodeURIComponent(ob.password)}@${hostUri}:${port}${q}${hash}`);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
    if (type === "vmess") {
      const tls = ob.tls ?? {};
      const transport = ob.transport ?? {};
      const payload = {
        v: "2",
        ps: name,
        add: server,
        port: Number(port),
        id: ob.uuid,
        aid: ob.alter_id ?? 0,
        scy: ob.security ?? "auto",
        net: transport.type ?? "tcp",
        host: transport.headers?.Host || (Array.isArray(transport.host) ? transport.host[0] : transport.host) || "",
        path: transport.path || transport.service_name || "",
        tls: tls.enabled ? "tls" : "",
        sni: tls.server_name || "",
        alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : "",
        fp: tls.utls?.fingerprint || "",
        allowInsecure: tls.insecure ? "1" : "",
      };
      const proxy = parseProxySpec("vmess", `vmess://${Buffer.from(JSON.stringify(payload), "utf8").toString("base64")}`);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
    if (type === "tuic") {
      const tls = ob.tls ?? {};
      const q = encodeUriQuery({
        sni: tls.server_name,
        allow_insecure: tls.insecure ? "1" : undefined,
        congestion_control: ob.congestion_control,
        udp_relay_mode: ob.udp_relay_mode,
        alpn: Array.isArray(tls.alpn) ? tls.alpn.join(",") : undefined,
      });
      const proxy = parseProxySpec("tuic", `tuic://${encodeURIComponent(ob.uuid)}:${encodeURIComponent(ob.password ?? "")}@${hostUri}:${port}${q}${hash}`);
      return proxy ? { name: defaultNodeName(proxy, 0), proxy } : null;
    }
  } catch {
    return null;
  }
  return null;
}

/** Auto-detect and parse raw subscription or pasted proxy list text. */
export function parseSubscriptionContent(rawText: string): ParsedSubscriptionResult {
  const trimmed = rawText.replace(/^\uFEFF/, "").trim();
  if (!trimmed) return { format: "uri", nodes: [], skipped: 0 };

  // 1. sing-box JSON format
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as { outbounds?: unknown };
      if (Array.isArray(parsed.outbounds)) {
        const nodes: ParsedPoolNode[] = [];
        let skipped = 0;
        for (const item of parsed.outbounds) {
          if (!item || typeof item !== "object") continue;
          const t = String((item as any).type ?? "").toLowerCase();
          if (["direct", "block", "dns", "selector", "urltest"].includes(t)) continue;
          const converted = singBoxOutboundToNode(item as Record<string, any>);
          if (converted) nodes.push(converted);
          else skipped++;
        }
        return { format: "singbox-json", nodes, skipped };
      }
    } catch {
      // Fall through to other formats
    }
  }

  // 2. Clash / Mihomo YAML format
  if (/^\s*proxies\s*:\s*$/m.test(trimmed)) {
    const entries = parseClashYamlProxies(trimmed);
    const nodes: ParsedPoolNode[] = [];
    let skipped = 0;
    for (const entry of entries) {
      const converted = clashProxyToSpec(entry);
      if (converted) nodes.push(converted);
      else skipped++;
    }
    if (nodes.length > 0 || entries.length > 0) {
      return { format: "clash-yaml", nodes, skipped };
    }
  }

  // 3. Direct URI / host:port lines
  const directLines = trimmed.split(/\r?\n/);
  const hasExplicitScheme = directLines.some((line) => /^[a-z][a-z0-9+.-]*:\/\//i.test(line.trim()));
  if (hasExplicitScheme) {
    return { format: "uri", ...tryParseUriLines(directLines) };
  }

  // 4. Base64-encoded URI list (typical V2Ray subscription body)
  if (!trimmed.includes(":") && /^[A-Za-z0-9+/=_\-\r\n]+$/.test(trimmed)) {
    try {
      const decoded = decodeBase64Flexible(trimmed);
      const decodedLines = decoded.split(/\r?\n/);
      if (decodedLines.some((line) => /^[a-z][a-z0-9+.-]*:\/\//i.test(line.trim()))) {
        return { format: "base64", ...tryParseUriLines(decodedLines) };
      }
    } catch {
      // Fall through
    }
  }

  // 5. Fallback: plain host:port[:user:pass] lines
  return { format: "uri", ...tryParseUriLines(directLines) };
}

export interface FetchSubscriptionOptions {
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  /** Optional HTTP proxy URL (e.g. local Clash http://127.0.0.1:7897) to fetch blocked subscription URLs. */
  proxyUrl?: string;
}

/** Fetch a remote http(s) proxy subscription URL and parse its nodes + userinfo header. */
export async function fetchProxySubscription(
  rawUrl: string,
  opts: FetchSubscriptionOptions = {},
): Promise<ParsedSubscriptionResult & { userInfo?: SubscriptionUserInfo }> {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw new Error("invalid subscription URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("subscription URL must use http or https");
  }
  const fetchFn = opts.fetchFn ?? fetch;
  const init: RequestInit & { proxy?: string } = {
    method: "GET",
    headers: {
      "User-Agent": "sing-box/1.14.4 (clash.meta)",
      Accept: "*/*",
    },
    signal: AbortSignal.timeout(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    ...(opts.proxyUrl ? { proxy: opts.proxyUrl } : {}),
  };
  const response = await fetchFn(url.toString(), init);
  if (!response.ok) {
    throw new Error(`subscription server returned HTTP ${response.status}`);
  }
  const contentLength = Number(response.headers.get("content-length") ?? 0);
  if (contentLength > MAX_SUBSCRIPTION_BYTES) {
    throw new Error("subscription response exceeds 10 MB limit");
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAX_SUBSCRIPTION_BYTES) {
    throw new Error("subscription response exceeds 10 MB limit");
  }
  const parsed = parseSubscriptionContent(text);
  const userInfo = parseSubscriptionUserInfo(response.headers.get("subscription-userinfo"));
  return { ...parsed, ...(userInfo ? { userInfo } : {}) };
}
