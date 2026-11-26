/**
 * Builds a minimal, leak-free sing-box configuration (compatible with sing-box 1.12–1.14+)
 * for a single profile proxy or multi-hop proxy chain (`preProxy`).
 *
 * Traffic flow:
 *   Browser / Fetch -> 127.0.0.1:<listenPort> (mixed HTTP+SOCKS5 inbound)
 *                   -> target outbound ("proxy")
 *                   --[detour]--> preProxy outbound ("chain-N") -> ... -> Internet
 *
 * Domain resolution for the browser's target websites stays at the exit proxy;
 * local DNS is configured only as `default_domain_resolver` so sing-box can
 * resolve the proxy server's own hostname.
 */

import type { ProxySpec } from "./types.ts";
import { isSingBoxProxyType, parseSingBoxUri, type ParsedSingBoxNode, type SingBoxTlsConfig, type SingBoxTransportConfig } from "./singbox-uri.ts";

export const MAX_PROXY_CHAIN_DEPTH = 4;

export interface SingBoxConfig {
  log: { level: string; timestamp: boolean };
  dns: {
    servers: Array<Record<string, unknown>>;
    rules?: Array<Record<string, unknown>>;
    final?: string;
  };
  inbounds: Array<Record<string, unknown>>;
  outbounds: Array<Record<string, unknown>>;
  endpoints?: Array<Record<string, unknown>>;
  route: Record<string, unknown>;
}

export interface BuildSingBoxConfigOptions {
  /** Pre-resolved IPv4/IPv6 addresses keyed by lowercase proxy hostname to avoid cold per-process DoH stalls. */
  predefinedHosts?: Record<string, string[]>;
}

/**
 * Build pure-IP DoH (TCP 443) DNS config for resolving proxy server hostnames.
 * Avoids `{ type: "local" }` because Clash/Mihomo TUN hijacks system DNS to a
 * virtual Fake-IP (`198.18.0.2`) and some local networks block direct UDP/53.
 */
function buildSingBoxDnsConfig(): {
  dns: SingBoxConfig["dns"];
  resolverTag: string;
} {
  const override = process.env.ALIASMODE_SINGBOX_DNS?.trim();
  if (override === "local") {
    return {
      dns: { servers: [{ type: "local", tag: "local" }] },
      resolverTag: "local",
    };
  }
  if (override) {
    try {
      const parsed = new URL(/^https?:\/\//i.test(override) ? override : `https://${override}/dns-query`);
      const host = parsed.hostname.replace(/^\[|\]$/g, "");
      if (host) {
        return {
          dns: {
            servers: [
              {
                type: "https",
                tag: "doh-custom",
                server: host,
                server_port: parsed.port ? Number(parsed.port) : 443,
                path: parsed.pathname && parsed.pathname !== "/" ? parsed.pathname : "/dns-query",
              },
            ],
            final: "doh-custom",
          },
          resolverTag: "doh-custom",
        };
      }
    } catch {
      // Fall back to built-in pure-IP DoH defaults.
    }
  }
  return {
    dns: {
      servers: [
        { type: "https", tag: "doh-ali", server: "223.5.5.5", server_port: 443, path: "/dns-query" },
        { type: "https", tag: "doh-ali-backup", server: "223.6.6.6", server_port: 443, path: "/dns-query" },
        { type: "https", tag: "doh-dnspod", server: "1.12.12.12", server_port: 443, path: "/dns-query" },
      ],
      final: "doh-ali",
    },
    resolverTag: "doh-ali",
  };
}

function isLoopbackServer(host: string): boolean {
  const normalized = host.trim().replace(/^\[|\]$/g, "").toLowerCase();
  return normalized === "localhost"
    || normalized === "::1"
    || normalized === "127.0.0.1"
    || normalized.startsWith("127.");
}

function buildTlsObject(tls?: SingBoxTlsConfig): Record<string, unknown> | undefined {
  if (!tls?.enabled) return undefined;
  return {
    enabled: true,
    ...(tls.serverName ? { server_name: tls.serverName } : {}),
    ...(tls.insecure ? { insecure: true } : {}),
    ...(tls.alpn?.length ? { alpn: tls.alpn } : {}),
    ...(tls.fingerprint ? { utls: { enabled: true, fingerprint: tls.fingerprint } } : {}),
    ...(tls.reality?.enabled ? {
      reality: {
        enabled: true,
        public_key: tls.reality.publicKey,
        ...(tls.reality.shortId ? { short_id: tls.reality.shortId } : {}),
      },
    } : {}),
  };
}

function buildTransportObject(transport?: SingBoxTransportConfig): Record<string, unknown> | undefined {
  if (!transport) return undefined;
  if (transport.type === "ws") {
    return {
      type: "ws",
      path: transport.path || "/",
      ...(transport.headers ? { headers: transport.headers } : transport.host ? { headers: { Host: transport.host } } : {}),
    };
  }
  if (transport.type === "grpc") {
    return {
      type: "grpc",
      ...(transport.serviceName ? { service_name: transport.serviceName } : {}),
    };
  }
  if (transport.type === "http") {
    return {
      type: "http",
      path: transport.path || "/",
      ...(transport.host ? { host: [transport.host] } : {}),
    };
  }
  if (transport.type === "httpupgrade") {
    return {
      type: "httpupgrade",
      path: transport.path || "/",
      ...(transport.host ? { host: transport.host } : {}),
    };
  }
  return undefined;
}

function buildParsedNodeOutbound(
  node: ParsedSingBoxNode,
  tag: string,
  detour?: string,
): { kind: "outbound" | "endpoint"; entry: Record<string, unknown> } {
  const dialer = detour ? { detour } : {};
  switch (node.type) {
    case "vless": {
      const tls = buildTlsObject(node.tls);
      const transport = buildTransportObject(node.transport);
      return {
        kind: "outbound",
        entry: {
          type: "vless",
          tag,
          server: node.host,
          server_port: node.port,
          uuid: node.uuid,
          ...(node.flow ? { flow: node.flow } : {}),
          ...(node.packetEncoding ? { packet_encoding: node.packetEncoding } : {}),
          ...(tls ? { tls } : {}),
          ...(transport ? { transport } : {}),
          ...dialer,
        },
      };
    }
    case "vmess": {
      const tls = buildTlsObject(node.tls);
      const transport = buildTransportObject(node.transport);
      return {
        kind: "outbound",
        entry: {
          type: "vmess",
          tag,
          server: node.host,
          server_port: node.port,
          uuid: node.uuid,
          alter_id: node.alterId,
          security: node.security || "auto",
          ...(tls ? { tls } : {}),
          ...(transport ? { transport } : {}),
          ...dialer,
        },
      };
    }
    case "trojan": {
      const tls = buildTlsObject(node.tls);
      const transport = buildTransportObject(node.transport);
      return {
        kind: "outbound",
        entry: {
          type: "trojan",
          tag,
          server: node.host,
          server_port: node.port,
          password: node.password,
          ...(tls ? { tls } : {}),
          ...(transport ? { transport } : {}),
          ...dialer,
        },
      };
    }
    case "ss": {
      return {
        kind: "outbound",
        entry: {
          type: "shadowsocks",
          tag,
          server: node.host,
          server_port: node.port,
          method: node.method,
          password: node.password,
          ...(node.plugin ? { plugin: node.plugin } : {}),
          ...(node.pluginOpts ? { plugin_opts: node.pluginOpts } : {}),
          ...dialer,
        },
      };
    }
    case "hysteria2": {
      const tls = buildTlsObject(node.tls);
      return {
        kind: "outbound",
        entry: {
          type: "hysteria2",
          tag,
          server: node.host,
          server_port: node.port,
          password: node.password,
          ...(node.upMbps ? { up_mbps: node.upMbps } : {}),
          ...(node.downMbps ? { down_mbps: node.downMbps } : {}),
          ...(node.obfs ? { obfs: node.obfs } : {}),
          ...(tls ? { tls } : {}),
          ...dialer,
        },
      };
    }
    case "tuic": {
      const tls = buildTlsObject(node.tls);
      return {
        kind: "outbound",
        entry: {
          type: "tuic",
          tag,
          server: node.host,
          server_port: node.port,
          uuid: node.uuid,
          password: node.password,
          ...(node.congestionControl ? { congestion_control: node.congestionControl } : {}),
          ...(node.udpRelayMode ? { udp_relay_mode: node.udpRelayMode } : {}),
          ...(node.zeroRttHandshake ? { zero_rtt_handshake: true } : {}),
          ...(tls ? { tls } : {}),
          ...dialer,
        },
      };
    }
    case "wireguard": {
      // sing-box 1.11+ represents WireGuard as a typed endpoint.
      return {
        kind: "endpoint",
        entry: {
          type: "wireguard",
          tag,
          address: node.localAddresses,
          private_key: node.privateKey,
          ...(node.mtu ? { mtu: node.mtu } : {}),
          peers: [
            {
              address: node.host,
              port: node.port,
              public_key: node.peerPublicKey,
              ...(node.preSharedKey ? { pre_shared_key: node.preSharedKey } : {}),
              ...(node.reserved ? { reserved: node.reserved } : {}),
              allowed_ips: ["0.0.0.0/0", "::/0"],
            },
          ],
          ...dialer,
        },
      };
    }
  }
}

function buildHop(
  proxy: ProxySpec,
  tag: string,
  detour?: string,
): { kind: "outbound" | "endpoint"; entry: Record<string, unknown> } {
  const dialer = detour ? { detour } : {};
  if (isSingBoxProxyType(proxy.type)) {
    if (!proxy.uri) throw new Error(`missing URI for ${proxy.type} proxy`);
    const parsed = parseSingBoxUri(proxy.uri);
    return buildParsedNodeOutbound(parsed, tag, detour);
  }
  const serverPort = Number(proxy.port);
  if (proxy.type === "socks5") {
    return {
      kind: "outbound",
      entry: {
        type: "socks",
        tag,
        server: proxy.host,
        server_port: serverPort,
        version: "5",
        ...(proxy.user ? { username: proxy.user, password: proxy.pass } : {}),
        ...dialer,
      },
    };
  }
  return {
    kind: "outbound",
    entry: {
      type: "http",
      tag,
      server: proxy.host,
      server_port: serverPort,
      ...(proxy.user ? { username: proxy.user, password: proxy.pass } : {}),
      ...(proxy.type === "https" ? { tls: { enabled: true, server_name: proxy.host } } : {}),
      ...dialer,
    },
  };
}

/**
 * Flatten a proxy chain from outermost transit hop to innermost landing hop.
 * Example: target (with preProxy = transit) -> [transit, target].
 */
export function flattenProxyChain(proxy: ProxySpec): ProxySpec[] {
  const hops: ProxySpec[] = [];
  let cursor: ProxySpec | undefined = proxy;
  while (cursor) {
    if (hops.length >= MAX_PROXY_CHAIN_DEPTH) {
      throw new Error(`proxy chain exceeds maximum depth of ${MAX_PROXY_CHAIN_DEPTH}`);
    }
    hops.unshift(cursor);
    cursor = cursor.preProxy;
  }
  return hops;
}

/** Build a complete sing-box JSON configuration binding to 127.0.0.1:<listenPort>. */
export function buildSingBoxConfig(
  proxy: ProxySpec,
  listenPort: number,
  options: BuildSingBoxConfigOptions = {},
): SingBoxConfig {
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    throw new Error(`invalid sing-box listen port: ${listenPort}`);
  }
  const predefined: Record<string, string[]> = {};
  if (options.predefinedHosts) {
    for (const [host, ips] of Object.entries(options.predefinedHosts)) {
      const cleanHost = host.trim().toLowerCase();
      const validIps = ips.filter(Boolean);
      if (cleanHost && validIps.length) predefined[cleanHost] = validIps;
    }
  }
  const hasPredefined = Object.keys(predefined).length > 0;

  const hops = flattenProxyChain(proxy);
  const outbounds: Array<Record<string, unknown>> = [];
  const endpoints: Array<Record<string, unknown>> = [];

  for (let i = 0; i < hops.length; i++) {
    const isFinal = i === hops.length - 1;
    const tag = isFinal ? "proxy" : `chain-${i}`;
    const detour = i > 0 ? `chain-${i - 1}` : undefined;
    const built = buildHop(hops[i]!, tag, detour);
    const serverHost = typeof built.entry.server === "string" ? built.entry.server.trim().toLowerCase() : "";
    if (built.kind === "outbound" && serverHost && predefined[serverHost]) {
      built.entry.domain_resolver = "hosts-pre";
    }
    if (built.kind === "endpoint") endpoints.push(built.entry);
    else outbounds.push(built.entry);
  }

  const { dns, resolverTag } = buildSingBoxDnsConfig();
  const effectiveDns: SingBoxConfig["dns"] = hasPredefined
    ? {
        servers: [
          { type: "hosts", tag: "hosts-pre", predefined },
          ...dns.servers,
        ],
        rules: [
          { domain: Object.keys(predefined), server: "hosts-pre" },
        ],
        ...(dns.final ? { final: dns.final } : {}),
      }
    : dns;
  const autoDetectInterface = process.env.ALIASMODE_SINGBOX_AUTO_DETECT_INTERFACE !== "0"
    && hops.length > 0
    && !isLoopbackServer(hops[0]!.host);

  return {
    log: { level: "error", timestamp: false },
    dns: effectiveDns,
    inbounds: [
      {
        type: "mixed",
        tag: "mixed-in",
        listen: "127.0.0.1",
        listen_port: listenPort,
      },
    ],
    ...(endpoints.length ? { endpoints } : {}),
    outbounds,
    route: {
      final: "proxy",
      ...(autoDetectInterface ? { auto_detect_interface: true } : {}),
      default_domain_resolver: {
        server: resolverTag,
        strategy: "prefer_ipv4",
      },
    },
  };
}
