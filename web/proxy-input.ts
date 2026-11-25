export type ParsedProxyType =
  | "http"
  | "socks5"
  | "vless"
  | "vmess"
  | "trojan"
  | "ss"
  | "hysteria2"
  | "tuic"
  | "wireguard";

export interface ParsedProxyInput {
  type: ParsedProxyType;
  host: string;
  port: string;
  user: string;
  pass: string;
  /** Present for sing-box protocol share URIs (vless://, vmess://, trojan://, ss://, hy2://, tuic://, wg://). */
  uri?: string;
  /** Optional remark / label parsed from the URI fragment or VMess ps field. */
  label?: string;
}

const SINGBOX_SCHEME_MAP: Record<string, ParsedProxyType> = {
  vless: "vless",
  vmess: "vmess",
  trojan: "trojan",
  ss: "ss",
  shadowsocks: "ss",
  hysteria2: "hysteria2",
  hy2: "hysteria2",
  tuic: "tuic",
  wireguard: "wireguard",
  wg: "wireguard",
};

export function isSingBoxType(value: string): boolean {
  const norm = value.trim().toLowerCase();
  return Object.hasOwn(SINGBOX_SCHEME_MAP, norm);
}

function proxyType(value: string, fallback: "http" | "socks5"): "http" | "socks5" {
  const normalized = value.trim().toLowerCase().replace(/:$/, "");
  if (!normalized) return fallback;
  if (normalized === "socks" || normalized === "socks5") return "socks5";
  if (normalized === "http") return "http";
  throw new Error(`unsupported proxy type “${normalized}” (use http, socks5, or sing-box URI)`);
}

function decoded(value: string, label: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    throw new Error(`proxy ${label} has invalid percent-encoding`);
  }
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function decodeBase64Browser(raw: string): string {
  const cleaned = raw.trim().replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  const padded = cleaned.length % 4 === 0 ? cleaned : cleaned + "=".repeat(4 - (cleaned.length % 4));
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function isIpv6(value: string): boolean {
  try {
    return new URL(`http://[${value}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

function validate(result: ParsedProxyInput): ParsedProxyInput {
  if (!result.host.trim()) throw new Error("proxy host is empty");
  const port = Number(result.port);
  if (!/^\d+$/.test(result.port) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid proxy port: ${result.port || "(empty)"}`);
  }
  if (!result.user && result.pass) throw new Error("proxy password requires a username");
  return { ...result, host: result.host.trim(), port: String(port) };
}

function parseSingBoxClientUri(raw: string, scheme: string): ParsedProxyInput {
  const mapped = SINGBOX_SCHEME_MAP[scheme.toLowerCase()]!;
  if (mapped === "vmess" && !raw.slice("vmess://".length).includes("@")) {
    const payload = raw.slice("vmess://".length);
    const hashIdx = payload.indexOf("#");
    const b64 = hashIdx >= 0 ? payload.slice(0, hashIdx) : payload;
    const hashLabel = hashIdx >= 0 ? safeDecode(payload.slice(hashIdx + 1)).trim() : "";
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(decodeBase64Browser(b64)) as Record<string, unknown>;
    } catch {
      throw new Error("invalid VMess base64 URI");
    }
    const host = String(json.add ?? "").trim().replace(/^\[|\]$/g, "");
    const port = String(json.port ?? "").trim();
    const label = String(json.ps ?? "").trim() || hashLabel;
    return validate({
      type: "vmess",
      host,
      port,
      user: "",
      pass: "",
      uri: raw,
      ...(label ? { label } : {}),
    });
  }

  if (mapped === "ss") {
    const after = raw.replace(/^(?:ss|shadowsocks):\/\//i, "");
    const hashIdx = after.indexOf("#");
    const label = hashIdx >= 0 ? safeDecode(after.slice(hashIdx + 1)).trim() : "";
    const withoutHash = hashIdx >= 0 ? after.slice(0, hashIdx) : after;
    const authority = withoutHash.split("?")[0]!;
    let hostPort = "";
    if (authority.includes("@")) {
      hostPort = authority.slice(authority.lastIndexOf("@") + 1);
    } else {
      const dec = decodeBase64Browser(authority);
      const atIdx = dec.lastIndexOf("@");
      if (atIdx < 0) throw new Error("invalid Shadowsocks URI");
      hostPort = dec.slice(atIdx + 1);
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(`http://${hostPort}`);
    } catch {
      throw new Error("invalid Shadowsocks host:port");
    }
    return validate({
      type: "ss",
      host: parsedUrl.hostname.replace(/^\[|\]$/g, ""),
      port: parsedUrl.port,
      user: "",
      pass: "",
      uri: raw,
      ...(label ? { label } : {}),
    });
  }

  let url: URL;
  try {
    url = new URL(raw.replace(/^hy2:\/\//i, "hysteria2://").replace(/^wg:\/\//i, "wireguard://"));
  } catch {
    throw new Error("invalid proxy URL");
  }
  const defaultPort = mapped === "wireguard" ? "51820" : mapped === "hysteria2" || mapped === "tuic" ? "443" : "";
  const label = safeDecode(url.hash.replace(/^#/, "")).trim();
  return validate({
    type: mapped,
    host: url.hostname.replace(/^\[|\]$/g, ""),
    port: url.port || defaultPort,
    user: "",
    pass: "",
    uri: raw,
    ...(label ? { label } : {}),
  });
}

/** Browser-side convenience parser; the API performs authoritative validation again. */
export function parsePastedProxy(
  value: string,
  fallbackType: "http" | "socks5" = "http",
): ParsedProxyInput {
  const raw = value.trim();
  if (!raw) throw new Error("paste a proxy first");
  const schemeMatch = raw.match(/^([a-z][a-z0-9+.-]*):\/\//i);
  if (schemeMatch) {
    const scheme = schemeMatch[1]!.toLowerCase();
    if (Object.hasOwn(SINGBOX_SCHEME_MAP, scheme)) {
      return parseSingBoxClientUri(raw, scheme);
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
    return validate({
      type: proxyType(url.protocol, fallbackType),
      host: url.hostname.replace(/^\[|\]$/g, ""),
      port: url.port,
      user: decoded(url.username, "username"),
      pass: decoded(url.password, "password"),
    });
  }

  const ipv6 = raw.match(/^\[([^\]]+)]:(\d+)(?::([^:]*)(?::(.*))?)?$/);
  if (ipv6) {
    return validate({
      type: fallbackType,
      host: ipv6[1]!,
      port: ipv6[2]!,
      user: ipv6[3] ?? "",
      pass: ipv6[4] ?? "",
    });
  }

  const parts = raw.split(":");
  if (parts.length < 2) throw new Error("proxy must be host:port:username:password or a proxy URL");
  // Unbracketed IPv6 host: the port sits before user:pass or at the end.
  let portIndex = 1;
  for (const index of [parts.length - 3, parts.length - 1]) {
    if (index >= 2 && /^\d+$/.test(parts[index]!) && isIpv6(parts.slice(0, index).join(":"))) {
      portIndex = index;
      break;
    }
  }
  return validate({
    type: fallbackType,
    host: parts.slice(0, portIndex).join(":"),
    port: parts[portIndex]!,
    user: parts[portIndex + 1] ?? "",
    // Passwords can contain colons; everything after the username belongs to it.
    pass: parts.slice(portIndex + 2).join(":"),
  });
}
