/**
 * Keyless IP reputation, type (residential / mobile / datacenter / vpn / proxy / tor),
 * ISP/ASN, and composite risk score (0–100) lookup with in-memory caching.
 *
 * Uses `api.ipquery.io` and `proxycheck.io` in parallel, falling back to `ip-api.com`.
 * Designed to be strictly best-effort: a risk API outage never breaks proxy checking.
 */

import { canonicalIp } from "./ip.ts";

export type IpRiskLevel = "low" | "medium" | "high";
export type IpNetworkType = "residential" | "mobile" | "datacenter" | "vpn" | "proxy" | "tor" | "unknown";

export interface IpRiskInfo {
  ip: string;
  /** Composite risk score from 0 (cleanest) to 100 (highest risk). */
  riskScore: number;
  riskLevel: IpRiskLevel;
  ipType: IpNetworkType;
  isp: string;
  asn: string;
  country: string;
  city: string;
  /** Machine-readable risk flags such as "datacenter", "vpn", "proxy", "tor", "mobile", "residential". */
  flags: string[];
}

export interface IpRiskLookupOptions {
  fetchFn?: typeof fetch;
  timeoutMs?: number;
  now?: () => number;
  bypassCache?: boolean;
}

const CACHE_TTL_MS = 30 * 60_000;
const cache = new Map<string, { at: number; info: IpRiskInfo }>();
const inFlight = new Map<string, Promise<IpRiskInfo | null>>();

export function clearIpRiskCache(): void {
  cache.clear();
  inFlight.clear();
}

export function classifyRiskLevel(score: number): IpRiskLevel {
  if (score >= 70) return "high";
  if (score >= 35) return "medium";
  return "low";
}

interface RawSignals {
  isTor?: boolean;
  isProxy?: boolean;
  isVpn?: boolean;
  isDatacenter?: boolean;
  isMobile?: boolean;
  providerRiskScore?: number;
  isp?: string;
  asn?: string;
  country?: string;
  city?: string;
}

export function scoreIpRiskSignals(ip: string, signals: RawSignals): IpRiskInfo {
  let score = typeof signals.providerRiskScore === "number" && Number.isFinite(signals.providerRiskScore)
    ? Math.max(0, Math.min(100, Math.round(signals.providerRiskScore)))
    : 0;

  const flags: string[] = [];
  let ipType: IpNetworkType = "residential";

  if (signals.isTor) {
    flags.push("tor");
    ipType = "tor";
    score = Math.max(score, 95);
  }
  if (signals.isProxy) {
    flags.push("proxy");
    if (ipType === "residential") ipType = "proxy";
    score = Math.max(score, 75);
  }
  if (signals.isVpn) {
    flags.push("vpn");
    if (ipType === "residential") ipType = "vpn";
    score = Math.max(score, 70);
  }
  if (signals.isDatacenter) {
    flags.push("datacenter");
    if (ipType === "residential") ipType = "datacenter";
    // Hosting/datacenter IP alone is medium risk (50); combined with proxy/VPN pushes higher.
    score = Math.max(score, 50);
    if (signals.isProxy || signals.isVpn) score = Math.max(score, 80);
  }
  if (signals.isMobile) {
    flags.push("mobile");
    if (ipType === "residential") ipType = "mobile";
  }
  if (flags.length === 0) {
    flags.push("residential");
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  return {
    ip,
    riskScore: score,
    riskLevel: classifyRiskLevel(score),
    ipType,
    isp: (signals.isp ?? "").trim(),
    asn: (signals.asn ?? "").trim(),
    country: (signals.country ?? "").trim(),
    city: (signals.city ?? "").trim(),
    flags,
  };
}

async function fetchJsonSafe(url: string, fetchFn: typeof fetch, timeoutMs: number): Promise<any | null> {
  try {
    const res = await fetchFn(url, { signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function parseIpQuery(data: any): RawSignals | null {
  if (!data || typeof data !== "object" || !data.risk) return null;
  const r = data.risk ?? {};
  const isp = data.isp ?? {};
  const loc = data.location ?? {};
  return {
    isTor: r.is_tor === true,
    isProxy: r.is_proxy === true,
    isVpn: r.is_vpn === true,
    isDatacenter: r.is_datacenter === true,
    isMobile: r.is_mobile === true,
    providerRiskScore: typeof r.risk_score === "number" ? r.risk_score : undefined,
    isp: typeof isp.isp === "string" ? isp.isp : typeof isp.org === "string" ? isp.org : "",
    asn: typeof isp.asn === "string" ? isp.asn : "",
    country: typeof loc.country_code === "string" ? loc.country_code : typeof loc.country === "string" ? loc.country : "",
    city: typeof loc.city === "string" ? loc.city : "",
  };
}

function parseProxyCheck(ip: string, data: any): RawSignals | null {
  if (!data || typeof data !== "object" || data.status !== "ok") return null;
  const entry = data[ip] ?? Object.values(data).find((v) => v && typeof v === "object" && "proxy" in (v as object));
  if (!entry || typeof entry !== "object") return null;
  const typeStr = String(entry.type ?? "").toLowerCase();
  const flaggedProxy = String(entry.proxy ?? "").toLowerCase() === "yes";
  const isVpn = typeStr.includes("vpn");
  const isTor = typeStr.includes("tor");
  const isHosting = typeStr.includes("hosting") || typeStr.includes("datacenter") || typeStr.includes("cloud");
  const isProxy = flaggedProxy && !isVpn && !isTor && !isHosting;
  return {
    isTor,
    isVpn,
    isProxy,
    isDatacenter: isHosting,
    providerRiskScore: typeof entry.risk === "number" ? entry.risk : undefined,
    isp: typeof entry.provider === "string" ? entry.provider : typeof entry.organisation === "string" ? entry.organisation : "",
    asn: typeof entry.asn === "string" ? entry.asn : "",
    country: typeof entry.isocode === "string" ? entry.isocode : typeof entry.country === "string" ? entry.country : "",
    city: typeof entry.city === "string" ? entry.city : "",
  };
}

function parseIpApi(data: any): RawSignals | null {
  if (!data || typeof data !== "object" || data.status !== "success") return null;
  return {
    isDatacenter: data.hosting === true,
    isProxy: data.proxy === true,
    isMobile: data.mobile === true,
    isp: typeof data.isp === "string" ? data.isp : typeof data.org === "string" ? data.org : "",
    asn: typeof data.as === "string" ? data.as.split(/\s+/)[0] ?? "" : "",
    country: typeof data.countryCode === "string" ? data.countryCode : "",
    city: typeof data.city === "string" ? data.city : "",
  };
}

function mergeSignals(parts: Array<RawSignals | null>): RawSignals | null {
  const valid = parts.filter((p): p is RawSignals => p !== null);
  if (!valid.length) return null;
  const scores = valid.map((v) => v.providerRiskScore).filter((n): n is number => typeof n === "number" && Number.isFinite(n));
  return {
    isTor: valid.some((v) => v.isTor === true),
    isProxy: valid.some((v) => v.isProxy === true),
    isVpn: valid.some((v) => v.isVpn === true),
    isDatacenter: valid.some((v) => v.isDatacenter === true),
    isMobile: valid.some((v) => v.isMobile === true),
    providerRiskScore: scores.length ? Math.max(...scores) : undefined,
    isp: valid.find((v) => v.isp)?.isp ?? "",
    asn: valid.find((v) => v.asn)?.asn ?? "",
    country: valid.find((v) => v.country)?.country ?? "",
    city: valid.find((v) => v.city)?.city ?? "",
  };
}

/** Look up IP risk score, type, ISP, and location for an exit IP. Returns null if all sources fail. */
export async function lookupIpRisk(
  rawIp: string,
  options: IpRiskLookupOptions = {},
): Promise<IpRiskInfo | null> {
  const ip = canonicalIp(rawIp);
  if (!ip) return null;
  const now = options.now ?? Date.now;
  if (!options.bypassCache) {
    const cached = cache.get(ip);
    if (cached && now() - cached.at < CACHE_TTL_MS) return cached.info;
    const pending = inFlight.get(ip);
    if (pending) return pending;
  }

  const run = (async (): Promise<IpRiskInfo | null> => {
    const fetchFn = options.fetchFn ?? fetch;
    const timeoutMs = options.timeoutMs ?? 5_000;
    const encoded = encodeURIComponent(ip);

    const [ipQueryRaw, proxyCheckRaw] = await Promise.all([
      fetchJsonSafe(`https://api.ipquery.io/${encoded}`, fetchFn, timeoutMs),
      fetchJsonSafe(`https://proxycheck.io/v2/${encoded}?vpn=1&asn=1&risk=1`, fetchFn, timeoutMs),
    ]);

    let merged = mergeSignals([parseIpQuery(ipQueryRaw), parseProxyCheck(ip, proxyCheckRaw)]);
    if (!merged) {
      const ipApiRaw = await fetchJsonSafe(
        `http://ip-api.com/json/${encoded}?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile,query`,
        fetchFn,
        timeoutMs,
      );
      merged = mergeSignals([parseIpApi(ipApiRaw)]);
    }
    if (!merged) return null;

    const info = scoreIpRiskSignals(ip, merged);
    cache.set(ip, { at: now(), info });
    return info;
  })();

  if (options.bypassCache) return run;

  const tracked = run.finally(() => {
    if (inFlight.get(ip) === tracked) inFlight.delete(ip);
  });
  inFlight.set(ip, tracked);
  return tracked;
}
