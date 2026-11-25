/** Shared direct/browser diagnostic egress lookup and validation. */

import { canonicalIp } from "./ip.ts";

export const DEFAULT_EGRESS_ENDPOINTS = [
  // High-limit plain IP endpoints first (shared airport exit IPs frequently hit ipinfo.io HTTP 429).
  "https://api64.ipify.org?format=json",
  "https://api.ipify.org?format=json",
  "https://icanhazip.com",
  "https://api.ip.sb/ip",
  // Geo fallback last (country/city/ISP/risk are normally enriched by ip-risk.ts).
  "https://ipinfo.io/json",
] as const;

export const DEFAULT_LATENCY_ENDPOINTS = [
  "http://www.gstatic.com/generate_204",
  "http://cp.cloudflare.com/generate_204",
] as const;

export interface EgressInfo {
  ip: string;
  country?: string;
  region?: string;
  city?: string;
  org?: string;
}

export interface EgressLookupOptions {
  endpoints?: readonly string[];
  timeoutMs?: number;
}

/**
 * Resolve the lookup list. Operators whose proxy pools block the defaults may
 * set ALIASMODE_EGRESS_ENDPOINTS to a comma-separated list of HTTP(S) endpoints.
 */
export function resolveEgressEndpoints(
  configured: string | undefined = process.env.ALIASMODE_EGRESS_ENDPOINTS,
): string[] {
  const endpoints = configured === undefined
    ? [...DEFAULT_EGRESS_ENDPOINTS]
    : configured.split(",").map((value) => value.trim()).filter(Boolean);
  if (endpoints.length === 0) throw new Error("ALIASMODE_EGRESS_ENDPOINTS must contain at least one URL");
  for (const endpoint of endpoints) {
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error(`invalid egress endpoint URL: ${endpoint}`);
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new Error(`egress endpoint must use http or https: ${endpoint}`);
    }
  }
  return endpoints;
}

/** Parse the JSON/plaintext shapes returned by common egress services. */
export function parseEgressResponse(body: string): EgressInfo | null {
  const raw = body.trim();
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown> | null;
    if (parsed && typeof parsed === "object") {
      const candidate = [parsed.ip, parsed.query]
        .find((value) => typeof value === "string" && canonicalIp(value));
      if (typeof candidate === "string") {
        const info: EgressInfo = { ip: canonicalIp(candidate)! };
        for (const key of ["country", "region", "city", "org"] as const) {
          if (typeof parsed[key] === "string") info[key] = parsed[key];
        }
        return info;
      }
    }
  } catch {
    // Plain-text endpoint response.
  }
  const ip = canonicalIp(raw);
  return ip ? { ip } : null;
}

export type EgressLookupFailure =
  | "request_failed"
  | "service_failed"
  | "proxy_authentication_failed";

export interface EgressTimingResult {
  info: EgressInfo | null;
  /** RTT of the single successful egress endpoint only (never accumulates prior failed endpoints). */
  latencyMs?: number;
}

export interface LatencyProbeOptions {
  endpoints?: readonly string[];
  timeoutMs?: number;
  /** Perform one warmup request before measuring the second RTT on the same endpoint (default true). */
  warmup?: boolean;
}

export interface LatencyProbeResult {
  latencyMs: number | null;
  endpoint?: string;
  authenticationFailed?: boolean;
}

/**
 * Fetch egress info while timing each endpoint independently so a failed/429
 * endpoint's wait time is never accumulated into the fallback endpoint's RTT.
 */
export async function fetchDirectEgressTimed(
  opts: EgressLookupOptions = {},
  fetchFn: typeof fetch = fetch,
  onFailure?: (failure: EgressLookupFailure) => void,
): Promise<EgressTimingResult> {
  const endpoints = opts.endpoints ? [...opts.endpoints] : resolveEgressEndpoints();
  const timeoutMs = opts.timeoutMs ?? 15_000;
  for (const endpoint of endpoints) {
    const startedAt = Date.now();
    try {
      const response = await fetchFn(endpoint, { signal: AbortSignal.timeout(timeoutMs) });
      if (!response.ok) {
        onFailure?.(response.status === 407 ? "proxy_authentication_failed" : "service_failed");
        continue;
      }
      const body = await response.text();
      const latencyMs = Math.max(1, Date.now() - startedAt);
      const info = parseEgressResponse(body);
      if (info) return { info, latencyMs };
      onFailure?.("service_failed");
    } catch {
      onFailure?.("request_failed");
      // Try the next independent endpoint with a fresh timer.
    }
  }
  return { info: null };
}

/** Fetch this machine's direct egress using the same endpoints/parser. */
export async function fetchDirectEgress(
  opts: EgressLookupOptions = {},
  fetchFn: typeof fetch = fetch,
  onFailure?: (failure: EgressLookupFailure) => void,
): Promise<EgressInfo | null> {
  return (await fetchDirectEgressTimed(opts, fetchFn, onFailure)).info;
}

/**
 * Measure lightweight global Anycast HTTP 204 round-trip latency (matching
 * Clash Verge / v2rayN) over an already-running proxy fetch wrapper.
 * Each endpoint is timed independently so failed endpoints never inflate RTT.
 */
export async function measureHttp204Latency(
  fetchFn: typeof fetch,
  opts: LatencyProbeOptions = {},
): Promise<LatencyProbeResult> {
  const endpoints = opts.endpoints?.length ? [...opts.endpoints] : [...DEFAULT_LATENCY_ENDPOINTS];
  const primaryTimeoutMs = Math.min(opts.timeoutMs ?? 4_000, 4_000);
  const warmup = opts.warmup !== false;

  for (let i = 0; i < endpoints.length; i++) {
    const endpoint = endpoints[i]!;
    const timeoutMs = i === 0 ? primaryTimeoutMs : Math.min(primaryTimeoutMs, 3_000);
    const firstStart = Date.now();
    try {
      const first = await fetchFn(endpoint, {
        method: "GET",
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (first.status === 407) {
        await first.body?.cancel().catch(() => {});
        return { latencyMs: null, authenticationFailed: true };
      }
      await first.body?.cancel().catch(() => {});
      if (first.status !== 204 && first.status !== 200) {
        continue;
      }
      const firstMs = Math.max(1, Date.now() - firstStart);
      if (!warmup) {
        return { latencyMs: firstMs, endpoint };
      }
      const secondStart = Date.now();
      try {
        const second = await fetchFn(endpoint, {
          method: "GET",
          redirect: "manual",
          signal: AbortSignal.timeout(timeoutMs),
        });
        await second.body?.cancel().catch(() => {});
        if (second.status === 204 || second.status === 200) {
          const secondMs = Math.max(1, Date.now() - secondStart);
          return { latencyMs: Math.min(firstMs, secondMs), endpoint };
        }
      } catch {
        // Warmup request succeeded; keep its clean RTT if the second probe fails.
      }
      return { latencyMs: firstMs, endpoint };
    } catch {
      // Try the next independent 204 endpoint with a fresh timer.
    }
  }
  return { latencyMs: null };
}
