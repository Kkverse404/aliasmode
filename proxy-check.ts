/** Pre-save proxy connectivity checks through the same relay used by launched browsers. */

import {
  fetchDirectEgress,
  fetchDirectEgressTimed,
  measureHttp204Latency,
  type EgressInfo,
  type EgressLookupOptions,
} from "./egress.ts";
import { lookupIpRisk, type IpNetworkType, type IpRiskInfo, type IpRiskLevel } from "./ip-risk.ts";
import { resolveRuntimeProxy, shouldRouteNodesViaSingBox } from "./local-network.ts";
import { isSingBoxProxy, normalizeProxySpec, type ProxyInput } from "./proxy.ts";
import { startProxyRelay, startProxyRelayForSpec, type ProxyRelay, type RelayOptions, type UpstreamProxy } from "./proxy-relay.ts";
import type { ProxySpec } from "./types.ts";

const ATTEMPT_COUNT = 3;

export type ProxyCheckStatus = "working" | "unstable" | "failed" | "unavailable";
export type ProxyCheckReason =
  | "authentication_failed"
  | "timeout"
  | "dns_failed"
  | "unreachable"
  | "connection_failed"
  | "intermittent"
  | "proxy_bypassed"
  | "check_unavailable";

type ProxyConnectionFailureReason = Exclude<
  ProxyCheckReason,
  "intermittent" | "proxy_bypassed" | "check_unavailable"
>;

export interface ProxyCheckAttempt {
  info: EgressInfo | null;
  latencyMs?: number;
  reason?: ProxyConnectionFailureReason | "check_unavailable";
}

export interface ProxyCheckResult {
  status: ProxyCheckStatus;
  attempts: number;
  successes: number;
  reason?: ProxyCheckReason;
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  asn?: string;
  ipType?: IpNetworkType;
  riskScore?: number;
  riskLevel?: IpRiskLevel;
  riskFlags?: string[];
  latencyMs?: number;
  rotating?: boolean;
}

type RelayFactory = (upstream: UpstreamProxy, options?: RelayOptions) => Promise<ProxyRelay>;
type SpecRelayFactory = (proxy: ProxySpec, options?: RelayOptions) => Promise<ProxyRelay>;

export interface ProxyCheckOptions extends EgressLookupOptions {
  fetchFn?: typeof fetch;
  relayFactory?: RelayFactory;
  specRelayFactory?: SpecRelayFactory;
  /** Number of egress check attempts (default 3 for single-proxy check; set 1 for fast node pool checks). */
  attempts?: number;
  /** Reuse a single relay across latency probe and egress attempt(s). Defaults to true for sing-box, local-clash, or 1-attempt checks. */
  reuseRelay?: boolean;
  /** Decouple latency testing onto lightweight Anycast HTTP 204 endpoints (default true when using default egress endpoints). */
  measureLatency?: boolean;
  /** Custom HTTP 204 latency endpoints (defaults to cp.cloudflare.com and gstatic.com generate_204). */
  latencyEndpoints?: readonly string[];
  /** Optional IP risk lookup override (for tests); defaults to keyless lookupIpRisk when includeRisk is true. */
  riskLookup?: (ip: string) => Promise<IpRiskInfo | null>;
  /** Set true to enrich successful checks with IP risk score, IP type (residential/datacenter/vpn/proxy), and ISP. */
  includeRisk?: boolean;
  /** Bulk runs share the direct-IP lookup, including a failed lookup (null). */
  direct?: EgressInfo | null;
}

function safeFailureReason(logs: readonly string[]): ProxyConnectionFailureReason {
  const text = logs.join("\n");
  if (/\b407\b|auth(?:entication)?|credential/i.test(text)) return "authentication_failed";
  if (/timed?\s*out|timeout/i.test(text)) return "timeout";
  if (/ENOTFOUND|EAI_AGAIN|name.+resolv/i.test(text)) return "dns_failed";
  if (/ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|refused/i.test(text)) return "unreachable";
  return "connection_failed";
}

function egressFields(info: EgressInfo): Pick<ProxyCheckResult, "ip" | "country" | "region" | "city"> {
  return {
    ip: info.ip,
    ...(info.country ? { country: info.country } : {}),
    ...(info.region ? { region: info.region } : {}),
    ...(info.city ? { city: info.city } : {}),
  };
}

function preferredFailureReason(attempts: readonly ProxyCheckAttempt[]): ProxyConnectionFailureReason {
  const reasons = attempts.map((attempt) => attempt.reason).filter(Boolean);
  for (const candidate of ["authentication_failed", "timeout", "dns_failed", "unreachable"] as const) {
    if (reasons.includes(candidate)) return candidate;
  }
  return "connection_failed";
}

export function classifyProxyAttempts(
  attempts: readonly ProxyCheckAttempt[],
  direct: EgressInfo | null,
): ProxyCheckResult {
  const successful = attempts.flatMap((attempt) => attempt.info ? [attempt.info] : []);
  const latencies = attempts
    .filter((attempt) => !!attempt.info && typeof attempt.latencyMs === "number" && Number.isFinite(attempt.latencyMs))
    .map((attempt) => attempt.latencyMs!);
  const minLatencyMs = latencies.length ? Math.min(...latencies) : undefined;
  const failed = attempts.filter((attempt) => !attempt.info);
  const base = { attempts: attempts.length, successes: successful.length };

  if (direct && successful.some((info) => info.ip === direct.ip)) {
    return { ...base, status: "failed", reason: "proxy_bypassed" };
  }
  if (successful.length > 0 && failed.every((attempt) => attempt.reason === "check_unavailable")) {
    return {
      ...base,
      status: "working",
      ...egressFields(successful[0]!),
      ...(minLatencyMs !== undefined ? { latencyMs: minLatencyMs } : {}),
      rotating: new Set(successful.map((info) => info.ip)).size > 1,
    };
  }
  if (successful.length > 0) {
    return {
      ...base,
      status: "unstable",
      reason: "intermittent",
      ...egressFields(successful[0]!),
      ...(minLatencyMs !== undefined ? { latencyMs: minLatencyMs } : {}),
      rotating: new Set(successful.map((info) => info.ip)).size > 1,
    };
  }
  const objectiveFailure = failed.some((attempt) =>
    attempt.reason === "authentication_failed" ||
    attempt.reason === "dns_failed" ||
    attempt.reason === "unreachable"
  );
  if (objectiveFailure) {
    return { ...base, status: "failed", reason: preferredFailureReason(attempts) };
  }
  if (failed.some((attempt) => attempt.reason === "check_unavailable")) {
    return { ...base, status: "unavailable", reason: "check_unavailable" };
  }
  if (direct) {
    return { ...base, status: "failed", reason: preferredFailureReason(attempts) };
  }
  return { ...base, status: "unavailable", reason: "check_unavailable" };
}

async function openCheckRelay(
  proxy: ProxySpec,
  options: Required<Pick<ProxyCheckOptions, "relayFactory">> & Pick<ProxyCheckOptions, "specRelayFactory"> & { useSpecRelay: boolean },
  logs: string[],
): Promise<ProxyRelay> {
  return options.useSpecRelay
    ? (options.specRelayFactory ?? startProxyRelayForSpec)(proxy, { log: (message) => logs.push(message) })
    : options.relayFactory({
        type: proxy.type === "socks5" ? "socks5" : "http",
        host: proxy.host,
        port: Number(proxy.port),
        user: proxy.user,
        pass: proxy.pass,
      }, { log: (message) => logs.push(message) });
}

function makeProxiedFetch(fetchFn: typeof fetch, port: number): typeof fetch {
  const proxyUrl = `http://127.0.0.1:${port}`;
  return ((input: RequestInfo | URL, init?: RequestInit) =>
    fetchFn(input, { ...init, proxy: proxyUrl })) as typeof fetch;
}

async function runEgressAttempt(
  proxiedFetch: typeof fetch,
  lookupOptions: EgressLookupOptions,
  logs: readonly string[],
): Promise<ProxyCheckAttempt> {
  let serviceFailed = false;
  let authenticationFailed = false;
  const { info, latencyMs } = await fetchDirectEgressTimed({
    endpoints: lookupOptions.endpoints,
    timeoutMs: lookupOptions.timeoutMs,
  }, proxiedFetch, (failure) => {
    if (failure === "service_failed") serviceFailed = true;
    if (failure === "proxy_authentication_failed") authenticationFailed = true;
  });
  return info
    ? { info, latencyMs }
    : {
        info: null,
        reason: authenticationFailed
          ? "authentication_failed"
          : serviceFailed ? "check_unavailable" : safeFailureReason(logs),
      };
}

function hasFatalRelayLog(logs: readonly string[]): boolean {
  const reason = safeFailureReason(logs);
  return reason === "authentication_failed" || reason === "dns_failed" || reason === "unreachable";
}

async function proxyAttempt(
  proxy: ProxySpec,
  options: Required<Pick<ProxyCheckOptions, "fetchFn" | "relayFactory">>
    & Pick<ProxyCheckOptions, "specRelayFactory" | "latencyEndpoints">
    & { useSpecRelay: boolean; measure204?: boolean }
    & EgressLookupOptions,
): Promise<{ attempt: ProxyCheckAttempt; latency204Ms: number | null }> {
  const logs: string[] = [];
  let relay: ProxyRelay | undefined;
  let latency204Ms: number | null = null;
  try {
    relay = await openCheckRelay(proxy, options, logs);
    const proxiedFetch = makeProxiedFetch(options.fetchFn, relay.port);
    if (options.measure204) {
      const probe = await measureHttp204Latency(proxiedFetch, {
        endpoints: options.latencyEndpoints,
        timeoutMs: options.timeoutMs,
      });
      if (probe.authenticationFailed) {
        return { attempt: { info: null, reason: "authentication_failed" }, latency204Ms: null };
      }
      latency204Ms = probe.latencyMs;
      if (latency204Ms === null && hasFatalRelayLog(logs)) {
        return { attempt: { info: null, reason: safeFailureReason(logs) }, latency204Ms: null };
      }
    }
    const attempt = await runEgressAttempt(proxiedFetch, options, logs);
    return { attempt, latency204Ms };
  } catch {
    return { attempt: { info: null, reason: safeFailureReason(logs) }, latency204Ms: null };
  } finally {
    relay?.close();
  }
}

async function runAttemptsOnSharedRelay(
  proxy: ProxySpec,
  attemptCount: number,
  options: Required<Pick<ProxyCheckOptions, "fetchFn" | "relayFactory">>
    & Pick<ProxyCheckOptions, "specRelayFactory" | "latencyEndpoints">
    & { useSpecRelay: boolean; measure204: boolean }
    & EgressLookupOptions,
): Promise<{ attempts: ProxyCheckAttempt[]; latency204Ms: number | null }> {
  const logs: string[] = [];
  let relay: ProxyRelay | undefined;
  let latency204Ms: number | null = null;
  try {
    relay = await openCheckRelay(proxy, options, logs);
    const proxiedFetch = makeProxiedFetch(options.fetchFn, relay.port);
    if (options.measure204) {
      const probe = await measureHttp204Latency(proxiedFetch, {
        endpoints: options.latencyEndpoints,
        timeoutMs: options.timeoutMs,
      });
      if (probe.authenticationFailed) {
        return {
          attempts: Array.from({ length: attemptCount }, () => ({ info: null, reason: "authentication_failed" as const })),
          latency204Ms: null,
        };
      }
      latency204Ms = probe.latencyMs;
      if (latency204Ms === null && hasFatalRelayLog(logs)) {
        const reason = safeFailureReason(logs);
        return {
          attempts: Array.from({ length: attemptCount }, () => ({ info: null, reason })),
          latency204Ms: null,
        };
      }
    }
    const attempts = await Promise.all(
      Array.from({ length: attemptCount }, () => runEgressAttempt(proxiedFetch, options, logs)),
    );
    return { attempts, latency204Ms };
  } catch {
    const reason = safeFailureReason(logs);
    return {
      attempts: Array.from({ length: attemptCount }, () => ({ info: null, reason })),
      latency204Ms: null,
    };
  } finally {
    relay?.close();
  }
}

/** Check unsaved proxy settings without storing them or launching a browser. */
export async function checkProxy(
  input: ProxyInput | ProxySpec | null | undefined,
  options: ProxyCheckOptions = {},
): Promise<ProxyCheckResult> {
  const normalized = normalizeProxySpec(input);
  if (!normalized) throw new Error("proxy is required");
  const proxy = resolveRuntimeProxy(normalized) ?? normalized;
  if (!isSingBoxProxy(proxy) && proxy.type !== "http" && proxy.type !== "socks5") {
    throw new Error("unsupported proxy type (use http or socks5)");
  }

  const fetchFn = options.fetchFn ?? fetch;
  const relayFactory = options.relayFactory ?? startProxyRelay;
  const useSpecRelay = isSingBoxProxy(proxy)
    || (!options.relayFactory && proxy.mode !== "local-clash" && shouldRouteNodesViaSingBox(proxy));
  const attemptCount = Number.isInteger(options.attempts) && options.attempts! >= 1 ? options.attempts! : ATTEMPT_COUNT;
  const reuseRelay = options.reuseRelay ?? (useSpecRelay || attemptCount === 1 || proxy.mode === "local-clash");
  const measure204 = options.measureLatency ?? (options.endpoints === undefined || options.latencyEndpoints !== undefined);
  const lookupOptions = { endpoints: options.endpoints, timeoutMs: options.timeoutMs };
  const skipDirectCompare = proxy.mode === "local-clash" || normalized.mode === "local-clash";

  const [direct, probeRun] = await Promise.all([
    skipDirectCompare
      ? Promise.resolve(null)
      : (options.direct === undefined ? fetchDirectEgress(lookupOptions, fetchFn) : options.direct),
    reuseRelay
      ? runAttemptsOnSharedRelay(proxy, attemptCount, {
          ...lookupOptions,
          fetchFn,
          relayFactory,
          specRelayFactory: options.specRelayFactory,
          latencyEndpoints: options.latencyEndpoints,
          useSpecRelay,
          measure204,
        })
      : Promise.all(Array.from(
          { length: attemptCount },
          (_, index) => proxyAttempt(proxy, {
            ...lookupOptions,
            fetchFn,
            relayFactory,
            specRelayFactory: options.specRelayFactory,
            latencyEndpoints: options.latencyEndpoints,
            useSpecRelay,
            measure204: measure204 && index === 0,
          }),
        )).then((runs) => ({
          attempts: runs.map((r) => r.attempt),
          latency204Ms: runs.find((r) => r.latency204Ms !== null)?.latency204Ms ?? null,
        })),
  ]);
  const classified = classifyProxyAttempts(probeRun.attempts, direct);
  const result: ProxyCheckResult = (classified.status === "working" || classified.status === "unstable")
    && probeRun.latency204Ms !== null
    ? { ...classified, latencyMs: probeRun.latency204Ms }
    : classified;
  if (options.includeRisk && result.ip && (result.status === "working" || result.status === "unstable")) {
    const riskFn = options.riskLookup ?? ((ip: string) => lookupIpRisk(ip, { fetchFn }));
    const risk = await riskFn(result.ip).catch(() => null);
    if (risk) {
      return {
        ...result,
        ...(risk.country && !result.country ? { country: risk.country } : {}),
        ...(risk.city && !result.city ? { city: risk.city } : {}),
        ...(risk.isp ? { isp: risk.isp } : {}),
        ...(risk.asn ? { asn: risk.asn } : {}),
        ipType: risk.ipType,
        riskScore: risk.riskScore,
        riskLevel: risk.riskLevel,
        riskFlags: risk.flags,
      };
    }
  }
  return result;
}
