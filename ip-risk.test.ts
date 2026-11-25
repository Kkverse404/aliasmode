import { afterEach, describe, expect, test } from "bun:test";
import { clearIpRiskCache, lookupIpRisk, scoreIpRiskSignals } from "./ip-risk.ts";
import { checkProxy } from "./proxy-check.ts";
import { formatPoolPickerOption, sortCheckRows, sortNodesForPicker, sortPoolNodes } from "./web/proxies.tsx";
import type { ProxyPoolNodeView } from "./web/api.ts";
import type { ProxyCheckView } from "./proxy-tools-types.ts";

afterEach(() => {
  clearIpRiskCache();
});

describe("IP risk scoring & lookup", () => {
  test("classifies residential, mobile, datacenter, vpn, proxy, and tor signals accurately", () => {
    const res = scoreIpRiskSignals("1.2.3.4", { providerRiskScore: 5, isp: "Comcast", country: "US", city: "Chicago" });
    expect(res).toMatchObject({
      ip: "1.2.3.4",
      riskScore: 5,
      riskLevel: "low",
      ipType: "residential",
      isp: "Comcast",
      country: "US",
      city: "Chicago",
      flags: ["residential"],
    });

    const mobile = scoreIpRiskSignals("1.2.3.5", { isMobile: true, providerRiskScore: 10 });
    expect(mobile).toMatchObject({ riskScore: 10, riskLevel: "low", ipType: "mobile", flags: ["mobile"] });

    // Hosting/datacenter IP with 0 provider score must still be surfaced as medium risk (50)
    const dc = scoreIpRiskSignals("192.255.220.134", { isDatacenter: true, providerRiskScore: 0, isp: "HostPapa" });
    expect(dc).toMatchObject({ riskScore: 50, riskLevel: "medium", ipType: "datacenter", flags: ["datacenter"] });

    const vpn = scoreIpRiskSignals("5.6.7.8", { isVpn: true, providerRiskScore: 40 });
    expect(vpn).toMatchObject({ riskScore: 70, riskLevel: "high", ipType: "vpn" });

    const dcProxy = scoreIpRiskSignals("5.6.7.9", { isDatacenter: true, isProxy: true, providerRiskScore: 60 });
    expect(dcProxy).toMatchObject({ riskScore: 80, riskLevel: "high", ipType: "proxy", flags: ["proxy", "datacenter"] });

    const tor = scoreIpRiskSignals("5.6.7.10", { isTor: true, providerRiskScore: 20 });
    expect(tor).toMatchObject({ riskScore: 95, riskLevel: "high", ipType: "tor" });
  });

  test("merges ipquery + proxycheck in parallel, caches per IP, and falls back to ip-api.com", async () => {
    const calls: string[] = [];
    const mockFetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      calls.push(url);
      if (url.includes("api.ipquery.io")) {
        return Response.json({
          ip: "198.51.100.10",
          isp: { asn: "AS15169", isp: "Google Cloud" },
          location: { country_code: "US", city: "Los Angeles" },
          risk: { is_datacenter: true, is_vpn: false, is_proxy: false, is_tor: false, is_mobile: false, risk_score: 0 },
        });
      }
      if (url.includes("proxycheck.io")) {
        return Response.json({
          status: "ok",
          "198.51.100.10": { asn: "AS15169", provider: "Google LLC", proxy: "yes", type: "VPN", risk: 66 },
        });
      }
      return new Response("not found", { status: 404 });
    }) as unknown as typeof fetch;

    const first = await lookupIpRisk("198.51.100.10", { fetchFn: mockFetch });
    expect(first).toMatchObject({
      ip: "198.51.100.10",
      riskScore: 80, // datacenter + vpn floor
      riskLevel: "high",
      ipType: "vpn",
      isp: "Google Cloud",
      asn: "AS15169",
      country: "US",
      city: "Los Angeles",
    });
    expect(calls).toHaveLength(2);

    // Cached call should not hit network (still valid after 25 min under 30-min TTL)
    let fakeNow = 1_000_000;
    clearIpRiskCache();
    let concurrentFetches = 0;
    const dedupFetch = (async (input: RequestInfo | URL) => {
      concurrentFetches++;
      await Bun.sleep(25);
      const url = String(input);
      if (url.includes("api.ipquery.io")) {
        return Response.json({
          ip: "198.51.100.11",
          isp: { asn: "AS15169", isp: "Google Cloud" },
          location: { country_code: "US", city: "Los Angeles" },
          risk: { is_datacenter: false, is_vpn: false, is_proxy: false, is_tor: false, is_mobile: false, risk_score: 0 },
        });
      }
      return Response.json({ status: "ok", "198.51.100.11": { proxy: "no", risk: 0 } });
    }) as unknown as typeof fetch;

    const batch = await Promise.all(
      Array.from({ length: 5 }, () => lookupIpRisk("198.51.100.11", { fetchFn: dedupFetch, now: () => fakeNow })),
    );
    expect(batch.every((r) => r?.ip === "198.51.100.11" && r.riskScore === 0)).toBe(true);
    // 5 concurrent lookups for the same IP must coalesce into a single external fetch pair (2 requests total)
    expect(concurrentFetches).toBe(2);

    // 25 minutes later still hits 30-min cache without re-fetching
    fakeNow += 25 * 60_000;
    const cachedLater = await lookupIpRisk("198.51.100.11", { fetchFn: dedupFetch, now: () => fakeNow });
    expect(cachedLater?.ip).toBe("198.51.100.11");
    expect(concurrentFetches).toBe(2);

    // 31 minutes later expires and refreshes
    fakeNow += 6 * 60_000;
    await lookupIpRisk("198.51.100.11", { fetchFn: dedupFetch, now: () => fakeNow });
    expect(concurrentFetches).toBe(4);

    // Fallback to ip-api.com when primary providers fail
    const fallbackFetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("ip-api.com")) {
        return Response.json({
          status: "success",
          countryCode: "JP",
          city: "Tokyo",
          isp: "NTT Communications",
          as: "AS2914 NTT America",
          hosting: false,
          proxy: false,
          mobile: false,
        });
      }
      return new Response("unavailable", { status: 503 });
    }) as unknown as typeof fetch;

    const fallback = await lookupIpRisk("203.0.113.55", { fetchFn: fallbackFetch });
    expect(fallback).toMatchObject({
      ip: "203.0.113.55",
      riskScore: 0,
      riskLevel: "low",
      ipType: "residential",
      isp: "NTT Communications",
      asn: "AS2914",
      country: "JP",
      city: "Tokyo",
    });
  });

  test("checkProxy returns measured RTT latencyMs and enriches risk info when includeRisk is true", async () => {
    let riskLookups = 0;
    const mockRelayFactory = async () => ({
      port: 18080,
      close: () => {},
    });
    const mockFetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxied = !!(init as any)?.proxy;
      return Response.json(proxied
        ? { ip: "198.51.100.77", country: "US", city: "Seattle" }
        : { ip: "203.0.113.1", country: "CN" });
    }) as unknown as typeof fetch;

    // Default (includeRisk omitted): does not invoke riskLookup
    const plain = await checkProxy(
      { type: "socks5", host: "proxy.example", port: "1080" },
      {
        fetchFn: mockFetch,
        relayFactory: mockRelayFactory,
        riskLookup: async () => {
          riskLookups++;
          return null;
        },
      },
    );
    expect(plain.status).toBe("working");
    expect(typeof plain.latencyMs).toBe("number");
    expect(plain.latencyMs!).toBeGreaterThanOrEqual(1);
    expect(plain.riskScore).toBeUndefined();
    expect(riskLookups).toBe(0);

    // includeRisk: true enriches risk metadata
    const enriched = await checkProxy(
      { type: "socks5", host: "proxy.example", port: "1080" },
      {
        fetchFn: mockFetch,
        relayFactory: mockRelayFactory,
        includeRisk: true,
        riskLookup: async (ip) => {
          riskLookups++;
          return scoreIpRiskSignals(ip, { isDatacenter: true, isp: "DigitalOcean", asn: "AS14061", city: "Seattle", country: "US" });
        },
      },
    );
    expect(riskLookups).toBe(1);
    expect(enriched).toMatchObject({
      status: "working",
      ip: "198.51.100.77",
      country: "US",
      city: "Seattle",
      isp: "DigitalOcean",
      asn: "AS14061",
      ipType: "datacenter",
      riskScore: 50,
      riskLevel: "medium",
      riskFlags: ["datacenter"],
    });
    expect(enriched.latencyMs).toBeGreaterThanOrEqual(1);

    // Local Clash mode must not falsely fail with proxy_bypassed when host TUN/system proxy shares the same exit IP
    const localClashRes = await checkProxy(
      { type: "http", host: "127.0.0.1", port: "7897", mode: "local-clash" },
      {
        fetchFn: (async () => Response.json({ ip: "198.51.100.77", country: "US", city: "Seattle" })) as unknown as typeof fetch,
        relayFactory: mockRelayFactory,
        includeRisk: true,
        riskLookup: async (ip) => scoreIpRiskSignals(ip, { isDatacenter: true, isp: "Example Cloud" }),
      },
    );
    expect(localClashRes).toMatchObject({
      status: "working",
      ip: "198.51.100.77",
      riskScore: 50,
      riskLevel: "medium",
      ipType: "datacenter",
    });
  });
});

function makeNode(partial: Partial<ProxyPoolNodeView> & { id: string; name: string }): ProxyPoolNodeView {
  return {
    id: partial.id,
    name: partial.name,
    subscriptionId: "",
    type: partial.type ?? "vless",
    host: "1.1.1.1",
    port: "443",
    summary: "vless://1.1.1.1:443",
    hasChain: false,
    value: "",
    proxy: { type: partial.type ?? "vless", host: "1.1.1.1", port: "443" },
    tags: [],
    lastStatus: partial.lastStatus ?? "",
    lastReason: partial.lastReason ?? "",
    lastIp: partial.lastIp ?? "",
    lastCountry: partial.lastCountry ?? "",
    lastCity: partial.lastCity ?? "",
    lastIsp: partial.lastIsp ?? "",
    lastIpType: partial.lastIpType ?? "",
    lastRiskScore: partial.lastRiskScore ?? null,
    lastRiskLevel: partial.lastRiskLevel ?? "",
    lastRiskFlags: partial.lastRiskFlags ?? [],
    lastLatencyMs: partial.lastLatencyMs ?? null,
    lastCheckedAt: 0,
    createdAt: 0,
  };
}

describe("Node pool & proxy check sorting", () => {
  test("sorts pool nodes by latency and risk with unchecked/null always at the bottom", () => {
    const nodes: ProxyPoolNodeView[] = [
      makeNode({ id: "untested", name: "Untested" }),
      makeNode({ id: "fast-high", name: "Fast High", lastStatus: "working", lastLatencyMs: 80, lastRiskScore: 85, lastRiskLevel: "high", lastCountry: "HK" }),
      makeNode({ id: "slow-clean", name: "Slow Clean", lastStatus: "working", lastLatencyMs: 260, lastRiskScore: 0, lastRiskLevel: "low", lastCountry: "US" }),
      makeNode({ id: "mid-clean", name: "Mid Clean", lastStatus: "working", lastLatencyMs: 140, lastRiskScore: 0, lastRiskLevel: "low", lastCountry: "JP" }),
      makeNode({ id: "dead", name: "Dead", lastStatus: "failed", lastLatencyMs: null, lastRiskScore: null }),
    ];

    expect(sortPoolNodes(nodes, "latency", "asc").map((n) => n.id)).toEqual([
      "fast-high", "mid-clean", "slow-clean", "dead", "untested",
    ]);
    expect(sortPoolNodes(nodes, "latency", "desc").map((n) => n.id)).toEqual([
      "slow-clean", "mid-clean", "fast-high", "dead", "untested",
    ]);
    // Risk asc tie-breaks by lower latency first!
    expect(sortPoolNodes(nodes, "risk", "asc").map((n) => n.id)).toEqual([
      "mid-clean", "slow-clean", "fast-high", "dead", "untested",
    ]);
    expect(sortPoolNodes(nodes, "risk", "desc").map((n) => n.id)).toEqual([
      "fast-high", "mid-clean", "slow-clean", "dead", "untested",
    ]);
    // Status asc puts working first, failed next, unchecked at bottom
    expect(sortPoolNodes(nodes, "status", "asc").map((n) => n.id)).toEqual([
      "fast-high", "mid-clean", "slow-clean", "dead", "untested",
    ]);
  });

  test("sorts bulk check rows by risk and latency with missing values last", () => {
    const rows: ProxyCheckView[] = [
      { key: "a", proxy: "http://a:80", profiles: [], status: "failed", checkedAt: 1 },
      { key: "b", proxy: "http://b:80", profiles: [], status: "working", ip: "1.1.1.1", country: "US", latencyMs: 220, riskScore: 10, riskLevel: "low", checkedAt: 1 },
      { key: "c", proxy: "http://c:80", profiles: [], status: "working", ip: "2.2.2.2", country: "SG", latencyMs: 90, riskScore: 60, riskLevel: "medium", checkedAt: 1 },
    ];
    expect(sortCheckRows(rows, "latency", "asc").map((r) => r.key)).toEqual(["c", "b", "a"]);
    expect(sortCheckRows(rows, "risk", "asc").map((r) => r.key)).toEqual(["b", "c", "a"]);
  });

  test("ranks picker nodes by working + low risk + low latency and formats option labels cleanly", () => {
    const nodes: ProxyPoolNodeView[] = [
      makeNode({ id: "dead", name: "Dead-01", lastStatus: "failed" }),
      makeNode({ id: "unchecked", name: "New-01", lastStatus: "" }),
      makeNode({ id: "high-fast", name: "SG-01", lastStatus: "working", lastCountry: "SG", lastLatencyMs: 50, lastRiskScore: 80, lastRiskLevel: "high" }),
      makeNode({ id: "clean-slow", name: "US-01", lastStatus: "working", lastCountry: "US", lastLatencyMs: 200, lastRiskScore: 0, lastRiskLevel: "low" }),
      makeNode({ id: "clean-fast", name: "HK-01", lastStatus: "working", lastCountry: "HK", lastLatencyMs: 68, lastRiskScore: 0, lastRiskLevel: "low" }),
    ];
    const sorted = sortNodesForPicker(nodes);
    expect(sorted.map((n) => n.id)).toEqual(["clean-fast", "clean-slow", "high-fast", "unchecked", "dead"]);
    const t = (k: string) => (k === "Low risk" ? "低风险" : k === "Dead" ? "失效" : k);
    expect(formatPoolPickerOption(sorted[0]!, t)).toBe("[VLESS] HK-01 · HK · 68ms · 低风险 0");
    expect(formatPoolPickerOption(sorted[4]!, t)).toBe("[VLESS] Dead-01 · 失效");
  });
});
