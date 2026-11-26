import { expect, test } from "bun:test";
import { fetchDirectEgressTimed, measureHttp204Latency } from "./egress.ts";
import {
  checkProxy,
  classifyProxyAttempts,
  type ProxyCheckAttempt,
} from "./proxy-check.ts";

const direct = { ip: "198.51.100.10" };
const exit = (ip: string) => ({ info: { ip, country: "NL" } }) satisfies ProxyCheckAttempt;
const failed = (reason: ProxyCheckAttempt["reason"] = "connection_failed") => ({ info: null, reason }) satisfies ProxyCheckAttempt;

test("proxy check classifies stable and rotating successful exits as working", () => {
  expect(classifyProxyAttempts([
    exit("203.0.113.10"),
    exit("203.0.113.10"),
    exit("203.0.113.10"),
  ], direct)).toEqual({
    status: "working",
    attempts: 3,
    successes: 3,
    ip: "203.0.113.10",
    country: "NL",
    rotating: false,
  });

  expect(classifyProxyAttempts([
    exit("203.0.113.10"),
    exit("203.0.113.11"),
    exit("203.0.113.12"),
  ], direct)).toMatchObject({ status: "working", successes: 3, rotating: true });
});

test("proxy check calls only mixed connectivity unstable", () => {
  expect(classifyProxyAttempts([
    exit("203.0.113.10"),
    failed("timeout"),
    exit("203.0.113.11"),
  ], direct)).toMatchObject({
    status: "unstable",
    attempts: 3,
    successes: 2,
    reason: "intermittent",
  });
});

test("checker service failures stay neutral and never make a proven proxy unstable", () => {
  const unavailable = { info: null, reason: "check_unavailable" } as ProxyCheckAttempt;
  expect(classifyProxyAttempts([unavailable, unavailable, unavailable], direct)).toEqual({
    status: "unavailable",
    attempts: 3,
    successes: 0,
    reason: "check_unavailable",
  });
  expect(classifyProxyAttempts([
    exit("203.0.113.10"),
    unavailable,
    unavailable,
  ], direct)).toMatchObject({ status: "working", successes: 1, ip: "203.0.113.10" });
});

test("objective proxy failures stay failed when direct egress is unavailable", () => {
  for (const reason of ["authentication_failed", "dns_failed", "unreachable"] as const) {
    expect(classifyProxyAttempts([
      failed(reason),
      failed(reason),
      failed(reason),
    ], null)).toMatchObject({ status: "failed", reason });
  }
});

test("proxy check treats checker HTTP errors as unavailable, not a bad proxy", async () => {
  const result = await checkProxy({
    type: "http",
    host: "proxy.example",
    port: "8080",
    user: "",
    pass: "",
  }, {
    endpoints: ["https://egress.test/ip"],
    relayFactory: async () => ({ port: 43000, close() {} }),
    fetchFn: (async (_input: RequestInfo | URL, init?: RequestInit) =>
      (init as RequestInit & { proxy?: string } | undefined)?.proxy
        ? new Response("rate limited", { status: 429 })
        : Response.json({ ip: direct.ip })) as typeof fetch,
  });

  expect(result).toEqual({
    status: "unavailable",
    attempts: 3,
    successes: 0,
    reason: "check_unavailable",
  });
});

test("proxy check preserves HTTP 407 as an authentication failure", async () => {
  const result = await checkProxy({
    type: "http",
    host: "proxy.example",
    port: "8080",
    user: "proxy-user",
    pass: "wrong-password",
  }, {
    endpoints: ["http://egress.test/ip"],
    relayFactory: async () => ({ port: 44000, close() {} }),
    fetchFn: (async (_input: RequestInfo | URL, init?: RequestInit) => {
      if ((init as RequestInit & { proxy?: string } | undefined)?.proxy) {
        return new Response("proxy authentication required", { status: 407 });
      }
      throw new Error("direct egress is unavailable");
    }) as typeof fetch,
  });

  expect(result).toMatchObject({
    status: "failed",
    successes: 0,
    reason: "authentication_failed",
  });
});

test("proxy check distinguishes failure, bypass, and unavailable check services", () => {
  expect(classifyProxyAttempts([
    failed("authentication_failed"),
    failed("authentication_failed"),
    failed("authentication_failed"),
  ], direct)).toMatchObject({ status: "failed", reason: "authentication_failed" });

  expect(classifyProxyAttempts([
    exit(direct.ip),
    exit(direct.ip),
    exit(direct.ip),
  ], direct)).toMatchObject({ status: "failed", reason: "proxy_bypassed" });

  expect(classifyProxyAttempts([
    failed(),
    failed(),
    failed(),
  ], null)).toEqual({
    status: "unavailable",
    attempts: 3,
    successes: 0,
    reason: "check_unavailable",
  });
});

test("proxy check uses a fresh relay for every attempt and always closes it", async () => {
  const upstreams: unknown[] = [];
  const proxyUrls: string[] = [];
  let closed = 0;
  let nextPort = 41000;

  const result = await checkProxy({
    type: "socks5",
    host: "proxy.example",
    port: "1080",
    user: "proxy-user",
    pass: "proxy-password",
  }, {
    endpoints: ["https://egress.test/ip"],
    relayFactory: async (upstream) => {
      upstreams.push(upstream);
      return { port: nextPort++, close: () => { closed++; } };
    },
    fetchFn: (async (_input: RequestInfo | URL, init?: RequestInit) => {
      const proxy = (init as RequestInit & { proxy?: string } | undefined)?.proxy;
      if (proxy) {
        proxyUrls.push(proxy);
        return Response.json({ ip: "203.0.113.20", country: "US" });
      }
      return Response.json({ ip: direct.ip });
    }) as typeof fetch,
  });

  expect(result).toMatchObject({ status: "working", successes: 3, ip: "203.0.113.20" });
  expect(upstreams).toHaveLength(3);
  expect(upstreams[0]).toEqual({
    type: "socks5",
    host: "proxy.example",
    port: 1080,
    user: "proxy-user",
    pass: "proxy-password",
  });
  expect(new Set(proxyUrls)).toEqual(new Set([
    "http://127.0.0.1:41000",
    "http://127.0.0.1:41001",
    "http://127.0.0.1:41002",
  ]));
  expect(closed).toBe(3);
});

test("proxy check uses Bun fetch through a real loopback relay", async () => {
  const egress = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => Response.json({ ip: direct.ip }),
  });
  const upstream = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch: () => Response.json({ ip: "203.0.113.30", country: "DE" }),
  });
  try {
    await expect(checkProxy({
      type: "http",
      host: "127.0.0.1",
      port: String(upstream.port),
      user: "",
      pass: "",
    }, {
      endpoints: [`http://127.0.0.1:${egress.port}/ip`],
      timeoutMs: 2_000,
    })).resolves.toMatchObject({
      status: "working",
      attempts: 3,
      successes: 3,
      ip: "203.0.113.30",
      country: "DE",
    });
  } finally {
    upstream.stop(true);
    egress.stop(true);
  }
});

test("proxy check returns fixed safe failure reasons", async () => {
  const result = await checkProxy({
    type: "http",
    host: "proxy.example",
    port: "8080",
    user: "proxy-user",
    pass: "private-password",
  }, {
    endpoints: ["https://egress.test/ip"],
    relayFactory: async (_upstream, options) => {
      options?.log?.("upstream refused CONNECT egress.test:443: HTTP/1.1 407 Proxy Authentication Required");
      return { port: 42000, close() {} };
    },
    fetchFn: (async (_input: RequestInfo | URL, init?: RequestInit) => {
      if ((init as RequestInit & { proxy?: string } | undefined)?.proxy) throw new Error("connection closed");
      return Response.json({ ip: direct.ip });
    }) as typeof fetch,
  });

  expect(result).toMatchObject({ status: "failed", reason: "authentication_failed" });
  expect(JSON.stringify(result)).not.toContain("private-password");
  expect(JSON.stringify(result)).not.toContain("proxy.example");
});

test("proxy check rejects blank and unsupported proxy input before network activity", async () => {
  await expect(checkProxy({ host: "", port: "" })).rejects.toThrow("proxy is required");
  await expect(checkProxy({ type: "https", host: "proxy.example", port: "8443" })).rejects.toThrow(
    "use http or socks5",
  );
});

test("fetchDirectEgressTimed does not accumulate failed/429 endpoint wait time into fallback latency", async () => {
  const result = await fetchDirectEgressTimed(
    { endpoints: ["https://slow-429.test/ip", "https://fast-ok.test/ip"], timeoutMs: 2_000 },
    (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("slow-429")) {
        await Bun.sleep(120);
        return new Response("rate limited", { status: 429 });
      }
      await Bun.sleep(5);
      return Response.json({ ip: "203.0.113.88", country: "JP" });
    }) as unknown as typeof fetch,
  );
  expect(result.info).toEqual({ ip: "203.0.113.88", country: "JP" });
  expect(typeof result.latencyMs).toBe("number");
  expect(result.latencyMs!).toBeLessThan(90);
});

test("measureHttp204Latency falls back cleanly without accumulating failed endpoint delay and short-circuits 407", async () => {
  let cfHits = 0;
  const probe = await measureHttp204Latency(
    (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("gstatic.com")) {
        await Bun.sleep(120);
        return new Response("blocked", { status: 503 });
      }
      cfHits++;
      await Bun.sleep(cfHits === 1 ? 35 : 5);
      return new Response(null, { status: 204 });
    }) as unknown as typeof fetch,
  );
  expect(probe.endpoint).toBe("https://cp.cloudflare.com/generate_204");
  expect(cfHits).toBe(2); // 1 warmup + 1 timed probe
  expect(probe.latencyMs).not.toBeNull();
  expect(probe.latencyMs!).toBeLessThan(80);

  let authCalls = 0;
  const authFail = await measureHttp204Latency(
    (async () => {
      authCalls++;
      return new Response("proxy auth required", { status: 407 });
    }) as unknown as typeof fetch,
  );
  expect(authFail).toEqual({ latencyMs: null, authenticationFailed: true });
  expect(authCalls).toBe(1);
});

test("checkProxy reuses a single sing-box relay and decouples 204 latency from slow egress IP lookup", async () => {
  let specRelaysOpened = 0;
  let specRelaysClosed = 0;
  const seenUrls: string[] = [];
  const seenPorts = new Set<string>();

  const result = await checkProxy(
    { uri: "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?security=tls#US-1" },
    {
      direct,
      specRelayFactory: async () => {
        specRelaysOpened++;
        return {
          port: 45100 + specRelaysOpened,
          close: () => { specRelaysClosed++; },
        };
      },
      fetchFn: (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const proxy = (init as RequestInit & { proxy?: string } | undefined)?.proxy;
        if (proxy) seenPorts.add(proxy);
        seenUrls.push(url);
        if (url.includes("generate_204")) {
          await Bun.sleep(5);
          return new Response(null, { status: 204 });
        }
        // Simulate slow cross-ocean ipinfo.io TLS + JSON response
        await Bun.sleep(160);
        return Response.json({ ip: "198.51.100.42", country: "US", city: "San Jose" });
      }) as unknown as typeof fetch,
    },
  );

  // Must open and close ONLY ONE sing-box relay (never 3!)
  expect(specRelaysOpened).toBe(1);
  expect(specRelaysClosed).toBe(1);
  expect(seenPorts.size).toBe(1);
  expect(result).toMatchObject({
    status: "working",
    attempts: 3,
    successes: 3,
    ip: "198.51.100.42",
    country: "US",
    city: "San Jose",
    rotating: false,
  });
  // Latency must reflect the fast 204 Anycast probe, NOT the 160ms egress lookup!
  expect(seenUrls.some((u) => u.includes("www.gstatic.com/generate_204"))).toBe(true);
  expect(typeof result.latencyMs).toBe("number");
  expect(result.latencyMs!).toBeLessThan(120);
});

test("single-attempt pool mode reuses 1 relay for 204 probe + 1 egress lookup only", async () => {
  let relaysOpened = 0;
  let relaysClosed = 0;
  let egressCalls = 0;
  let probe204Calls = 0;

  const result = await checkProxy(
    { uri: "trojan://secret@node.example.com:443#JP-1" },
    {
      attempts: 1,
      reuseRelay: true,
      measureLatency: true,
      direct,
      specRelayFactory: async () => {
        relaysOpened++;
        return { port: 46100, close: () => { relaysClosed++; } };
      },
      fetchFn: (async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("generate_204")) {
          probe204Calls++;
          return new Response(null, { status: 204 });
        }
        egressCalls++;
        return Response.json({ ip: "203.0.113.99", country: "JP" });
      }) as unknown as typeof fetch,
    },
  );

  expect(relaysOpened).toBe(1);
  expect(relaysClosed).toBe(1);
  expect(probe204Calls).toBe(2); // 1 warmup + 1 timed 204 on same relay
  expect(egressCalls).toBe(1);   // 1 egress lookup only (not 3)
  expect(result).toMatchObject({
    status: "working",
    attempts: 1,
    successes: 1,
    ip: "203.0.113.99",
    country: "JP",
  });
  expect(result.latencyMs).toBeGreaterThanOrEqual(1);
});

test("dead sing-box pool node with skipped direct compare fails fast as timeout/connection_failed instead of unavailable", async () => {
  let egressCalls = 0;
  let probe204Calls = 0;

  const timedOut = await checkProxy(
    { uri: "vless://11111111-1111-1111-1111-111111111111@43.206.234.181:25331?security=tls#JP-Dead" },
    {
      attempts: 1,
      reuseRelay: true,
      measureLatency: true,
      direct: null,
      skipDirect: true,
      specRelayFactory: async (_proxy, opts) => {
        opts?.log?.("sing-box: ERROR connection: open connection using outbound/vless[proxy]: dial tcp 43.206.234.181:25331: i/o timeout");
        return { port: 46200, close() {} };
      },
      fetchFn: (async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("generate_204")) {
          probe204Calls++;
          return new Response("Bad Gateway", { status: 502 });
        }
        egressCalls++;
        return new Response("Bad Gateway", { status: 502 });
      }) as unknown as typeof fetch,
    },
  );

  // Must bail out right after the 204 probes without retrying all egress endpoints,
  // and must classify as `failed` (`timeout`) rather than `unavailable` (`check_unavailable`).
  expect(probe204Calls).toBe(2);
  expect(egressCalls).toBe(0);
  expect(timedOut).toEqual({
    status: "failed",
    attempts: 1,
    successes: 0,
    reason: "timeout",
  });
});
