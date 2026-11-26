import { expect, test } from "bun:test";
import { DEFAULT_LATENCY_ENDPOINTS, fetchDirectEgress, parseEgressResponse, resolveEgressEndpoints } from "./egress.ts";

test("parseEgressResponse accepts JSON, Cloudflare cdn-cgi/trace, and plain IPv4/IPv6 responses", () => {
  expect(parseEgressResponse('{"ip":"203.0.113.4","country":"US"}')).toEqual({ ip: "203.0.113.4", country: "US" });
  expect(parseEgressResponse('{"query":"2001:db8::1"}')).toEqual({ ip: "2001:db8::1" });
  expect(parseEgressResponse("198.51.100.9\n")).toEqual({ ip: "198.51.100.9" });
  expect(parseEgressResponse("fl=975f65\nh=1.1.1.1\nip=45.207.156.192\nts=1795683258.000\nloc=HK\n")).toEqual({
    ip: "45.207.156.192",
    country: "HK",
  });
  expect(parseEgressResponse("ip=203.0.113.55\nloc=XX\n")).toEqual({ ip: "203.0.113.55" });
  expect(DEFAULT_LATENCY_ENDPOINTS.every((u) => u.startsWith("https://"))).toBe(true);
});

test("parseEgressResponse rejects malformed responses", () => {
  expect(parseEgressResponse("")).toBeNull();
  expect(parseEgressResponse("not an ip")).toBeNull();
  expect(parseEgressResponse('{"ip":"localhost"}')).toBeNull();
});

test("egress endpoints support an operator override and reject invalid schemes", () => {
  expect(resolveEgressEndpoints("https://one.example/ip, http://127.0.0.1:8080/ip")).toEqual([
    "https://one.example/ip",
    "http://127.0.0.1:8080/ip",
  ]);
  expect(() => resolveEgressEndpoints("")).toThrow("at least one URL");
  expect(() => resolveEgressEndpoints("file:///tmp/ip")).toThrow("must use http or https");
});

test("direct egress reports request and service failures without exposing raw errors", async () => {
  const seen: string[] = [];
  const failures: string[] = [];
  const info = await fetchDirectEgress({
    endpoints: ["https://one.test/ip", "https://two.test/ip"],
  }, (async (endpoint: string) => {
    seen.push(endpoint);
    if (endpoint.includes("one")) throw new Error("unavailable");
    return new Response('{"ip":"198.51.100.7"}');
  }) as typeof fetch, (failure) => failures.push(failure));

  expect(info).toEqual({ ip: "198.51.100.7" });
  expect(seen).toEqual(["https://one.test/ip", "https://two.test/ip"]);
  expect(failures).toEqual(["request_failed"]);

  await expect(fetchDirectEgress({ endpoints: ["https://one.test/ip"] },
    (async () => new Response("rate limited", { status: 429 })) as unknown as typeof fetch,
    (failure) => failures.push(failure),
  )).resolves.toBeNull();
  expect(failures).toEqual(["request_failed", "service_failed"]);

  await expect(fetchDirectEgress({ endpoints: ["http://one.test/ip"] },
    (async () => new Response("proxy authentication required", { status: 407 })) as unknown as typeof fetch,
    (failure) => failures.push(failure),
  )).resolves.toBeNull();
  expect(failures).toEqual([
    "request_failed",
    "service_failed",
    "proxy_authentication_failed",
  ]);
});
