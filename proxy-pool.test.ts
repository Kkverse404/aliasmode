import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProfileStore } from "./store.ts";
import { handleProxyPoolRequest } from "./proxy-pool.ts";
import { buildNewProfile } from "./create.ts";
import type { Launcher } from "./launcher.ts";

const tempDirs: string[] = [];

function createTestStore(): ProfileStore {
  const dir = mkdtempSync(join(tmpdir(), "aliasmode-pool-test-"));
  tempDirs.push(dir);
  return new ProfileStore(join(dir, "profiles.sqlite"));
}

const mockLauncher = {
  cacheCleanupSettled: async () => {},
  profileDeletionBlocked: () => false,
} as unknown as Launcher;

const VLESS_URI = "vless://11111111-1111-4111-8111-111111111111@transit.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=4r6e9gT4n1p8mK3yX2wV7qL5jH0cF6bD8aZ9sE1uR2M&sid=01ab#US-Transit";
const HY2_URI = "hy2://mypass@hy.example.com:443?sni=hy.example.com#JP-HY2";
const SOCKS_RES = "socks5://resuser:respass@203.0.113.20:1080";

afterEach(() => {
  while (tempDirs.length) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("proxy pool & subscription API", () => {
  test("imports manual nodes with deduplication and lists them", async () => {
    const store = createTestStore();
    try {
      const importReq = new Request("http://127.0.0.1/ui/api/proxy-pool/nodes/import", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input: `${VLESS_URI}\n${SOCKS_RES}\n${VLESS_URI}` }),
      });
      const importRes = await handleProxyPoolRequest(importReq, store, mockLauncher);
      expect(importRes.status).toBe(200);
      const importBody = await importRes.json() as any;
      expect(importBody).toMatchObject({ ok: true, imported: 2, duplicates: 1, skipped: 0 });

      const listRes = await handleProxyPoolRequest(new Request("http://127.0.0.1/ui/api/proxy-pool"), store, mockLauncher);
      const listBody = await listRes.json() as any;
      expect(listBody.ok).toBe(true);
      expect(listBody.nodes).toHaveLength(2);
      expect(listBody.nodes.map((n: any) => n.type).sort()).toEqual(["socks5", "vless"]);
    } finally {
      store.close();
    }
  });

  test("adds, refreshes, and deletes a Base64 subscription", async () => {
    const store = createTestStore();
    let payloadLines = [VLESS_URI, HY2_URI];
    const mockFetch = (async () => new Response(
      Buffer.from(payloadLines.join("\n"), "utf8").toString("base64"),
      {
        status: 200,
        headers: { "subscription-userinfo": "upload=100; download=200; total=10000; expire=1900000000" },
      },
    )) as unknown as typeof fetch;

    try {
      const addRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/subscriptions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: "My Airport", url: "https://sub.example.com/api/v1/client/subscribe?token=abc" }),
        }),
        store,
        mockLauncher,
        {},
        { subscriptionFetch: mockFetch },
      );
      const addBody = await addRes.json() as any;
      expect(addBody.ok).toBe(true);
      expect(addBody.imported).toBe(2);
      expect(addBody.subscription.name).toBe("My Airport");
      expect(addBody.subscription.userInfo).toEqual({ upload: 100, download: 200, total: 10000, expire: 1900000000 });

      // Refresh with only 1 node replaces old subscription nodes atomically.
      payloadLines = [VLESS_URI];
      const refreshRes = await handleProxyPoolRequest(
        new Request(`http://127.0.0.1/ui/api/proxy-pool/subscriptions/${addBody.subscription.id}/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        }),
        store,
        mockLauncher,
        {},
        { subscriptionFetch: mockFetch },
      );
      const refreshBody = await refreshRes.json() as any;
      expect(refreshBody.ok).toBe(true);
      expect(refreshBody.imported).toBe(1);
      expect(store.listProxyNodes(addBody.subscription.id)).toHaveLength(1);

      // Delete removes subscription and its nodes.
      const delRes = await handleProxyPoolRequest(
        new Request(`http://127.0.0.1/ui/api/proxy-pool/subscriptions/${addBody.subscription.id}`, { method: "DELETE" }),
        store,
        mockLauncher,
      );
      expect((await delRes.json() as any).ok).toBe(true);
      expect(store.listProxySubscriptions()).toHaveLength(0);
      expect(store.listProxyNodes()).toHaveLength(0);
    } finally {
      store.close();
    }
  });

  test("checks nodes and assigns chained proxies (transit + residential landing) to profiles", async () => {
    const store = createTestStore();
    try {
      const p1 = buildNewProfile({ name: "Google-1", group: "Google" }, () => false);
      const p2 = buildNewProfile({ name: "Google-2", group: "Google" }, () => false);
      store.upsertProfile(p1);
      store.upsertProfile(p2);

      // Import 1 transit node + 2 residential SOCKS5 nodes
      const importRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/nodes/import", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            input: `${VLESS_URI}\nsocks5://u1:p1@203.0.113.11:1080\nsocks5://u2:p2@203.0.113.12:1080`,
          }),
        }),
        store,
        mockLauncher,
      );
      const imported = (await importRes.json() as any).nodes as any[];
      const transitNode = imported.find((n) => n.type === "vless");
      const landingNodes = imported.filter((n) => n.type === "socks5");

      // Check landing nodes through transit pre-proxy
      const checkedProxies: any[] = [];
      const checkRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/nodes/check", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids: landingNodes.map((n) => n.id), preProxyNodeId: transitNode.id }),
        }),
        store,
        mockLauncher,
        {},
        {
          proxyCheck: async (proxy) => {
            checkedProxies.push(proxy);
            return {
              status: "working",
              attempts: 3,
              successes: 3,
              ip: proxy.host,
              country: "US",
              city: "Los Angeles",
              isp: "Example Residential ISP",
              ipType: "residential",
              riskScore: 12,
              riskLevel: "low",
              riskFlags: ["residential"],
              latencyMs: 88,
            };
          },
        },
      );
      const checkBody = await checkRes.json() as any;
      expect(checkBody.ok).toBe(true);
      expect(checkedProxies).toHaveLength(2);
      expect(checkedProxies[0].preProxy.type).toBe("vless");
      const checkedNode = store.getProxyNode(landingNodes[0].id);
      expect(checkedNode?.lastStatus).toBe("working");
      expect(checkedNode?.lastCountry).toBe("US");
      expect(checkedNode?.lastCity).toBe("Los Angeles");
      expect(checkedNode?.lastIsp).toBe("Example Residential ISP");
      expect(checkedNode?.lastIpType).toBe("residential");
      expect(checkedNode?.lastRiskScore).toBe(12);
      expect(checkedNode?.lastRiskLevel).toBe("low");
      expect(checkedNode?.lastRiskFlags).toEqual(["residential"]);
      expect(checkedNode?.lastLatencyMs).toBe(88);

      // Verify GET /ui/api/proxy-pool surfaces the persisted risk & latency fields
      const poolRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool"),
        store,
        mockLauncher,
      );
      const poolBody = await poolRes.json() as any;
      const poolViewNode = poolBody.nodes.find((n: any) => n.id === landingNodes[0].id);
      expect(poolViewNode).toMatchObject({
        lastStatus: "working",
        lastCountry: "US",
        lastCity: "Los Angeles",
        lastIsp: "Example Residential ISP",
        lastIpType: "residential",
        lastRiskScore: 12,
        lastRiskLevel: "low",
        lastRiskFlags: ["residential"],
        lastLatencyMs: 88,
      });

      // Assign landing nodes chained via transitNode to folder "Google" (1 profile per node)
      const assignRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/assign", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scope: { groups: ["Google"] },
            nodeIds: landingNodes.map((n) => n.id),
            preProxyNodeId: transitNode.id,
            profilesPerNode: 1,
          }),
        }),
        store,
        mockLauncher,
        {},
        {
          timezoneFetch: async () => ({ json: async () => ({ timezone: "America/Los_Angeles", country_code: "US", ip: "203.0.113.11" }) }),
        },
      );
      const assignBody = await assignRes.json() as any;
      expect(assignBody).toMatchObject({ ok: true, assigned: 2, skipped: 0, failed: 0 });

      const updated1 = store.getProfile(p1.id)!;
      const updated2 = store.getProfile(p2.id)!;
      expect(updated1.proxy?.type).toBe("socks5");
      expect(updated1.proxy?.preProxy?.type).toBe("vless");
      expect(updated2.proxy?.type).toBe("socks5");
      expect(updated2.proxy?.preProxy?.type).toBe("vless");
      expect(updated1.proxy?.host).not.toBe(updated2.proxy?.host);
    } finally {
      store.close();
    }
  });

  test("preserves node IDs and check metadata on subscription refresh and forwards useLocalClash proxy", async () => {
    const store = createTestStore();
    let payloadLines = [VLESS_URI, HY2_URI];
    const seenProxyInits: Array<string | undefined> = [];
    const mockFetch = (async (_input: RequestInfo | URL, init?: RequestInit & { proxy?: string }) => {
      seenProxyInits.push(init?.proxy);
      return new Response(Buffer.from(payloadLines.join("\n"), "utf8").toString("base64"), { status: 200 });
    }) as unknown as typeof fetch;

    try {
      const addRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/subscriptions", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name: "SubA", url: "https://sub.example.com/list", useLocalClash: true }),
        }),
        store,
        mockLauncher,
        {},
        { subscriptionFetch: mockFetch },
      );
      const addBody = await addRes.json() as any;
      expect(seenProxyInits[0]).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);

      const vlessBefore = store.listProxyNodes(addBody.subscription.id).find((n) => n.proxy.type === "vless")!;
      store.updateProxyNodeCheck(vlessBefore.id, "working", "198.51.100.5", "US", 72, 123456, {
        reason: "",
        city: "San Jose",
        isp: "Residential ISP",
        ipType: "residential",
        riskScore: 5,
        riskLevel: "low",
        riskFlags: ["residential"],
      });

      // Refresh subscription keeping VLESS node (even if renamed) and dropping HY2
      payloadLines = [VLESS_URI.replace("#US-Transit", "#US-Transit-Renamed")];
      const refreshRes = await handleProxyPoolRequest(
        new Request(`http://127.0.0.1/ui/api/proxy-pool/subscriptions/${addBody.subscription.id}/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ useLocalClash: false }),
        }),
        store,
        mockLauncher,
        {},
        { subscriptionFetch: mockFetch },
      );
      const refreshBody = await refreshRes.json() as any;
      expect(refreshBody).toMatchObject({ ok: true, imported: 1, preserved: 1 });
      expect(seenProxyInits[1]).toBeUndefined();

      const after = store.listProxyNodes(addBody.subscription.id);
      expect(after).toHaveLength(1);
      expect(after[0]!.id).toBe(vlessBefore.id);
      expect(after[0]!.name).toBe("US-Transit-Renamed");
      expect(after[0]).toMatchObject({
        lastStatus: "working",
        lastIp: "198.51.100.5",
        lastCountry: "US",
        lastCity: "San Jose",
        lastIsp: "Residential ISP",
        lastIpType: "residential",
        lastRiskScore: 5,
        lastRiskLevel: "low",
        lastRiskFlags: ["residential"],
        lastLatencyMs: 72,
        lastCheckedAt: 123456,
      });
    } finally {
      store.close();
    }
  });

  test("streams NDJSON node checks, stores lastReason, skips direct compare for sing-box, supports includeRisk=false and skips failed on assign", async () => {
    const store = createTestStore();
    try {
      const p1 = buildNewProfile({ name: "P1", group: "G1" }, () => false);
      store.upsertProfile(p1);

      const importRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/nodes/import", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ input: `${VLESS_URI}\n${HY2_URI}` }),
        }),
        store,
        mockLauncher,
      );
      const nodes = (await importRes.json() as any).nodes as any[];
      const seenOpts: Array<{ type: string; direct: unknown; includeRisk: unknown }> = [];

      const streamRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/nodes/check", {
          method: "POST",
          headers: { "Content-Type": "application/json", Accept: "application/x-ndjson" },
          body: JSON.stringify({ ids: nodes.map((n) => n.id), includeRisk: false, stream: true }),
        }),
        store,
        mockLauncher,
        {},
        {
          proxyCheck: async (proxy, opts) => {
            seenOpts.push({ type: proxy.type, direct: opts?.direct, includeRisk: opts?.includeRisk });
            if (proxy.type === "vless") {
              return { status: "working", attempts: 1, successes: 1, ip: "203.0.113.50", country: "HK", latencyMs: 62 };
            }
            return { status: "failed", attempts: 1, successes: 0, reason: "timeout" };
          },
        },
      );
      expect(streamRes.headers.get("content-type")).toContain("application/x-ndjson");
      const lines = (await streamRes.text()).trim().split("\n").map((l) => JSON.parse(l));
      expect(lines.some((e) => e.type === "progress" && e.completed === 0 && e.total === 2)).toBe(true);
      expect(lines.filter((e) => e.type === "result")).toHaveLength(2);
      expect(lines.at(-1)).toEqual({ type: "done", completed: 2, total: 2, cancelled: false });

      // Both sing-box nodes must skip direct egress compare (direct === null) and respect includeRisk: false
      expect(seenOpts.every((o) => o.direct === null && o.includeRisk === false)).toBe(true);

      const failedNode = store.listProxyNodes().find((n) => n.proxy.type === "hysteria2")!;
      const workingNode = store.listProxyNodes().find((n) => n.proxy.type === "vless")!;
      expect(failedNode.lastStatus).toBe("failed");
      expect(failedNode.lastReason).toBe("timeout");
      expect(workingNode.lastStatus).toBe("working");
      expect(workingNode.lastReason).toBe("");

      // Assigning [failedNode, workingNode] must automatically skip failedNode and assign workingNode!
      const assignRes = await handleProxyPoolRequest(
        new Request("http://127.0.0.1/ui/api/proxy-pool/assign", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            scope: { groups: ["G1"] },
            nodeIds: [failedNode.id, workingNode.id],
          }),
        }),
        store,
        mockLauncher,
        {},
        { timezoneFetch: async () => ({ json: async () => ({ timezone: "Asia/Hong_Kong", country_code: "HK", ip: "203.0.113.50" }) }) },
      );
      const assignBody = await assignRes.json() as any;
      expect(assignBody).toMatchObject({ ok: true, assigned: 1, skippedFailedNodes: 1 });
      expect(store.getProfile(p1.id)?.proxy?.type).toBe("vless");
    } finally {
      store.close();
    }
  });
});
