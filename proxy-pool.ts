/**
 * Local proxy node pool, subscription sync, sing-box kernel management,
 * node checking, and one-click batch profile assignment (including chain proxies).
 */

import { fetchDirectEgress } from "./egress.ts";
import { checkProxy, type ProxyCheckOptions, type ProxyCheckResult } from "./proxy-check.ts";
import { startProxyRelay, type ProxyRelay } from "./proxy-relay.ts";
import { attachTimezones, type FetchLike } from "./geoip.ts";
import { syncFirefoxTimezone } from "./firefox-config.ts";
import { selectProxyProfiles, type ProxyInventoryProfile } from "./proxy-bulk.ts";
import { isSingBoxProxy, normalizeProxySpec, proxyDisplaySummary, proxyIdentityKey, proxyLegacyString } from "./proxy.ts";
import { buildLocalClashProxySpec, readLocalNetworkSettings } from "./local-network.ts";
import { fetchProxySubscription, parseSubscriptionContent } from "./proxy-subscription.ts";
import { defaultSingBoxRuntimeRoot, ensureSingBoxBinary, singBoxKernelStatus } from "./singbox-runtime.ts";
import type { Launcher } from "./launcher.ts";
import type { ProfileStore } from "./store.ts";
import type { UiRuntimeOptions } from "./ui.ts";
import type { ProxyPoolNode, ProxySpec, ProxySubscription } from "./types.ts";
import type { ProxyScope } from "./proxy-tools-types.ts";

export interface ProxyPoolNodeView {
  id: string;
  name: string;
  subscriptionId: string;
  type: ProxySpec["type"];
  host: string;
  port: string;
  summary: string;
  hasChain: boolean;
  /** Loopback-only editable value (share URI or host:port[:user:pass]) for quick profile fill. */
  value: string;
  proxy: ProxySpec;
  tags: string[];
  lastStatus: ProxyPoolNode["lastStatus"];
  lastReason: string;
  lastIp: string;
  lastCountry: string;
  lastCity: string;
  lastIsp: string;
  lastIpType: NonNullable<ProxyPoolNode["lastIpType"]>;
  lastRiskScore: number | null;
  lastRiskLevel: NonNullable<ProxyPoolNode["lastRiskLevel"]>;
  lastRiskFlags: string[];
  lastLatencyMs: number | null;
  lastCheckedAt: number;
  createdAt: number;
}

export interface ProxyPoolCheckResultItem {
  id: string;
  status: ProxyPoolNode["lastStatus"];
  reason: string;
  ip: string;
  country: string;
  city: string;
  isp: string;
  ipType: NonNullable<ProxyPoolNode["lastIpType"]>;
  riskScore: number | null;
  riskLevel: NonNullable<ProxyPoolNode["lastRiskLevel"]>;
  riskFlags: string[];
  latencyMs: number | null;
  checkedAt: number;
}

export type ProxyPoolCheckStreamEvent =
  | { type: "progress"; completed: number; total: number }
  | { type: "result"; item: ProxyPoolCheckResultItem }
  | { type: "done"; completed: number; total: number; cancelled: boolean }
  | { type: "error"; error: string };

export function proxyPoolNodeView(node: ProxyPoolNode): ProxyPoolNodeView {
  return {
    id: node.id,
    name: node.name,
    subscriptionId: node.subscriptionId,
    type: node.proxy.type,
    host: node.proxy.host,
    port: node.proxy.port,
    summary: proxyDisplaySummary(node.proxy),
    hasChain: !!node.proxy.preProxy,
    value: proxyLegacyString(node.proxy),
    proxy: node.proxy,
    tags: node.tags,
    lastStatus: node.lastStatus,
    lastReason: node.lastReason ?? "",
    lastIp: node.lastIp,
    lastCountry: node.lastCountry,
    lastCity: node.lastCity ?? "",
    lastIsp: node.lastIsp ?? "",
    lastIpType: node.lastIpType ?? "",
    lastRiskScore: node.lastRiskScore ?? null,
    lastRiskLevel: node.lastRiskLevel ?? "",
    lastRiskFlags: node.lastRiskFlags ?? [],
    lastLatencyMs: node.lastLatencyMs,
    lastCheckedAt: node.lastCheckedAt,
    createdAt: node.createdAt,
  };
}

async function fetchSubscriptionViaOptionalClash(
  url: string,
  useLocalClash: boolean,
  fetchFn?: typeof fetch,
) {
  if (!useLocalClash) {
    return fetchProxySubscription(url, { fetchFn });
  }
  const clashUrl = readLocalNetworkSettings().localClashUrl;
  if (/^socks5:\/\//i.test(clashUrl)) {
    const clashSpec = buildLocalClashProxySpec(clashUrl);
    let relay: ProxyRelay | undefined;
    try {
      relay = await startProxyRelay({
        type: "socks5",
        host: clashSpec.host,
        port: Number(clashSpec.port),
        user: clashSpec.user,
        pass: clashSpec.pass,
      });
      return await fetchProxySubscription(url, { fetchFn, proxyUrl: `http://127.0.0.1:${relay.port}` });
    } finally {
      relay?.close();
    }
  }
  return fetchProxySubscription(url, { fetchFn, proxyUrl: clashUrl });
}

function shouldSkipDirectCompare(proxy: ProxySpec): boolean {
  return isSingBoxProxy(proxy) || !!proxy.preProxy || proxy.mode === "local-clash";
}

function noStoreJson(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function defaultSubscriptionName(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname || "Subscription";
  } catch {
    return "Subscription";
  }
}

export interface ProxyPoolRequestDeps {
  subscriptionFetch?: typeof fetch;
  proxyCheck?: (proxy: ProxySpec, options?: ProxyCheckOptions) => Promise<ProxyCheckResult>;
  timezoneFetch?: FetchLike;
}

export async function handleProxyPoolRequest(
  req: Request,
  store: ProfileStore,
  launcher: Launcher,
  options: UiRuntimeOptions = {},
  deps: ProxyPoolRequestDeps = {},
): Promise<Response> {
  const { pathname } = new URL(req.url);
  const runtimeRoot = options.paths?.browser ?? defaultSingBoxRuntimeRoot();

  try {
    // GET /ui/api/proxy-pool
    if (pathname === "/ui/api/proxy-pool" && req.method === "GET") {
      const subscriptions = store.listProxySubscriptions();
      const nodes = store.listProxyNodes().map(proxyPoolNodeView);
      return noStoreJson({
        ok: true,
        kernel: singBoxKernelStatus(runtimeRoot),
        subscriptions,
        nodes,
      });
    }

    // GET /ui/api/proxy-pool/kernel
    if (pathname === "/ui/api/proxy-pool/kernel" && req.method === "GET") {
      return noStoreJson({ ok: true, kernel: singBoxKernelStatus(runtimeRoot) });
    }

    // POST /ui/api/proxy-pool/kernel/install
    if (pathname === "/ui/api/proxy-pool/kernel/install" && req.method === "POST") {
      await ensureSingBoxBinary(runtimeRoot);
      return noStoreJson({ ok: true, kernel: singBoxKernelStatus(runtimeRoot) });
    }

    // POST /ui/api/proxy-pool/subscriptions  (add & sync)
    if (pathname === "/ui/api/proxy-pool/subscriptions" && req.method === "POST") {
      const body = (await req.json()) as { name?: unknown; url?: unknown; useLocalClash?: unknown };
      const url = typeof body?.url === "string" ? body.url.trim() : "";
      if (!url) return noStoreJson({ ok: false, error: "Subscription URL is required" }, 400);
      const name = typeof body?.name === "string" && body.name.trim()
        ? body.name.trim()
        : defaultSubscriptionName(url);
      const useLocalClash = body?.useLocalClash === true;

      const now = Date.now();
      const subId = `sub_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
      const parsed = await fetchSubscriptionViaOptionalClash(url, useLocalClash, deps.subscriptionFetch);
      const sub: ProxySubscription = {
        id: subId,
        name,
        url,
        nodeCount: parsed.nodes.length,
        lastUpdatedAt: now,
        lastError: "",
        ...(parsed.userInfo ? { userInfo: parsed.userInfo } : {}),
        createdAt: now,
      };
      store.upsertProxySubscription(sub);
      const poolNodes: ProxyPoolNode[] = parsed.nodes.map((entry, idx) => ({
        id: `node_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`,
        name: entry.name || `${name} #${idx + 1}`,
        subscriptionId: subId,
        proxy: entry.proxy,
        tags: [],
        lastStatus: "",
        lastReason: "",
        lastIp: "",
        lastCountry: "",
        lastLatencyMs: null,
        lastCheckedAt: 0,
        createdAt: now + idx,
      }));
      store.replaceSubscriptionNodes(subId, poolNodes);
      return noStoreJson({
        ok: true,
        subscription: store.getProxySubscription(subId),
        imported: poolNodes.length,
        skipped: parsed.skipped,
        format: parsed.format,
      });
    }

    // POST /ui/api/proxy-pool/subscriptions/:id/refresh
    const refreshMatch = pathname.match(/^\/ui\/api\/proxy-pool\/subscriptions\/([^/]+)\/refresh$/);
    if (refreshMatch && req.method === "POST") {
      const id = decodeURIComponent(refreshMatch[1]!);
      const existing = store.getProxySubscription(id);
      if (!existing) return noStoreJson({ ok: false, error: "Subscription not found" }, 404);
      const body = (await req.json().catch(() => ({}))) as { useLocalClash?: unknown };
      const useLocalClash = body?.useLocalClash === true;
      try {
        const parsed = await fetchSubscriptionViaOptionalClash(existing.url, useLocalClash, deps.subscriptionFetch);
        const now = Date.now();
        // Match existing nodes by proxyIdentityKey so unchanged nodes keep their
        // original IDs (preserving pre-proxy selections) and last check metadata.
        const oldByKey = new Map<string, ProxyPoolNode[]>();
        for (const oldNode of store.listProxyNodes(id)) {
          const key = proxyIdentityKey(oldNode.proxy);
          const bucket = oldByKey.get(key);
          if (bucket) bucket.push(oldNode);
          else oldByKey.set(key, [oldNode]);
        }
        store.upsertProxySubscription({
          ...existing,
          nodeCount: parsed.nodes.length,
          lastUpdatedAt: now,
          lastError: "",
          ...(parsed.userInfo ? { userInfo: parsed.userInfo } : {}),
        });
        let preserved = 0;
        const poolNodes: ProxyPoolNode[] = parsed.nodes.map((entry, idx) => {
          const prev = oldByKey.get(proxyIdentityKey(entry.proxy))?.shift();
          if (prev) {
            preserved++;
            return {
              ...prev,
              name: entry.name || prev.name || `${existing.name} #${idx + 1}`,
              subscriptionId: id,
              proxy: entry.proxy,
            };
          }
          return {
            id: `node_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`,
            name: entry.name || `${existing.name} #${idx + 1}`,
            subscriptionId: id,
            proxy: entry.proxy,
            tags: [],
            lastStatus: "",
            lastReason: "",
            lastIp: "",
            lastCountry: "",
            lastLatencyMs: null,
            lastCheckedAt: 0,
            createdAt: now + idx,
          };
        });
        store.replaceSubscriptionNodes(id, poolNodes);
        return noStoreJson({
          ok: true,
          subscription: store.getProxySubscription(id),
          imported: poolNodes.length,
          preserved,
          skipped: parsed.skipped,
          format: parsed.format,
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        store.upsertProxySubscription({ ...existing, lastError: message });
        return noStoreJson({ ok: false, error: message }, 502);
      }
    }

    // DELETE /ui/api/proxy-pool/subscriptions/:id
    const subDeleteMatch = pathname.match(/^\/ui\/api\/proxy-pool\/subscriptions\/([^/]+)$/);
    if (subDeleteMatch && req.method === "DELETE") {
      const id = decodeURIComponent(subDeleteMatch[1]!);
      const deleted = store.deleteProxySubscription(id, true);
      if (!deleted) return noStoreJson({ ok: false, error: "Subscription not found" }, 404);
      return noStoreJson({ ok: true, deleted: true });
    }

    // POST /ui/api/proxy-pool/nodes/import  (paste URIs / Base64 / Clash YAML / sing-box JSON)
    if (pathname === "/ui/api/proxy-pool/nodes/import" && req.method === "POST") {
      const body = (await req.json()) as { input?: unknown; tags?: unknown };
      const input = typeof body?.input === "string" ? body.input : "";
      if (!input.trim()) return noStoreJson({ ok: false, error: "Paste at least one proxy URI or node list" }, 400);
      const tags = Array.isArray(body?.tags) ? body.tags.map(String).map((t) => t.trim()).filter(Boolean) : [];
      const parsed = parseSubscriptionContent(input);
      if (!parsed.nodes.length) {
        return noStoreJson({ ok: false, error: "No valid proxy nodes were found in the pasted text" }, 400);
      }
      const existingManualKeys = new Set(
        store.listProxyNodes("").map((node) => proxyIdentityKey(node.proxy)),
      );
      const now = Date.now();
      let imported = 0;
      let duplicates = 0;
      const created: ProxyPoolNodeView[] = [];
      for (let i = 0; i < parsed.nodes.length; i++) {
        const entry = parsed.nodes[i]!;
        const key = proxyIdentityKey(entry.proxy);
        if (existingManualKeys.has(key)) {
          duplicates++;
          continue;
        }
        existingManualKeys.add(key);
        const node: ProxyPoolNode = {
          id: `node_${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`,
          name: entry.name,
          subscriptionId: "",
          proxy: entry.proxy,
          tags,
          lastStatus: "",
          lastIp: "",
          lastCountry: "",
          lastLatencyMs: null,
          lastCheckedAt: 0,
          createdAt: now + i,
        };
        store.upsertProxyNode(node);
        created.push(proxyPoolNodeView(node));
        imported++;
      }
      return noStoreJson({
        ok: true,
        imported,
        duplicates,
        skipped: parsed.skipped,
        format: parsed.format,
        nodes: created,
      });
    }

    // POST /ui/api/proxy-pool/nodes/delete
    if (pathname === "/ui/api/proxy-pool/nodes/delete" && req.method === "POST") {
      const body = (await req.json()) as { ids?: unknown };
      const ids = Array.isArray(body?.ids) ? body.ids.map(String).filter(Boolean) : [];
      if (!ids.length) return noStoreJson({ ok: false, error: "Select at least one node to delete" }, 400);
      const deleted = store.deleteProxyNodes(ids);
      return noStoreJson({ ok: true, deleted });
    }

    // POST /ui/api/proxy-pool/nodes/check
    if (pathname === "/ui/api/proxy-pool/nodes/check" && req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as {
        ids?: unknown;
        preProxyNodeId?: unknown;
        includeRisk?: unknown;
        stream?: unknown;
      };
      const requestedIds = Array.isArray(body?.ids) ? new Set(body.ids.map(String)) : null;
      const allNodes = store.listProxyNodes();
      const targets = requestedIds ? allNodes.filter((n) => requestedIds.has(n.id)) : allNodes;
      const wantStream = body?.stream === true || !!req.headers.get("accept")?.includes("application/x-ndjson");
      const includeRisk = body?.includeRisk !== false;

      const preProxyNodeId = typeof body?.preProxyNodeId === "string" ? body.preProxyNodeId.trim() : "";
      const preProxySpec = preProxyNodeId === "__local_clash__"
        ? buildLocalClashProxySpec()
        : preProxyNodeId
          ? store.getProxyNode(preProxyNodeId)?.proxy ?? null
          : null;
      if (preProxyNodeId && !preProxySpec) {
        return noStoreJson({ ok: false, error: "Selected pre-proxy node was not found" }, 404);
      }

      if (!targets.length) {
        if (wantStream) {
          const doneLine = `${JSON.stringify({ type: "done", completed: 0, total: 0, cancelled: false } satisfies ProxyPoolCheckStreamEvent)}\n`;
          return new Response(doneLine, {
            headers: { "Content-Type": "application/x-ndjson; charset=utf-8", "Cache-Control": "no-store" },
          });
        }
        return noStoreJson({ ok: true, results: [] });
      }

      const effectiveById = new Map<string, ProxySpec>();
      for (const node of targets) {
        const effectiveProxy = preProxySpec && preProxyNodeId !== node.id
          ? normalizeProxySpec({ ...node.proxy, preProxy: preProxySpec })!
          : node.proxy;
        effectiveById.set(node.id, effectiveProxy);
      }

      const injectedCheck = deps.proxyCheck ?? options.proxyCheck;
      const runBatch = async (
        onItem: (item: ProxyPoolCheckResultItem, completed: number, total: number) => void,
        isCancelled: () => boolean,
      ): Promise<{ results: ProxyPoolCheckResultItem[]; completed: number; cancelled: boolean }> => {
        // Only fetch direct egress when at least one non-sing-box, non-chained, non-local-clash
        // plain HTTP/SOCKS5 node is checked; skipping it for sing-box/chained nodes avoids both
        // extra latency and Clash TUN false `proxy_bypassed` verdicts.
        const needsDirect = !injectedCheck && targets.some((node) => {
          const eff = effectiveById.get(node.id)!;
          return !shouldSkipDirectCompare(eff) && eff.type !== "https";
        });
        const sharedDirect = needsDirect && !isCancelled()
          ? await fetchDirectEgress({ timeoutMs: 5_000 }).catch(() => null)
          : null;

        const results: ProxyPoolCheckResultItem[] = [];
        let cursor = 0;
        let completed = 0;
        const total = targets.length;

        const worker = async () => {
          while (!isCancelled() && cursor < total) {
            const node = targets[cursor++]!;
            const effectiveProxy = effectiveById.get(node.id)!;
            const checkedAt = Date.now();
            let item: ProxyPoolCheckResultItem;

            if (!isSingBoxProxy(effectiveProxy) && effectiveProxy.type === "https") {
              item = {
                id: node.id,
                status: "unavailable",
                reason: "unsupported",
                ip: "",
                country: "",
                city: "",
                isp: "",
                ipType: "",
                riskScore: null,
                riskLevel: "",
                riskFlags: [],
                latencyMs: null,
                checkedAt,
              };
              store.updateProxyNodeCheck(node.id, "unavailable", "", "", null, checkedAt, { reason: "unsupported" });
            } else {
              const startedAt = Date.now();
              try {
                const checkOpts: ProxyCheckOptions = {
                  attempts: 1,
                  reuseRelay: true,
                  measureLatency: true,
                  includeRisk,
                  direct: shouldSkipDirectCompare(effectiveProxy) ? null : sharedDirect,
                  timeoutMs: 6_000,
                };
                const res = injectedCheck
                  ? await injectedCheck(effectiveProxy, checkOpts)
                  : await checkProxy(effectiveProxy, checkOpts);
                const ok = res.status === "working" || res.status === "unstable";
                const latencyMs = ok
                  ? (typeof res.latencyMs === "number" && Number.isFinite(res.latencyMs)
                    ? Math.max(1, Math.round(res.latencyMs))
                    : Math.max(1, Date.now() - startedAt))
                  : null;
                const ip = res.ip ?? "";
                const country = res.country ?? "";
                const reason = res.status === "working" ? "" : (res.reason ?? "");
                // If risk lookup was disabled and exit IP is unchanged, preserve existing risk metadata.
                const preserveRisk = !includeRisk && ok && !!ip && ip === node.lastIp && node.lastRiskScore != null;
                const city = res.city ?? (preserveRisk ? (node.lastCity ?? "") : "");
                const isp = res.isp ?? (preserveRisk ? (node.lastIsp ?? "") : "");
                const ipType = ((res.ipType ?? (preserveRisk ? (node.lastIpType ?? "") : "")) || "") as NonNullable<ProxyPoolNode["lastIpType"]>;
                const riskScore = typeof res.riskScore === "number" && Number.isFinite(res.riskScore)
                  ? Math.max(0, Math.min(100, Math.round(res.riskScore)))
                  : (preserveRisk ? (node.lastRiskScore ?? null) : null);
                const riskLevel = ((res.riskLevel ?? (preserveRisk ? (node.lastRiskLevel ?? "") : "")) || "") as NonNullable<ProxyPoolNode["lastRiskLevel"]>;
                const riskFlags = Array.isArray(res.riskFlags)
                  ? res.riskFlags
                  : (preserveRisk ? (node.lastRiskFlags ?? []) : []);
                const doneAt = Date.now();
                store.updateProxyNodeCheck(node.id, res.status, ip, country, latencyMs, doneAt, {
                  reason,
                  city,
                  isp,
                  ipType,
                  riskScore,
                  riskLevel,
                  riskFlags,
                });
                item = {
                  id: node.id,
                  status: res.status,
                  reason,
                  ip,
                  country,
                  city,
                  isp,
                  ipType,
                  riskScore,
                  riskLevel,
                  riskFlags,
                  latencyMs,
                  checkedAt: doneAt,
                };
              } catch {
                const doneAt = Date.now();
                store.updateProxyNodeCheck(node.id, "failed", "", "", null, doneAt, { reason: "connection_failed" });
                item = {
                  id: node.id,
                  status: "failed",
                  reason: "connection_failed",
                  ip: "",
                  country: "",
                  city: "",
                  isp: "",
                  ipType: "",
                  riskScore: null,
                  riskLevel: "",
                  riskFlags: [],
                  latencyMs: null,
                  checkedAt: doneAt,
                };
              }
            }
            results.push(item);
            completed++;
            onItem(item, completed, total);
          }
        };

        await Promise.all(Array.from({ length: Math.min(8, total) }, worker));
        return { results, completed, cancelled: isCancelled() && completed < total };
      };

      if (wantStream) {
        let clientGone = false;
        const isCancelled = () => clientGone || req.signal.aborted;
        const encoder = new TextEncoder();
        const stream = new ReadableStream<Uint8Array>({
          async start(controller) {
            const send = (event: ProxyPoolCheckStreamEvent) => {
              if (clientGone) return;
              try {
                controller.enqueue(encoder.encode(`${JSON.stringify(event)}\n`));
              } catch {
                clientGone = true;
              }
            };
            try {
              send({ type: "progress", completed: 0, total: targets.length });
              const out = await runBatch((item, completed, total) => {
                send({ type: "result", item });
                send({ type: "progress", completed, total });
              }, isCancelled);
              send({ type: "done", completed: out.completed, total: targets.length, cancelled: out.cancelled });
            } catch (error) {
              send({ type: "error", error: error instanceof Error ? error.message : String(error) });
            } finally {
              try { controller.close(); } catch {}
            }
          },
          cancel() {
            clientGone = true;
          },
        });
        return new Response(stream, {
          headers: {
            "Content-Type": "application/x-ndjson; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
          },
        });
      }

      const out = await runBatch(() => {}, () => req.signal.aborted);
      return noStoreJson({ ok: true, results: out.results });
    }

    // POST /ui/api/proxy-pool/assign  (assign selected pool nodes, optionally chained with preProxyNodeId, to profiles)
    if (pathname === "/ui/api/proxy-pool/assign" && req.method === "POST") {
      const body = (await req.json()) as {
        scope?: ProxyScope;
        nodeIds?: unknown;
        preProxyNodeId?: unknown;
        profilesPerNode?: unknown;
        skipFailed?: unknown;
      };
      const nodeIds = Array.isArray(body?.nodeIds) ? body.nodeIds.map(String).filter(Boolean) : [];
      if (!nodeIds.length) return noStoreJson({ ok: false, error: "Select at least one proxy node to assign" }, 400);
      const skipFailed = body?.skipFailed !== false;
      const foundNodes = nodeIds.map((id) => store.getProxyNode(id)).filter((n): n is ProxyPoolNode => !!n);
      if (!foundNodes.length) return noStoreJson({ ok: false, error: "None of the selected proxy nodes exist" }, 404);
      const nodes = skipFailed ? foundNodes.filter((n) => n.lastStatus !== "failed") : foundNodes;
      const skippedFailedNodes = foundNodes.length - nodes.length;
      if (!nodes.length) {
        return noStoreJson({ ok: false, error: "All selected proxy nodes are marked as failed" }, 400);
      }

      const preProxyNodeId = typeof body?.preProxyNodeId === "string" ? body.preProxyNodeId.trim() : "";
      const preProxySpec = preProxyNodeId === "__local_clash__"
        ? buildLocalClashProxySpec()
        : preProxyNodeId
          ? store.getProxyNode(preProxyNodeId)?.proxy ?? null
          : null;
      if (preProxyNodeId && !preProxySpec) {
        return noStoreJson({ ok: false, error: "Selected pre-proxy node was not found" }, 404);
      }

      const perNode = body?.profilesPerNode === undefined ? 1 : Number(body.profilesPerNode);
      if (!Number.isInteger(perNode) || perNode < 1) {
        return noStoreJson({ ok: false, error: "profilesPerNode must be a positive integer" }, 400);
      }

      const profiles = store.listProfiles();
      await Promise.all(profiles.map((p) => launcher.cacheCleanupSettled(p.id)));
      const inventory: ProxyInventoryProfile[] = profiles.map((p) => ({
        id: p.id,
        name: p.name,
        group: p.group,
        proxy: p.proxy,
        proxyError: p.proxyError,
        permission: "edit",
        running: launcher.profileDeletionBlocked(p.id),
      }));
      const selected = selectProxyProfiles(inventory, body?.scope ?? { all: true })
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

      let assigned = 0;
      let skipped = 0;
      let failed = 0;
      const results: Array<{ profileId: string; name: string; status: "updated" | "skipped" | "failed"; proxy?: string; reason?: string }> = [];

      for (let i = 0; i < selected.length; i++) {
        const target = selected[i]!;
        const nodeIndex = Math.floor(i / perNode);
        if (nodeIndex >= nodes.length) {
          skipped++;
          results.push({ profileId: target.id, name: target.name, status: "skipped", reason: "no_node_left" });
          continue;
        }
        if (target.running) {
          skipped++;
          results.push({ profileId: target.id, name: target.name, status: "skipped", reason: "profile_open" });
          continue;
        }
        const landingNode = nodes[nodeIndex]!;
        try {
          const nextProxy = preProxySpec && preProxyNodeId !== landingNode.id
            ? normalizeProxySpec({ ...landingNode.proxy, preProxy: preProxySpec })!
            : landingNode.proxy;
          const stored = store.getProfile(target.id);
          if (!stored) {
            skipped++;
            results.push({ profileId: target.id, name: target.name, status: "skipped", reason: "profile_missing" });
            continue;
          }
          const changed = { ...stored, proxy: nextProxy, timezone: stored.timezoneManual ? stored.timezone : "" };
          if (!stored.timezoneManual) {
            await attachTimezones([changed], deps.timezoneFetch ?? options.timezoneFetch, true).catch(() => {});
          }
          stored.proxy = nextProxy;
          delete stored.proxyError;
          if (!stored.timezoneManual && changed.timezone) {
            stored.timezone = changed.timezone;
            if (changed.locale) stored.locale = changed.locale;
            syncFirefoxTimezone(stored);
          }
          store.upsertProfile(stored);
          assigned++;
          results.push({ profileId: target.id, name: target.name, status: "updated", proxy: proxyDisplaySummary(nextProxy) });
        } catch (error) {
          failed++;
          results.push({
            profileId: target.id,
            name: target.name,
            status: "failed",
            reason: error instanceof Error ? error.message : String(error),
          });
        }
      }

      return noStoreJson({ ok: true, assigned, skipped, failed, skippedFailedNodes, results });
    }

    return noStoreJson({ ok: false, error: "Unknown proxy pool operation" }, 404);
  } catch (error) {
    const status = error instanceof SyntaxError ? 400 : 400;
    return noStoreJson({ ok: false, error: error instanceof Error ? error.message : String(error) }, status);
  }
}
