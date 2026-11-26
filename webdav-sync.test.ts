import { describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ProfileStore } from "./store.ts";
import { buildNewProfile } from "./create.ts";
import { Launcher } from "./launcher.ts";
import {
  buildClashTunRuleList,
  buildClashTunRules,
  buildClashVergeScript,
  buildLocalClashProxySpec,
  normalizeLocalClashUrl,
  readLocalNetworkSettings,
  resolveRuntimeProxy,
  setLocalNetworkStateRoot,
  writeLocalNetworkSettings,
} from "./local-network.ts";
import {
  decryptSyncPayload,
  encryptSyncPayload,
  executeWebDavSync,
  previewWebDavSync,
  saveWebDavConfig,
  testWebDavConnection,
} from "./webdav-sync.ts";
import { normalizeProxySpec, proxyDisplaySummary } from "./proxy.ts";

/** In-memory RFC 4918 WebDAV fetch mock for deterministic E2EE sync testing. */
function createMockWebDavFetch(authUser = "u", authPass = "p") {
  const files = new Map<string, string>();
  const dirs = new Set<string>(["/dav"]);
  const expectedAuth = `Basic ${Buffer.from(`${authUser}:${authPass}`).toString("base64")}`;

  const fetchFn = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const headers = new Headers(init?.headers);
    if (headers.get("authorization") !== expectedAuth) {
      return new Response("Unauthorized", { status: 401 });
    }
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (method === "MKCOL") {
      if (dirs.has(path)) return new Response(null, { status: 405 });
      dirs.add(path);
      return new Response(null, { status: 201 });
    }
    if (method === "PROPFIND") {
      if (!dirs.has(path)) return new Response("Not Found", { status: 404 });
      return new Response("<multistatus/>", { status: 207 });
    }
    if (method === "GET") {
      const content = files.get(path);
      if (content === undefined) return new Response("Not Found", { status: 404 });
      return new Response(content, { status: 200 });
    }
    if (method === "PUT") {
      const text = typeof init?.body === "string" ? init.body : await new Response(init?.body).text();
      files.set(path, text);
      return new Response(null, { status: 201 });
    }
    if (method === "DELETE") {
      files.delete(path);
      return new Response(null, { status: 204 });
    }
    return new Response(null, { status: 405 });
  }) as typeof fetch;

  return { fetchFn, files, dirs };
}

describe("3-mode local network & Local Clash routing", () => {
  test("resolves local-clash proxy specs dynamically and formats summaries cleanly", () => {
    const root = mkdtempSync(join(tmpdir(), "aliasmode-net-"));
    try {
      const settingsPath = join(root, "network-settings.json");
      expect(normalizeLocalClashUrl("127.0.0.1:7890")).toBe("http://127.0.0.1:7890");
      expect(normalizeLocalClashUrl("socks5://127.0.0.1:10808")).toBe("socks5://127.0.0.1:10808");
      const saved = writeLocalNetworkSettings({ localClashUrl: "http://127.0.0.1:7897", routeNodesViaSingBox: true }, settingsPath);
      expect(readLocalNetworkSettings(settingsPath)).toEqual(saved);

      const clashSpec = normalizeProxySpec({ mode: "local-clash" })!;
      expect(clashSpec.mode).toBe("local-clash");
      expect(proxyDisplaySummary(clashSpec)).toBe("Local Clash (127.0.0.1:7897)");

      const resolved = resolveRuntimeProxy(clashSpec, { localClashUrl: "socks5://127.0.0.1:10808", routeNodesViaSingBox: true })!;
      expect(resolved.type).toBe("socks5");
      expect(resolved.host).toBe("127.0.0.1");
      expect(resolved.port).toBe("10808");
      expect(resolved.mode).toBe("local-clash");

      // Chained residential proxy with Local Clash pre-proxy resolves preProxy dynamically too.
      const chained = normalizeProxySpec({
        type: "socks5",
        host: "res.example.com",
        port: "1080",
        user: "u",
        pass: "p",
        preProxy: buildLocalClashProxySpec("http://127.0.0.1:7897"),
      })!;
      expect(proxyDisplaySummary(chained)).toBe("socks5://res.example.com:1080 via Local Clash");
      const resolvedChain = resolveRuntimeProxy(chained, { localClashUrl: "http://127.0.0.1:7890", routeNodesViaSingBox: true })!;
      expect(resolvedChain.preProxy?.port).toBe("7890");
      expect(resolvedChain.preProxy?.mode).toBe("local-clash");

      const rules = buildClashTunRules(root);
      expect(rules).toContain("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,");
      expect(rules).toContain(")),DIRECT");

      // Explicit stateRoot without browserRoot must derive `<stateRoot>\browser`, never process CWD
      const appDataRules = buildClashTunRuleList("C:\\Users\\Demo\\AppData\\Roaming\\com.aliasmode.desktop", {
        platform: "win32",
      });
      const singBoxInner = appDataRules[0]!.slice("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,".length, -")),DIRECT".length);
      expect(new RegExp(singBoxInner).test("C:\\Users\\Demo\\AppData\\Roaming\\com.aliasmode.desktop\\browser\\sing-box-1.14.4\\sing-box.exe")).toBe(true);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("generates Mihomo IN-TYPE,TUN rules without nested parentheses and valid Clash Verge String.raw JS script", () => {
    const winOpts = {
      platform: "win32" as const,
      browserRoot: "D:\\aliasmode\\browser",
      runtimesRoot: "D:\\aliasmode\\runtimes",
    };
    const ruleList = buildClashTunRuleList("D:\\aliasmode", winOpts);
    expect(ruleList).toHaveLength(3);

    const extractedRegexes: RegExp[] = [];
    for (const rule of ruleList) {
      expect(rule.startsWith("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,")).toBe(true);
      expect(rule.endsWith(")),DIRECT")).toBe(true);
      const inner = rule.slice("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,".length, -")),DIRECT".length);
      // Must contain zero nested parentheses (no (?i), no (chrome|firefox), etc.)
      expect(inner).not.toContain("(");
      expect(inner).not.toContain(")");
      expect(inner.startsWith("^[Dd]:\\\\")).toBe(true);
      extractedRegexes.push(new RegExp(inner));
    }

    // Verify drive-letter case-insensitivity and exact executable matching
    expect(extractedRegexes[0]!.test("D:\\aliasmode\\browser\\sing-box-1.14.4\\sing-box.exe")).toBe(true);
    expect(extractedRegexes[0]!.test("d:\\aliasmode\\browser\\sing-box-1.14.4\\sing-box.exe")).toBe(true);
    expect(extractedRegexes[0]!.test("C:\\other\\sing-box.exe")).toBe(false);

    expect(extractedRegexes[1]!.test("D:\\aliasmode\\runtimes\\chromium-155\\chrome.exe")).toBe(true);
    expect(extractedRegexes[1]!.test("d:\\aliasmode\\runtimes\\cloakbrowser\\chrome.exe")).toBe(true);
    expect(extractedRegexes[1]!.test("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")).toBe(false);

    expect(extractedRegexes[2]!.test("D:\\aliasmode\\runtimes\\firefox-138\\firefox.exe")).toBe(true);
    expect(extractedRegexes[2]!.test("d:\\aliasmode\\runtimes\\camoufox\\firefox.exe")).toBe(true);
    expect(extractedRegexes[2]!.test("D:\\aliasmode\\runtimes\\chromium-155\\chrome.exe")).toBe(false);

    // Paths containing literal parentheses must escape them as \x28 / \x29 without emitting nested parens
    const parenRules = buildClashTunRuleList("C:\\Program Files (x86)\\AliasMode", {
      platform: "win32",
      browserRoot: "C:\\Program Files (x86)\\AliasMode\\browser",
      runtimesRoot: "C:\\Program Files (x86)\\AliasMode\\runtimes",
    });
    for (const rule of parenRules) {
      const inner = rule.slice("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,".length, -")),DIRECT".length);
      expect(inner).not.toContain("(");
      expect(inner).not.toContain(")");
      expect(inner).toContain("\\x28x86\\x29");
    }
    const parenChromeInner = parenRules[1]!.slice("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,".length, -")),DIRECT".length);
    expect(new RegExp(parenChromeInner).test("c:\\Program Files (x86)\\AliasMode\\runtimes\\chromium\\chrome.exe")).toBe(true);

    // YAML output includes all 3 wrapped rules and no (?i) or (chrome|firefox)
    const yaml = buildClashTunRules("D:\\aliasmode", winOpts);
    expect(yaml).not.toContain("(?i)");
    expect(yaml).not.toContain("(chrome|firefox)");
    for (const rule of ruleList) {
      expect(yaml).toContain(`- ${rule}`);
    }

    // Clash Verge JS override script uses String.raw and preserves every backslash when evaluated!
    const js = buildClashVergeScript("D:\\aliasmode", winOpts);
    expect(js).toContain("String.raw`AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,");
    const runMain = new Function(`${js}\nreturn main;`) as () => (cfg: { rules?: string[] }) => { rules: string[] };
    const main = runMain();
    const out = main({ rules: ["MATCH,PROXY"] });
    expect(out.rules).toEqual([...ruleList, "MATCH,PROXY"]);
    // Running main() again must stay idempotent without duplicating rules
    const outAgain = main(out);
    expect(outAgain.rules).toEqual([...ruleList, "MATCH,PROXY"]);

    // POSIX rules also wrap with IN-TYPE,TUN and contain zero nested parens
    const posixRules = buildClashTunRuleList("/opt/aliasmode", {
      platform: "linux",
      browserRoot: "/opt/aliasmode/browser",
      runtimesRoot: "/opt/aliasmode/runtimes",
    });
    expect(posixRules).toHaveLength(4);
    for (const rule of posixRules) {
      const inner = rule.slice("AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,".length, -")),DIRECT".length);
      expect(inner).not.toContain("(");
      expect(inner).not.toContain(")");
      expect(new RegExp(inner)).toBeInstanceOf(RegExp);
    }
  });

  test("Direct mode passes --no-proxy-server to Chromium while Local Clash passes --proxy-server", () => {
    const store = new ProfileStore(":memory:");
    const launcher = new Launcher({ store, binaryPath: "/fake" });
    const directProfile = buildNewProfile({ name: "Direct", engine: "chromium", proxy: null }, () => false);
    const clashProfile = buildNewProfile({ name: "Clash", engine: "chromium", proxy: { mode: "local-clash" } }, () => false);

    const directArgs = launcher.buildArgs(directProfile, 9333, "/data", []);
    expect(directArgs).toContain("--no-proxy-server");
    expect(directArgs.some((a) => a.startsWith("--proxy-server="))).toBe(false);

    const clashArgs = launcher.buildArgs(clashProfile, 9334, "/data", []);
    expect(clashArgs).not.toContain("--no-proxy-server");
    expect(clashArgs.some((a) => a.startsWith("--proxy-server=http://127.0.0.1:"))).toBe(true);
    store.close();
  });
});

describe("Encrypted sharded WebDAV sync", () => {
  test("encrypts payloads with scrypt+AES-256-GCM and rejects wrong passphrases", () => {
    const cipher = encryptSyncPayload({ secret: "cookie-value-123" }, "my-strong-pass");
    expect(cipher).not.toContain("cookie-value-123");
    expect(decryptSyncPayload<{ secret: string }>(cipher, "my-strong-pass")).toEqual({ secret: "cookie-value-123" });
    expect(() => decryptSyncPayload(cipher, "wrong-pass")).toThrow("check your encryption passphrase");
  });

  test("syncs profiles, portable sessions, and proxy pool across two devices with conflict detection", async () => {
    const rootA = mkdtempSync(join(tmpdir(), "aliasmode-dav-a-"));
    const rootB = mkdtempSync(join(tmpdir(), "aliasmode-dav-b-"));
    const storeA = new ProfileStore(":memory:");
    const storeB = new ProfileStore(":memory:");
    const dav = createMockWebDavFetch("alice", "dav-pass");

    try {
      const cfgA = saveWebDavConfig(rootA, {
        url: "https://vps97.example.com/dav/aliasmode",
        username: "alice",
        password: "dav-pass",
        passphrase: "e2ee-secret-key",
        deviceName: "Home-2K",
        enabled: true,
      });
      const cfgB = saveWebDavConfig(rootB, {
        url: "https://vps97.example.com/dav/aliasmode",
        username: "alice",
        password: "dav-pass",
        passphrase: "e2ee-secret-key",
        deviceName: "Office-PC",
        enabled: true,
      });

      const probe0 = await testWebDavConnection(cfgA, { fetchFn: dav.fetchFn });
      expect(probe0.remoteInitialized).toBe(false);

      // Device A creates a profile (with sing-box proxy + portable session) and a subscription/node.
      const p1 = buildNewProfile({
        name: "Google-01",
        group: "US",
        proxy: { uri: "vless://11111111-1111-1111-1111-111111111111@edge.example.com:443?security=tls#US-Edge" },
      }, () => false);
      storeA.upsertProfile(p1);
      storeA.saveSessionBundle(p1.id, JSON.stringify({ cookies: [{ name: "SID", value: "tok123", domain: ".google.com", path: "/" }] }));
      storeA.upsertProxySubscription({
        id: "sub1",
        name: "Airport",
        url: "https://sub.example.com/list",
        nodeCount: 1,
        lastUpdatedAt: 1000,
        lastError: "",
        createdAt: 1000,
      });
      storeA.upsertProxyNode({
        id: "node1",
        name: "US-Edge",
        subscriptionId: "sub1",
        proxy: p1.proxy!,
        tags: ["us"],
        lastStatus: "working",
        lastIp: "1.2.3.4",
        lastCountry: "US",
        lastLatencyMs: 80,
        lastCheckedAt: 1000,
        createdAt: 1000,
      });

      // Push from Device A
      const syncA1 = await executeWebDavSync(rootA, storeA, { mode: "merge" }, { fetchFn: dav.fetchFn, now: () => 10_000 });
      expect(syncA1.pushed).toBe(1);
      expect(syncA1.proxyPoolAction).toBe("pushed");

      // Stored files on WebDAV must be ciphertext (no plaintext cookies or hostnames).
      const allRemoteText = [...dav.files.values()].join("\n");
      expect(allRemoteText).not.toContain("tok123");
      expect(allRemoteText).not.toContain("Google-01");
      expect(allRemoteText).not.toContain("edge.example.com");

      // Device B checks connection, previews, and pulls.
      const probeB = await testWebDavConnection(cfgB, { fetchFn: dav.fetchFn });
      expect(probeB.remoteInitialized).toBe(true);
      expect(probeB.profileCount).toBe(1);

      const previewB = await previewWebDavSync(rootB, storeB, { fetchFn: dav.fetchFn });
      expect(previewB.summary.pull).toBe(2); // 1 profile + proxy pool

      const syncB1 = await executeWebDavSync(rootB, storeB, { mode: "merge" }, { fetchFn: dav.fetchFn, now: () => 20_000 });
      expect(syncB1.pulled).toBe(1);
      expect(syncB1.proxyPoolAction).toBe("pulled");

      // Verify Device B restored profile, pending session bundle, and proxy pool.
      const restored = storeB.getProfile(p1.id)!;
      expect(restored.name).toBe("Google-01");
      expect(restored.proxy?.type).toBe("vless");
      expect(storeB.getPendingSessionBundle(p1.id)).toContain("tok123");
      expect(storeB.listProxyNodes()).toHaveLength(1);

      // Simulate true conflict: both Device A and Device B edit the same profile independently.
      storeA.upsertProfile({ ...storeA.getProfile(p1.id)!, name: "Google-01-Home" });
      await executeWebDavSync(rootA, storeA, { mode: "merge" }, { fetchFn: dav.fetchFn, now: () => 30_000 });
      storeB.upsertProfile({ ...storeB.getProfile(p1.id)!, name: "Google-01-Office" });

      const conflictPreview = await previewWebDavSync(rootB, storeB, { fetchFn: dav.fetchFn });
      expect(conflictPreview.summary.conflicts).toBe(1);
      expect(conflictPreview.profiles[0]?.action).toBe("conflict");

      // Resolving conflict in favor of remote updates Device B cleanly.
      const resolvedSync = await executeWebDavSync(rootB, storeB, {
        mode: "merge",
        resolutions: { [p1.id]: "remote" },
      }, { fetchFn: dav.fetchFn, now: () => 40_000 });
      expect(resolvedSync.pulled).toBe(1);
      expect(resolvedSync.unresolvedConflicts).toEqual([]);
      expect(storeB.getProfile(p1.id)!.name).toBe("Google-01-Home");
    } finally {
      storeA.close();
      storeB.close();
      rmSync(rootA, { recursive: true, force: true });
      rmSync(rootB, { recursive: true, force: true });
    }
  });
});
