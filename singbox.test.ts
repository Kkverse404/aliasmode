import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseProxySpec, normalizeProxySpec, isSingBoxProxy, proxyDisplaySummary, proxyIdentityKey } from "./proxy.ts";
import { parseSingBoxUri } from "./singbox-uri.ts";
import { buildSingBoxConfig, flattenProxyChain } from "./singbox-config.ts";
import { parseSubscriptionContent, parseSubscriptionUserInfo } from "./proxy-subscription.ts";
import { cleanupTempDirAfterExit, startSingBoxRelay } from "./singbox-runtime.ts";

const SAMPLES = {
  vlessReality: "vless://11111111-1111-4111-8111-111111111111@node.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=4r6e9gT4n1p8mK3yX2wV7qL5jH0cF6bD8aZ9sE1uR2M&sid=01ab&flow=xtls-rprx-vision#US%20Reality",
  vlessWsTls: "vless://11111111-1111-4111-8111-111111111111@ws.example.com:443?encryption=none&security=tls&sni=cdn.example.com&type=ws&path=%2Fws&host=cdn.example.com#US-WS",
  vmessWs: "vmess://" + Buffer.from(JSON.stringify({
    v: "2",
    ps: "JP-VMess",
    add: "jp.example.com",
    port: 443,
    id: "11111111-1111-4111-8111-111111111111",
    aid: 0,
    scy: "auto",
    net: "ws",
    host: "jp.example.com",
    path: "/v",
    tls: "tls",
    sni: "jp.example.com",
  })).toString("base64"),
  trojanGrpc: "trojan://secretpass@tr.example.com:443?security=tls&sni=tr.example.com&type=grpc&serviceName=gun#SG-Trojan",
  ss2022: `ss://${Buffer.from("2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==").toString("base64")}@ss.example.com:8388#HK-SS`,
  hysteria2: "hy2://mypass@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#US-HY2",
  tuic: "tuic://11111111-1111-4111-8111-111111111111:mypass@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr&alpn=h3#EU-TUIC",
  wireguard: "wg://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=@198.51.100.1:51820?publickey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=&address=10.0.0.2/32&mtu=1280#WG-Node",
};

describe("sing-box URI parsing & ProxySpec normalization", () => {
  test("parses all supported sing-box share URI schemes", () => {
    const vless = parseSingBoxUri(SAMPLES.vlessReality);
    expect(vless.type).toBe("vless");
    expect(vless.host).toBe("node.example.com");
    expect(vless.port).toBe(443);
    expect(vless.label).toBe("US Reality");
    if (vless.type === "vless") {
      expect(vless.tls?.reality?.publicKey).toBe("4r6e9gT4n1p8mK3yX2wV7qL5jH0cF6bD8aZ9sE1uR2M");
    }

    const vmess = parseSingBoxUri(SAMPLES.vmessWs);
    expect(vmess.type).toBe("vmess");
    expect(vmess.label).toBe("JP-VMess");
    if (vmess.type === "vmess") {
      expect(vmess.transport?.type).toBe("ws");
    }

    const hy2 = parseSingBoxUri(SAMPLES.hysteria2);
    expect(hy2.type).toBe("hysteria2");
    if (hy2.type === "hysteria2") {
      expect(hy2.obfs?.type).toBe("salamander");
    }

    const wg = parseSingBoxUri(SAMPLES.wireguard);
    expect(wg.type).toBe("wireguard");
    if (wg.type === "wireguard") {
      expect(wg.localAddresses).toEqual(["10.0.0.2/32"]);
    }
  });

  test("normalizes sing-box specs and preProxy chains without leaking secrets in display summary", () => {
    const transit = parseProxySpec("vless", SAMPLES.vlessReality)!;
    expect(isSingBoxProxy(transit)).toBe(true);
    expect(proxyDisplaySummary(transit)).toBe("vless://node.example.com:443");

    const chained = normalizeProxySpec({
      type: "socks5",
      host: "203.0.113.10",
      port: "1080",
      user: "res_user",
      pass: "res_secret",
      preProxy: transit,
    })!;
    expect(isSingBoxProxy(chained)).toBe(true);
    expect(flattenProxyChain(chained)).toHaveLength(2);
    expect(proxyDisplaySummary(chained)).toBe("socks5://203.0.113.10:1080 via vless://node.example.com:443");
    expect(proxyDisplaySummary(chained)).not.toContain("res_secret");
    expect(proxyDisplaySummary(chained)).not.toContain("11111111");

    const unchained = normalizeProxySpec({
      type: "socks5",
      host: "203.0.113.10",
      port: "1080",
      user: "res_user",
      pass: "res_secret",
    })!;
    expect(proxyIdentityKey(chained)).not.toBe(proxyIdentityKey(unchained));
  });
});

describe("subscription parsing", () => {
  test("parses Base64 V2Ray subscription body and userinfo header", () => {
    const rawLines = [SAMPLES.vlessReality, SAMPLES.trojanGrpc, SAMPLES.hysteria2].join("\n");
    const base64 = Buffer.from(rawLines, "utf8").toString("base64");
    const parsed = parseSubscriptionContent(base64);
    expect(parsed.format).toBe("base64");
    expect(parsed.nodes).toHaveLength(3);
    expect(parsed.nodes.map((n) => n.proxy.type)).toEqual(["vless", "trojan", "hysteria2"]);

    const info = parseSubscriptionUserInfo("upload=1024; download=2048; total=10737418240; expire=1900000000");
    expect(info).toEqual({ upload: 1024, download: 2048, total: 10737418240, expire: 1900000000 });
  });

  test("parses Clash YAML (both inline flow and block styles)", () => {
    const yaml = `
port: 7890
proxies:
  - { name: "US-Inline-SS", type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: secret }
  - name: JP-Block-VLESS
    type: vless
    server: jp.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    servername: jp.example.com
    network: ws
    ws-opts:
      path: /chat
      headers:
        Host: jp.example.com
  - name: SG-HY2
    type: hysteria2
    server: sg.example.com
    port: 8443
    password: hy2password
    sni: sg.example.com
    skip-cert-verify: true
proxy-groups:
  - name: PROXY
`;
    const parsed = parseSubscriptionContent(yaml);
    expect(parsed.format).toBe("clash-yaml");
    expect(parsed.nodes).toHaveLength(3);
    expect(parsed.nodes[0]!.name).toBe("US-Inline-SS");
    expect(parsed.nodes[1]!.proxy.type).toBe("vless");
    expect(parsed.nodes[2]!.proxy.type).toBe("hysteria2");
  });

  test("parses Clash YAML lowercase ws-opts.headers.host (VLESS/Trojan) and wireguard nodes", () => {
    const yaml = `
proxies:
  - name: VLESS-LowerHost
    type: vless
    server: v.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    tls: true
    network: ws
    ws-opts:
      path: /ws-v
      headers:
        host: cdn-v.example.com
  - name: Trojan-LowerHost
    type: trojan
    server: t.example.com
    port: 443
    password: secret
    network: ws
    ws-opts:
      path: /ws-t
      headers:
        host: cdn-t.example.com
  - name: WG-Home
    type: wireguard
    server: wg.example.com
    port: 51820
    ip: 10.7.0.2/32
    ipv6: fd00::2/128
    private-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
    public-key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
    pre-shared-key: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=
    reserved: [1, 2, 3]
    mtu: 1280
`;
    const parsed = parseSubscriptionContent(yaml);
    expect(parsed.format).toBe("clash-yaml");
    expect(parsed.nodes).toHaveLength(3);
    expect(parsed.nodes[0]!.proxy.uri).toContain("host=cdn-v.example.com");
    expect(parsed.nodes[1]!.proxy.uri).toContain("host=cdn-t.example.com");
    const wgNode = parsed.nodes[2]!;
    expect(wgNode.proxy.type).toBe("wireguard");
    const parsedWg = parseSingBoxUri(wgNode.proxy.uri!);
    expect(parsedWg.type).toBe("wireguard");
    if (parsedWg.type === "wireguard") {
      expect(parsedWg.localAddresses).toEqual(["10.7.0.2/32", "fd00::2/128"]);
      expect(parsedWg.reserved).toEqual([1, 2, 3]);
      expect(parsedWg.mtu).toBe(1280);
      expect(parsedWg.preSharedKey).toBe("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=");
    }
  });

  test("cleanupTempDirAfterExit waits for child exit before removing config dir", async () => {
    const dir = mkdtempSync(join(tmpdir(), "aliasmode-sb-cleanup-"));
    writeFileSync(join(dir, "config.json"), '{"secret":"ok"}');
    let resolveExit!: () => void;
    const exitPromise = new Promise<void>((r) => { resolveExit = r; });
    const cleanupPromise = cleanupTempDirAfterExit(dir, exitPromise, [10]);
    // Dir must still exist until child exits
    await Bun.sleep(15);
    expect(existsSync(dir)).toBe(true);
    resolveExit();
    expect(await cleanupPromise).toBe(true);
    expect(existsSync(dir)).toBe(false);
  });

  test("parses sing-box JSON outbounds", () => {
    const json = JSON.stringify({
      outbounds: [
        { type: "direct", tag: "direct" },
        { type: "trojan", tag: "EU-Trojan", server: "eu.example.com", server_port: 443, password: "pw", tls: { enabled: true, server_name: "eu.example.com" } },
      ],
    });
    const parsed = parseSubscriptionContent(json);
    expect(parsed.format).toBe("singbox-json");
    expect(parsed.nodes).toHaveLength(1);
    expect(parsed.nodes[0]!.name).toBe("EU-Trojan");
    expect(parsed.nodes[0]!.proxy.type).toBe("trojan");
  });
});

describe("sing-box binary validation & real sidecar relay", () => {
  const singboxPath = process.env.ALIASMODE_SINGBOX_PATH;

  test("generated configs pass `sing-box check` for all protocols and detour chains", () => {
    if (!singboxPath || !existsSync(singboxPath)) return;
    for (const [name, uri] of Object.entries(SAMPLES)) {
      const spec = parseProxySpec("http", uri)!;
      const cfg = buildSingBoxConfig(spec, 23456);
      const file = join(tmpdir(), `aliasmode-sb-check-${name}-${Date.now()}.json`);
      writeFileSync(file, JSON.stringify(cfg, null, 2));
      try {
        const res = Bun.spawnSync([singboxPath, "check", "-c", file]);
        expect(res.exitCode, `${name}: ${res.stderr.toString()}`).toBe(0);
      } finally {
        rmSync(file, { force: true });
      }
    }

    const cfg = buildSingBoxConfig(parseProxySpec("vless", SAMPLES.vlessReality)!, 23456);
    expect(cfg.dns.servers[0]).toMatchObject({
      type: "https",
      tag: "doh-ali",
      server: "223.5.5.5",
      server_port: 443,
      path: "/dns-query",
    });
    expect(cfg.route.default_domain_resolver).toEqual({
      server: "doh-ali",
      strategy: "prefer_ipv4",
    });

    // Chain proxy: VLESS Reality transit -> Residential SOCKS5 landing
    const chain = normalizeProxySpec({
      type: "socks5",
      host: "203.0.113.10",
      port: "1080",
      user: "res_user",
      pass: "res_pass",
      preProxy: parseProxySpec("vless", SAMPLES.vlessReality)!,
    })!;
    const chainCfg = buildSingBoxConfig(chain, 23457);
    const chainFile = join(tmpdir(), `aliasmode-sb-check-chain-${Date.now()}.json`);
    writeFileSync(chainFile, JSON.stringify(chainCfg, null, 2));
    try {
      const res = Bun.spawnSync([singboxPath, "check", "-c", chainFile]);
      expect(res.exitCode, res.stderr.toString()).toBe(0);
    } finally {
      rmSync(chainFile, { force: true });
    }
  }, 20_000);

  test("starts a real sing-box relay and proxies HTTP traffic through a 2-hop chained CONNECT proxy", async () => {
    if (!singboxPath || !existsSync(singboxPath)) return;
    const net = await import("node:net");

    // Helper: minimal loopback HTTP CONNECT proxy that records every tunnel target it carried.
    const startConnectProxy = (name: string, seen: string[]) => new Promise<{ port: number; close(): void }>((resolve) => {
      const server = net.createServer((client) => {
        client.on("error", () => client.destroy());
        let buf = Buffer.alloc(0);
        const onData = (chunk: Buffer) => {
          buf = Buffer.concat([buf, chunk]);
          const end = buf.indexOf("\r\n\r\n");
          if (end < 0) return;
          client.off("data", onData);
          const head = buf.subarray(0, end).toString("latin1");
          const rest = buf.subarray(end + 4);
          const first = head.split("\r\n")[0] ?? "";
          const match = first.match(/^CONNECT\s+([^:\s]+):(\d+)\s+HTTP/i);
          if (!match) { client.destroy(); return; }
          seen.push(`${name}->${match[1]}:${match[2]}`);
          const target = net.connect({ host: match[1]!, port: Number(match[2]!) }, () => {
            client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            if (rest.length) target.write(rest);
            target.pipe(client);
            client.pipe(target);
          });
          target.on("error", () => client.destroy());
          client.on("close", () => target.destroy());
          target.on("close", () => client.destroy());
        };
        client.on("data", onData);
      });
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address() as AddressInfo;
        resolve({ port: addr.port, close: () => server.close() });
      });
    });

    const targetOrigin = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: () => Response.json({ ok: true, ip: "203.0.113.77" }),
    });
    const seen: string[] = [];
    const transit = await startConnectProxy("transit", seen);
    const landing = await startConnectProxy("landing", seen);
    const chainSpec = normalizeProxySpec({
      type: "http",
      host: "127.0.0.1",
      port: String(landing.port),
      user: "",
      pass: "",
      preProxy: {
        type: "http",
        host: "127.0.0.1",
        port: String(transit.port),
        user: "",
        pass: "",
      },
    })!;
    const relay = await startSingBoxRelay(chainSpec, { binaryPath: singboxPath });
    try {
      const res = await fetch(`http://127.0.0.1:${targetOrigin.port}/ip`, {
        proxy: `http://127.0.0.1:${relay.port}`,
      } as RequestInit);
      expect(await res.json()).toEqual({ ok: true, ip: "203.0.113.77" });
      // Verify traffic genuinely went Local -> sing-box -> transit -> landing -> origin!
      expect(seen).toContain(`transit->127.0.0.1:${landing.port}`);
      expect(seen).toContain(`landing->127.0.0.1:${targetOrigin.port}`);
    } finally {
      relay.close();
      landing.close();
      transit.close();
      targetOrigin.stop(true);
    }
  }, 15_000);
});
