import { expect, test } from "bun:test";
import { parsePastedProxy } from "./proxy-input.ts";

test("proxy paste splits host:port:username:password and preserves password colons", () => {
  expect(parsePastedProxy("1.2.3.4:1080:user:pa:ss", "socks5")).toEqual({
    type: "socks5",
    host: "1.2.3.4",
    port: "1080",
    user: "user",
    pass: "pa:ss",
  });
});

test("an explicit proxy URL selects its type and decodes credentials", () => {
  expect(parsePastedProxy("socks5://user:p%40ss@proxy.example:1080", "http")).toEqual({
    type: "socks5",
    host: "proxy.example",
    port: "1080",
    user: "user",
    pass: "p@ss",
  });
});

test("proxy paste supports bracketed IPv6 and rejects malformed input", () => {
  expect(parsePastedProxy("[2001:db8::1]:1080:user:pass", "socks5")).toMatchObject({
    host: "2001:db8::1",
    port: "1080",
  });
  expect(parsePastedProxy("2a01:4f8::2:1080:user:pass", "http")).toMatchObject({
    host: "2a01:4f8::2",
    port: "1080",
    user: "user",
    pass: "pass",
  });
  expect(parsePastedProxy("2001:db8::1:2:1080", "http")).toMatchObject({ host: "2001:db8::1:2", port: "1080" });
  expect(() => parsePastedProxy("not-a-proxy", "http")).toThrow("host:port");
  expect(() => parsePastedProxy("proxy.example:not-a-port:user:pass", "http")).toThrow("invalid proxy port");
  expect(() => parsePastedProxy("https://u:p@proxy.example:8443", "http")).toThrow("unsupported proxy type");
});

test("proxy paste parses sing-box share URIs (vless, vmess, trojan, ss, hy2, tuic, wg)", () => {
  const vless = parsePastedProxy("vless://11111111-1111-4111-8111-111111111111@node.example:443?security=reality&pbk=abc#US-1");
  expect(vless).toMatchObject({ type: "vless", host: "node.example", port: "443", label: "US-1" });
  expect(vless.uri).toContain("vless://");

  const hy2 = parsePastedProxy("hy2://pw@hy.example:8443?sni=hy.example#JP");
  expect(hy2).toMatchObject({ type: "hysteria2", host: "hy.example", port: "8443", label: "JP" });

  const vmessPayload = Buffer.from(JSON.stringify({ v: "2", ps: "SG", add: "sg.example", port: 443, id: "uuid" })).toString("base64");
  expect(parsePastedProxy(`vmess://${vmessPayload}`)).toMatchObject({ type: "vmess", host: "sg.example", port: "443", label: "SG" });

  const ss = parsePastedProxy(`ss://${Buffer.from("aes-256-gcm:secret").toString("base64")}@ss.example:8388#HK`);
  expect(ss).toMatchObject({ type: "ss", host: "ss.example", port: "8388", label: "HK" });
});
