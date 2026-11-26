# AliasMode（增强二开版）

> **二开声明**：本项目基于开源指纹浏览器项目 [aliasmode/aliasmode](https://github.com/aliasmode/aliasmode)（`v0.1.0-beta.75`，Apache-2.0 协议）进行二次开发。完整保留上游的多引擎指纹浏览器（AliasMode Chromium / AliasMode Firefox / CloakBrowser）、Playwright 脚本自动化、Local API（兼容 AdsPower）与 MCP 能力，并围绕**自托管同步**与**多协议代理池**做了系统性增强。

[![GitHub Releases](https://img.shields.io/github/v/release/Kkverse404/aliasmode?label=Release)](https://github.com/Kkverse404/aliasmode/releases)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

---

## 本二开版主要新增功能

### 1. sing-box 代理池与机场订阅管理
- **多协议原生支持**：内置 `sing-box` 运行时管理（首次使用自动下载或界面一键安装），支持 **VLESS**（Reality / WS / gRPC / HTTPUpgrade）、**VMess**、**Trojan**、**Shadowsocks**、**Hysteria 2**、**TUIC**、**WireGuard** 以及传统 **HTTP / HTTPS / SOCKS5** 代理。
- **多种导入与订阅方式**：支持直接粘贴单条/批量分享链接、Base64 订阅、Clash / Mihomo YAML（兼容 `wireguard` 与小写 `ws-opts.headers.host`）和 sing-box JSON；支持添加/刷新远程订阅链接（可选「经由本地 Clash 拉取订阅」），刷新时按节点身份自动保留既有测活数据与节点 ID，不丢失前置代理绑定。
- **高效流式批量测活与管理**：
  - 单节点仅启动 1 个 `sing-box` 进程复用完成测速与出口 IP 探测，流式实时回传进度条、支持随时取消并记录具体失败原因（超时 / 认证失败 / DNS 失败 / 不可达等）。
  - 支持跨页全选筛选结果、一键删除失效节点、复制节点链接、批量分配到文件夹（自动跳过失效节点）；环境创建/编辑时的节点选择器按「可用 + 低风险 + 低延迟」智能排序并展示国家、延迟与风险分。
- **TUN 环境 DNS 抗死锁**：`sing-box` 内置纯 IP DoH 解析（AliDNS `223.5.5.5` / DNSPod `1.12.12.12`，`prefer_ipv4`），解决 Clash TUN 虚拟 DNS（`198.18.0.2`）或局域网禁用 UDP/53 导致的域名解析超时问题。

### 2. 真实延迟测速 & 出口 IP 风险评估
- **真实 RTT 延迟测速**：将延迟测试与出口 IP 查询解耦，优先通过全球 Anycast HTTP 204 端点（`gstatic.com` / `cp.cloudflare.com`）测量真实往返延迟，避免跨洋接口或 429 限流导致延迟虚高。
- **出口 IP 风险画像与多列排序**：查询出口 IP、国家/地区、城市、ISP、IP 类型（住宅 / 机房 / 代理 / VPN / Tor）及风险评分，内置并发请求合并去重与 30 分钟缓存；节点池批量测活支持按需开关「同时检测 IP 风险」，并支持按状态、国家、延迟、风险分、协议等字段排序筛选。

### 3. 三模式网络路由与 Clash / Mihomo TUN 放行规则
- **每环境独立三模式路由**：
  1. **本地直连**：绕过系统代理与 Clash TUN，直出本机网络。
  2. **本地 Clash**：走本机代理端口（如 `127.0.0.1:7897`），支持一键自动探测常见 Clash / v2rayN 本地端口。
  3. **代理节点**：为环境绑定独立节点或链式前置代理（支持「本地 Clash → 落地节点」或「节点 → 节点」），通过独立 `sing-box` 进程出网，不与系统代理冲突。
- **Clash / Mihomo TUN 放行规则生成器**：根据当前安装路径自动生成基于 `AND,((IN-TYPE,TUN),(PROCESS-PATH-REGEX,...)),DIRECT` 的精准规则（只放行 TUN 流量，不误杀 `127.0.0.1` 本地 Clash 流量），同时提供 **Clash YAML 规则** 与 **Clash Verge JS 覆写脚本（`String.raw`）** 两种一键复制格式。

### 4. 端到端加密（E2EE）WebDAV 手动同步
- **取代官方云登录**：首次启动桌面端直接进入本地模式，无需注册或连接官方 AliasMode Cloud。
- **客户端 AES-256-GCM 加密**：使用自定义同步口令在本地加密后再上传至你自己的 WebDAV 服务器（NAS / VPS / 支持 WebDAV 的网盘），服务端仅存储密文。
- **可控的手动同步工作流**：
  - 同步范围涵盖浏览器环境配置、分组、标签、便携登录会话（Cookies & localStorage，上传前自动采集已打开浏览器的最新会话，拉取时自动跳过运行中环境防止覆盖）以及代理池与订阅。
  - 支持**检查差异**、**智能双向同步**、**全量上传（本地 → WebDAV）**、**全量下载（WebDAV → 本地）**及逐条冲突裁决（保留本地 / 使用远端 / 跳过）。
  - 设置页内置 VPS 一键部署 WebDAV 服务端参考命令（Docker / Caddy）。

---

## 下载与安装

请前往本仓库 [**Releases 页面**](https://github.com/Kkverse404/aliasmode/releases) 下载对应平台的最新安装包：

| 平台 | 推荐安装包 | 说明 |
| --- | --- | --- |
| **Windows x64（推荐）** | `AliasMode_<ver>_x64-setup.exe` | 在线精简安装包（复用系统自带 WebView2） |
| **Windows x64（离线版）** | `AliasMode_<ver>_x64-offline-setup.exe` | 内置 Microsoft Edge WebView2 离线组件 |
| **macOS Apple Silicon (M1–M4)** | `AliasMode_<ver>_aarch64.dmg` / `.app.tar.gz` | 原生 `arm64` 版本 |
| **macOS Intel (x64)** | `AliasMode_<ver>_x64.dmg` / `.app.tar.gz` | 适用于 Intel 芯片 Mac |
| **Linux x86_64** | `AliasMode_<ver>_amd64.deb` / `_x86_64-linux.tar.gz` | Debian / Ubuntu 推荐 `.deb`，其他发行版可用 `.tar.gz` |

macOS / Linux 也支持终端一键安装（自动校验 SHA-256 并拉取本仓库最新版）：

```sh
# macOS (Apple Silicon / Intel)
curl -fsSL https://raw.githubusercontent.com/Kkverse404/aliasmode/main/scripts/install-macos.sh | bash

# Linux x86_64
curl -fsSL https://raw.githubusercontent.com/Kkverse404/aliasmode/main/scripts/install-linux.sh | bash
```

> **使用提示**
> - **macOS 首次打开**：由于未经过 Apple 商业公证，如系统提示「已损坏」或无法验证开发者，请在终端执行 `xattr -dr com.apple.quarantine /Applications/AliasMode.app`，或在 **系统设置 → 隐私与安全性** 中点击「仍要打开」。
> - **Clash TUN 模式**：若同时开启 Clash Verge / Mihomo TUN，建议在应用内 **「设置 → WebDAV 同步与网络」** 复制生成的 TUN 放行规则并应用，确保「本地直连」「代理节点」与「本地 Clash」三种模式均可正常工作。
> - **sing-box 核心**：首次对代理池节点测活或启动节点环境时会自动下载匹配当前系统的 `sing-box` 二进制，也可在 **「代理 → 节点池与订阅」** 中手动点击安装。

---

## 保留的原项目核心能力

本二开版完整保留了上游 AliasMode 的原有基础功能：
- **多浏览器内核**：支持 [AliasMode Chromium](https://github.com/aliasmode/aliasmode-chromium)、[AliasMode Firefox](https://github.com/aliasmode/aliasmode-firefox)（基于 Camoufox 的 C++ 指纹隔离内核）及 CloakBrowser，首次使用时自动下载并校验 SHA-256。
- **环境与指纹管理**：分组、标签、自定义编号、Cookies 导入、2FA（TOTP）、回收站恢复以及批量导入（AdsPower / GoLogin / Multilogin / Dolphin Anty / HideMyAcc 等）。
- **自动化与 AI Agent 集成**：
  - 内置 JavaScript / Python Playwright 脚本批量执行能力。
  - 兼容 AdsPower 的本地循环接口 Local API（仅监听 `127.0.0.1`）。
  - 内置本地 stdio MCP 服务（`aliasmode-mcp`），支持对接 Claude Code、Codex 等 AI Agent 自动操作浏览器。

---

## 本地开发与构建

环境依赖：[Bun](https://bun.sh/)、Node.js（推荐 22.23.2），桌面端打包另需 Rust 工具链与对应平台 Tauri 依赖。

```sh
# 安装依赖
bun install

# 运行测试与类型检查
bun test
bun run typecheck
bun run i18n:locales:check

# 源码模式启动本地服务与 Web 控制台（默认 http://127.0.0.1:50400）
bun cli.ts start
```

### 桌面端本地打包

```sh
# Windows x64（需 MSVC Build Tools）
bun run desktop:prepare
bun run desktop:build:nsis

# macOS（支持 ALIASMODE_MACOS_ARCH=arm64|x64）
bun run desktop:build:macos

# Linux x86_64（需 libwebkit2gtk-4.1-dev 等 GTK 开发库）
bun run desktop:build:linux
```

本仓库同时配置了全平台自动打包工作流 [`.github/workflows/release-all.yml`](.github/workflows/release-all.yml)，推送 `v*` 标签或手动触发 workflow 即可自动构建 Windows（在线/离线）、macOS（Apple Silicon / Intel）和 Linux（`.deb` / `.tar.gz`）全部版本并发布至 GitHub Release。

---

## 上游项目与开源协议

- 上游主项目：[aliasmode/aliasmode](https://github.com/aliasmode/aliasmode)（由 [Xreacher](https://xreacher.com/) 团队构建维护）
- 开源浏览器内核：[aliasmode/aliasmode-firefox](https://github.com/aliasmode/aliasmode-firefox)（MPL-2.0）、[aliasmode/aliasmode-chromium](https://github.com/aliasmode/aliasmode-chromium)
- 本仓库继续遵循 **[Apache-2.0](LICENSE)** 开源协议发布。
