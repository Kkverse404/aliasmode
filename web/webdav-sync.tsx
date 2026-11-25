import { useEffect, useState } from "react";
import {
  detectLocalClash,
  fetchLocalNetwork,
  fetchWebDavSync,
  previewWebDavSyncApi,
  runWebDavSyncApi,
  saveLocalNetwork,
  saveWebDavSync,
  testWebDavSync,
  type DetectedLocalProxyView,
  type LocalNetworkSettingsView,
  type SyncConflictChoiceView,
  type SyncItemActionView,
  type WebDavSyncModeView,
  type WebDavSyncPreviewView,
  type WebDavSyncPublicConfigView,
} from "./api.ts";
import { useTranslation } from "./i18n.tsx";

function actionLabel(t: (key: string) => string, action: SyncItemActionView): string {
  switch (action) {
    case "push_create": return t("Upload new");
    case "push_update": return t("Upload update");
    case "push_delete": return t("Remove remote");
    case "pull_create": return t("Download new");
    case "pull_update": return t("Download update");
    case "pull_delete": return t("Trash local");
    case "conflict": return t("Conflict");
    default: return t("Up to date");
  }
}

function actionTone(action: SyncItemActionView): string {
  if (action === "conflict") return "failed";
  if (action.startsWith("push_")) return "working";
  if (action.startsWith("pull_")) return "unstable";
  return "";
}

export function WebDavSyncPanel({
  profileCount,
  onSynced,
  onConfigChanged,
}: {
  profileCount: number;
  onSynced: () => Promise<void>;
  onConfigChanged?: (config: WebDavSyncPublicConfigView) => void;
}) {
  const { t } = useTranslation();
  const [config, setConfig] = useState<WebDavSyncPublicConfigView | null>(null);
  const [deployGuide, setDeployGuide] = useState("");
  const [url, setUrl] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [deviceName, setDeviceName] = useState("");
  const [busy, setBusy] = useState<"load" | "save" | "test" | "preview" | "sync" | "clear" | null>("load");
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [preview, setPreview] = useState<WebDavSyncPreviewView | null>(null);
  const [resolutions, setResolutions] = useState<Record<string, SyncConflictChoiceView>>({});
  const [poolResolution, setPoolResolution] = useState<SyncConflictChoiceView>("skip");
  const [guideCopied, setGuideCopied] = useState(false);

  const loadConfig = async () => {
    setBusy("load");
    setErr(null);
    try {
      const data = await fetchWebDavSync();
      setConfig(data.config);
      setDeployGuide(data.deployGuide);
      setUrl(data.config.url);
      setUsername(data.config.username);
      setDeviceName(data.config.deviceName);
      onConfigChanged?.(data.config);
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  useEffect(() => {
    void loadConfig();
  }, []);

  const handleSave = async () => {
    setBusy("save");
    setErr(null);
    setNotice(null);
    try {
      const data = await saveWebDavSync({
        url,
        username,
        ...(password ? { password } : {}),
        ...(passphrase ? { passphrase } : {}),
        deviceName,
        enabled: true,
      });
      setConfig(data.config);
      setPassword("");
      setPassphrase("");
      onConfigChanged?.(data.config);
      setNotice(t("WebDAV sync settings saved."));
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleTest = async () => {
    setBusy("test");
    setErr(null);
    setNotice(null);
    try {
      const result = await testWebDavSync({
        url,
        username,
        ...(password ? { password } : {}),
        ...(passphrase ? { passphrase } : {}),
        deviceName,
      });
      setNotice(result.remoteInitialized
        ? t("Connected to WebDAV · {count} profile(s) on server (last updated by {device})", {
          count: result.profileCount,
          device: result.remoteUpdatedBy || "—",
        })
        : t("Connected to WebDAV · remote folder is ready for your first upload."));
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleClear = async () => {
    if (!confirm(t("Disconnect WebDAV sync and remove saved WebDAV credentials from this computer?"))) return;
    setBusy("clear");
    setErr(null);
    setNotice(null);
    try {
      const data = await saveWebDavSync({ clearCredentials: true });
      setConfig(data.config);
      setUrl("");
      setUsername("");
      setPassword("");
      setPassphrase("");
      setPreview(null);
      setResolutions({});
      onConfigChanged?.(data.config);
      setNotice(t("WebDAV sync disconnected."));
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handlePreview = async () => {
    setBusy("preview");
    setErr(null);
    setNotice(null);
    try {
      const diff = await previewWebDavSyncApi(true);
      setPreview(diff);
      const nextRes: Record<string, SyncConflictChoiceView> = {};
      for (const item of diff.profiles) {
        if (item.action === "conflict") nextRes[item.id] = "skip";
      }
      setResolutions(nextRes);
      setPoolResolution("skip");
      setNotice(t("Checked differences: {push} to upload · {pull} to download · {conflicts} conflict(s)", {
        push: diff.summary.push,
        pull: diff.summary.pull,
        conflicts: diff.summary.conflicts,
      }));
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleSync = async (mode: WebDavSyncModeView) => {
    if (mode === "push" && !confirm(t("Upload all local profiles, sessions, and proxy pool changes to WebDAV (overwriting remote differences)?"))) return;
    if (mode === "pull" && !confirm(t("Pull all remote profiles, sessions, and proxy pool from WebDAV (overwriting local differences on closed profiles)?"))) return;
    setBusy("sync");
    setErr(null);
    setNotice(null);
    try {
      const result = await runWebDavSyncApi({
        mode,
        resolutions,
        proxyPoolResolution: poolResolution,
      });
      setConfig(result.config);
      onConfigChanged?.(result.config);
      setNotice(`${t("Sync complete")}: ${result.message}`);
      await onSynced();
      // Refresh diff after syncing so resolved items disappear cleanly.
      const nextDiff = await previewWebDavSyncApi(false).catch(() => null);
      if (nextDiff) setPreview(nextDiff);
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const changedProfiles = preview?.profiles.filter((item) => item.action !== "unchanged") ?? [];

  return (
    <>
      <div className="identity-card">
        <span className="identity-avatar">☁</span>
        <span className="identity-lines">
          <b>{config?.configured ? t("WebDAV sync connected") : t("Local workspace (WebDAV not configured)")}</b>
          <span>
            {config?.configured
              ? `${config.deviceName} · ${config.url}`
              : t("All profiles stay local until you connect your own WebDAV server (e.g. VPS / NAS).")}
          </span>
        </span>
        <span className="chip">{config?.configured ? t("WebDAV") : t("Local")}</span>
      </div>

      <section className="settings-card">
        <header><h2>{t("WebDAV sync configuration")}</h2></header>
        <div className="card-body">
          <p>{t("Sync profiles, portable login sessions (cookies & localStorage), and your sing-box proxy pool across devices with client-side AES-256-GCM encryption.")}</p>
          <div className="settings-row"><span>{t("Local profiles")}</span><strong>{profileCount}</strong></div>
          {config?.lastSyncAt ? (
            <div className="settings-row">
              <span>{t("Last sync")}</span>
              <strong>{new Date(config.lastSyncAt).toLocaleString()}{config.lastSyncMessage ? ` · ${config.lastSyncMessage}` : ""}</strong>
            </div>
          ) : null}

          <label className="fld">
            <span>{t("WebDAV server URL")}</span>
            <input
              value={url}
              placeholder="https://vps97.example.com/dav/aliasmode"
              onChange={(e) => setUrl(e.target.value)}
            />
            <small>{t("Supports HTTPS or private HTTP (Tailscale / LAN). Files are encrypted before upload.")}</small>
          </label>
          <div className="fld-row">
            <label className="fld grow">
              <span>{t("Username")}</span>
              <input value={username} placeholder="aliasmode" onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label className="fld grow">
              <span>{t("Password")}</span>
              <input
                type="password"
                value={password}
                placeholder={config?.hasPassword ? t("Saved · leave blank to keep") : t("WebDAV password")}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
          </div>
          <div className="fld-row">
            <label className="fld grow">
              <span>{t("Encryption passphrase (E2EE)")}</span>
              <input
                type="password"
                value={passphrase}
                placeholder={config?.hasPassphrase ? t("Saved · leave blank to keep") : t("Required · same passphrase on every device")}
                onChange={(e) => setPassphrase(e.target.value)}
              />
            </label>
            <label className="fld grow">
              <span>{t("Device name")}</span>
              <input value={deviceName} placeholder="Home-PC" onChange={(e) => setDeviceName(e.target.value)} />
            </label>
          </div>

          <div className="proxy-actions">
            <button type="button" className="btn primary" disabled={busy !== null || !url.trim()} onClick={() => void handleSave()}>
              {busy === "save" ? t("Saving…") : t("Save WebDAV settings")}
            </button>
            <button type="button" className="btn" disabled={busy !== null || !url.trim()} onClick={() => void handleTest()}>
              {busy === "test" ? t("Testing…") : t("Test connection")}
            </button>
            {config?.configured && (
              <button type="button" className="btn danger" disabled={busy !== null} onClick={() => void handleClear()}>
                {t("Disconnect")}
              </button>
            )}
          </div>

          {err && <div className="modal-err" role="alert">{err}</div>}
          {notice && <p className="hint" role="status">{notice}</p>}
        </div>
      </section>

      <section className="settings-card">
        <header><h2>{t("Manual sync")}</h2></header>
        <div className="card-body">
          <p>{t("Open browsers automatically capture their latest cookies before upload. Pulling skips currently open profiles so nothing is overwritten mid-session.")}</p>
          <div className="proxy-actions">
            <button type="button" className="btn" disabled={busy !== null || !config?.configured} onClick={() => void handlePreview()}>
              {busy === "preview" ? t("Checking…") : t("Check differences")}
            </button>
            <button type="button" className="btn primary" disabled={busy !== null || !config?.configured} onClick={() => void handleSync("merge")}>
              {busy === "sync" ? t("Syncing…") : t("Smart two-way sync")}
            </button>
            <button type="button" className="btn" disabled={busy !== null || !config?.configured} onClick={() => void handleSync("push")}>
              {t("Upload all (Local → WebDAV)")}
            </button>
            <button type="button" className="btn" disabled={busy !== null || !config?.configured} onClick={() => void handleSync("pull")}>
              {t("Download all (WebDAV → Local)")}
            </button>
          </div>

          {preview && (
            <div style={{ marginTop: 12 }}>
              <div className="settings-row">
                <span>{t("Proxy pool & subscriptions")}</span>
                <strong>
                  {t("Local {ls} subs / {ln} nodes · Remote {rs} subs / {rn} nodes", {
                    ls: preview.proxyPool.localSubscriptions,
                    ln: preview.proxyPool.localNodes,
                    rs: preview.proxyPool.remoteSubscriptions,
                    rn: preview.proxyPool.remoteNodes,
                  })}
                  {" · "}
                  {preview.proxyPool.action === "conflict" ? (
                    <select
                      className="select"
                      value={poolResolution}
                      onChange={(e) => setPoolResolution(e.target.value as SyncConflictChoiceView)}
                    >
                      <option value="skip">{t("Skip conflict")}</option>
                      <option value="local">{t("Keep local")}</option>
                      <option value="remote">{t("Use remote")}</option>
                    </select>
                  ) : (
                    <span>{preview.proxyPool.action}</span>
                  )}
                </strong>
              </div>

              {changedProfiles.length === 0 ? (
                <p className="hint">{t("All profiles are in sync with WebDAV.")}</p>
              ) : (
                <div className="proxy-table-wrap" style={{ marginTop: 8 }}>
                  <table className="profile-table proxy-table">
                    <thead>
                      <tr>
                        <th>{t("Profile")}</th>
                        <th>{t("Action")}</th>
                        <th>{t("Remote info")}</th>
                        <th>{t("Resolution")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {changedProfiles.map((item) => (
                        <tr key={item.id}>
                          <td>
                            <strong>{item.name}</strong>
                            <small> {item.id}{item.localOpen ? ` · ${t("Open")}` : ""}</small>
                          </td>
                          <td>
                            <span className={`tools-status ${actionTone(item.action)}`}>{actionLabel(t, item.action)}</span>
                          </td>
                          <td>
                            {item.remoteDevice
                              ? `${item.remoteDevice}${item.remoteUpdatedAt ? ` · ${new Date(item.remoteUpdatedAt).toLocaleString()}` : ""}`
                              : "—"}
                          </td>
                          <td>
                            {item.action === "conflict" ? (
                              <select
                                className="select"
                                value={resolutions[item.id] ?? "skip"}
                                onChange={(e) => setResolutions((prev) => ({
                                  ...prev,
                                  [item.id]: e.target.value as SyncConflictChoiceView,
                                }))}
                              >
                                <option value="skip">{t("Skip")}</option>
                                <option value="local">{t("Keep local")}</option>
                                <option value="remote">{t("Use remote")}</option>
                              </select>
                            ) : (
                              <span className="muted">{t("Automatic")}</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {deployGuide && (
            <details className="fingerprint-settings" style={{ marginTop: 12 }}>
              <summary><span>{t("VPS WebDAV quick deploy guide (Docker / Caddy)")}</span></summary>
              <div className="proxy-settings">
                <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12, margin: 0 }}>{deployGuide}</pre>
                <div className="proxy-actions">
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      void navigator.clipboard?.writeText(deployGuide);
                      setGuideCopied(true);
                      setTimeout(() => setGuideCopied(false), 1800);
                    }}
                  >
                    {guideCopied ? t("Copied") : t("Copy deploy commands")}
                  </button>
                </div>
              </div>
            </details>
          )}
        </div>
      </section>
    </>
  );
}

export function LocalNetworkPanel({
  onChanged,
}: {
  onChanged?: (settings: LocalNetworkSettingsView) => void;
}) {
  const { t } = useTranslation();
  const [localClashUrl, setLocalClashUrl] = useState("http://127.0.0.1:7897");
  const [routeNodesViaSingBox, setRouteNodesViaSingBox] = useState(true);
  const [clashTunRules, setClashTunRules] = useState("");
  const [clashVergeScript, setClashVergeScript] = useState("");
  const [ruleFormat, setRuleFormat] = useState<"yaml" | "verge-js">("yaml");
  const [detected, setDetected] = useState<DetectedLocalProxyView[]>([]);
  const [busy, setBusy] = useState<"load" | "save" | "detect" | null>("load");
  const [err, setErr] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [copiedFormat, setCopiedFormat] = useState<"yaml" | "verge-js" | null>(null);

  useEffect(() => {
    fetchLocalNetwork()
      .then((res) => {
        setLocalClashUrl(res.settings.localClashUrl);
        setRouteNodesViaSingBox(res.settings.routeNodesViaSingBox);
        setClashTunRules(res.clashTunRules);
        setClashVergeScript(res.clashVergeScript);
        onChanged?.(res.settings);
      })
      .catch((error) => setErr(error instanceof Error ? error.message : String(error)))
      .finally(() => setBusy(null));
  }, []);

  const handleSave = async () => {
    setBusy("save");
    setErr(null);
    setNotice(null);
    try {
      const res = await saveLocalNetwork({ localClashUrl, routeNodesViaSingBox });
      setLocalClashUrl(res.settings.localClashUrl);
      setRouteNodesViaSingBox(res.settings.routeNodesViaSingBox);
      setClashTunRules(res.clashTunRules);
      setClashVergeScript(res.clashVergeScript);
      onChanged?.(res.settings);
      setNotice(t("Local network settings saved."));
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  const handleDetect = async () => {
    setBusy("detect");
    setErr(null);
    setNotice(null);
    try {
      const found = await detectLocalClash();
      setDetected(found);
      if (found.length > 0) {
        setLocalClashUrl(found[0]!.url);
        setNotice(t("Detected {count} local proxy port(s).", { count: found.length }));
      } else {
        setNotice(t("No common local Clash / v2rayN ports were detected on 127.0.0.1."));
      }
    } catch (error) {
      setErr(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section className="settings-card">
      <header><h2>{t("Local Clash & TUN routing")}</h2></header>
      <div className="card-body">
        <p>{t("Profiles support 3 modes: Direct (bypasses system proxy), Local Clash (uses the address below), and Proxy Node (independent sing-box / chained node bypassing Clash TUN).")}</p>
        <div className="fld-row">
          <label className="fld grow">
            <span>{t("Local Clash proxy address")}</span>
            <input
              value={localClashUrl}
              placeholder="http://127.0.0.1:7897"
              onChange={(e) => setLocalClashUrl(e.target.value)}
            />
          </label>
        </div>
        {detected.length > 0 && (
          <div className="proxy-actions" style={{ marginBottom: 8 }}>
            {detected.map((item) => (
              <button
                key={item.port}
                type="button"
                className="btn xs"
                onClick={() => setLocalClashUrl(item.url)}
              >
                {item.url} ({item.hint})
              </button>
            ))}
          </div>
        )}
        <label className="extchk">
          <input
            type="checkbox"
            checked={routeNodesViaSingBox}
            onChange={(e) => setRouteNodesViaSingBox(e.target.checked)}
          />
          <span>{t("Route single-hop HTTP/SOCKS5 proxy nodes via sing-box.exe (recommended for Clash TUN bypass)")}</span>
        </label>
        <div className="proxy-actions" style={{ marginTop: 8 }}>
          <button type="button" className="btn primary" disabled={busy !== null} onClick={() => void handleSave()}>
            {busy === "save" ? t("Saving…") : t("Save network settings")}
          </button>
          <button type="button" className="btn" disabled={busy !== null} onClick={() => void handleDetect()}>
            {busy === "detect" ? t("Detecting…") : t("Auto-detect local Clash port")}
          </button>
        </div>
        {err && <div className="modal-err" role="alert">{err}</div>}
        {notice && <p className="hint" role="status">{notice}</p>}

        {(clashTunRules || clashVergeScript) && (
          <details className="fingerprint-settings" style={{ marginTop: 12 }}>
            <summary><span>{t("Clash / Mihomo TUN bypass rules")}</span></summary>
            <div className="proxy-settings">
              <small>
                {t("If Clash TUN mode is enabled, apply these rules at the top of Clash / Mihomo. Wrapping each rule with IN-TYPE,TUN ensures Direct and Proxy Node traffic bypasses TUN while Local Clash (127.0.0.1) traffic is never forced back to DIRECT under find-process-mode: strict.")}
              </small>
              <div className="segmented" role="tablist" aria-label={t("Clash / Mihomo TUN bypass rules")} style={{ alignSelf: "flex-start" }}>
                <button
                  type="button"
                  role="tab"
                  aria-selected={ruleFormat === "yaml"}
                  className={ruleFormat === "yaml" ? "on" : ""}
                  onClick={() => setRuleFormat("yaml")}
                >
                  {t("Clash YAML rules")}
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={ruleFormat === "verge-js"}
                  className={ruleFormat === "verge-js" ? "on" : ""}
                  onClick={() => setRuleFormat("verge-js")}
                >
                  {t("Clash Verge JS override")}
                </button>
              </div>
              {ruleFormat === "verge-js" && (
                <small>
                  {t("Paste into Clash Verge Rev → Subscriptions → Right-click → Edit Script (or Global Extend Script). Uses String.raw so backslashes are preserved intact.")}
                </small>
              )}
              <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12, margin: 0 }}>
                {ruleFormat === "verge-js" ? clashVergeScript : clashTunRules}
              </pre>
              <div className="proxy-actions">
                <button
                  type="button"
                  className={ruleFormat === "yaml" ? "btn primary" : "btn"}
                  onClick={() => {
                    void navigator.clipboard?.writeText(clashTunRules);
                    setCopiedFormat("yaml");
                    setTimeout(() => setCopiedFormat((cur) => (cur === "yaml" ? null : cur)), 1800);
                  }}
                >
                  {copiedFormat === "yaml" ? t("Copied") : t("Copy YAML rules")}
                </button>
                <button
                  type="button"
                  className={ruleFormat === "verge-js" ? "btn primary" : "btn"}
                  onClick={() => {
                    void navigator.clipboard?.writeText(clashVergeScript);
                    setCopiedFormat("verge-js");
                    setTimeout(() => setCopiedFormat((cur) => (cur === "verge-js" ? null : cur)), 1800);
                  }}
                >
                  {copiedFormat === "verge-js" ? t("Copied") : t("Copy Clash Verge JS script")}
                </button>
              </div>
            </div>
          </details>
        )}
      </div>
    </section>
  );
}
