import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "./i18n.tsx";
import { folderScope, type FolderInfo } from "../folders.ts";
import { ProxyProviderOffer } from "./proxy-offer.tsx";
import {
  addProxySubscription,
  assignProxyPoolNodes,
  deleteProxyPoolNodes,
  deleteProxySubscription,
  fetchProxyPool,
  importProxyPoolNodes,
  installSingBoxKernel,
  refreshProxySubscription,
  streamCheckProxyPoolNodes,
  type IpNetworkType,
  type IpRiskLevel,
  type ProxyPoolNodeView,
  type ProxySubscriptionView,
  type SingBoxKernelStatusView,
} from "./api.ts";
import type {
  ProxyCheckView,
  ProxyPreview,
  ProxyPreviewInput,
  ProxyProgressEvent,
  ProxyReplacementMode,
  ProxyReplacementView,
  ProxyScope,
} from "../proxy-tools-types.ts";

export class ProxyToolsError extends Error {}

const PAGE_SIZE = 50;
const CHECK_STATUSES = ["working", "failed", "unstable", "unavailable", "missing", "invalid", "unsupported"] as const;
function getCheckLabel(t: (key: string) => string, status: ProxyCheckView["status"]): string {
  const labels: Record<ProxyCheckView["status"], string> = {
    working: t("Alive"), failed: t("Dead"), unstable: t("Unstable"), unavailable: t("Unknown"),
    missing: t("Missing proxy"), invalid: t("Invalid proxy"), unsupported: t("Unsupported"),
  };
  return labels[status];
}
function getReplacementLabel(t: (key: string) => string, status: ProxyReplacementView["status"]): string {
  const labels: Record<ProxyReplacementView["status"], string> = {
    ready: t("Ready"), updated: t("Updated"), unchanged: t("No change"), missing: t("No match"), skipped: t("Skipped"), failed: t("Failed"),
  };
  return labels[status];
}
function getReasonLabel(t: (key: string) => string, reason: string): string {
  const reasons: Record<string, string> = {
    authentication_failed: t("Authentication failed"), timeout: t("Timed out"), dns_failed: t("DNS lookup failed"),
    unreachable: t("Cannot connect"), connection_failed: t("Connection failed"), intermittent: t("Intermittent connection"),
    proxy_bypassed: t("Connection bypassed the proxy"), check_unavailable: t("Check service unavailable"),
    profile_open: t("Close this profile before replacing its proxy"), version_conflict: t("Profile changed; preview again"),
    profile_trashed: t("Profile is in Trash"), invalid_row: t("Invalid input row"), invalid_proxy: t("Invalid proxy"),
    duplicate_selector: t("Duplicate input selector"), duplicate_target: t("Conflicting assignments"),
    no_editable_match: t("No editable profile matched"), ambiguous_username: t("More than one profile matched"),
    expected_version_required: t("Preview this profile again"), unsupported: t("This proxy type cannot be checked"),
    cancelled: t("Not completed"), folder_access_denied: t("Folder access denied"),
  };
  return reasons[reason] || t("Check could not complete");
}

export type SortDir = "asc" | "desc";
export type PoolSortKey = "default" | "latency" | "risk" | "status" | "country" | "protocol" | "name";
export type PoolRiskFilter = "all" | "working" | "low" | "medium_or_low" | "high" | "unchecked";
export type CheckSortKey = "default" | "latency" | "risk" | "status" | "ip";

function getRiskLevelLabel(t: (key: string) => string, level: IpRiskLevel | ""): string {
  if (level === "low") return t("Low risk");
  if (level === "medium") return t("Medium risk");
  if (level === "high") return t("High risk");
  return "";
}

function getIpTypeLabel(t: (key: string) => string, type: IpNetworkType | "" | undefined): string {
  if (type === "residential") return t("Residential");
  if (type === "mobile") return t("Mobile");
  if (type === "datacenter") return t("Datacenter");
  if (type === "vpn") return t("VPN");
  if (type === "proxy") return t("Proxy IP");
  if (type === "tor") return t("Tor");
  if (type === "unknown") return t("Unknown");
  return "";
}

function latencyTierClass(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return "";
  if (ms < 150) return "fast";
  if (ms <= 350) return "mid";
  return "slow";
}

function statusRank(status: string): number {
  if (status === "working") return 0;
  if (status === "unstable") return 1;
  if (status === "failed") return 2;
  if (status === "unavailable") return 3;
  if (status === "missing" || status === "invalid" || status === "unsupported") return 4;
  return 5;
}

function compareNullableNumber(a: number | null | undefined, b: number | null | undefined, dir: SortDir): number {
  const aValid = typeof a === "number" && Number.isFinite(a);
  const bValid = typeof b === "number" && Number.isFinite(b);
  if (!aValid && !bValid) return 0;
  if (!aValid) return 1;
  if (!bValid) return -1;
  return dir === "asc" ? a! - b! : b! - a!;
}

function compareNullableString(a: string | undefined, b: string | undefined, dir: SortDir): number {
  const aVal = (a ?? "").trim();
  const bVal = (b ?? "").trim();
  if (!aVal && !bVal) return 0;
  if (!aVal) return 1;
  if (!bVal) return -1;
  const cmp = aVal.localeCompare(bVal, undefined, { numeric: true, sensitivity: "base" });
  return dir === "asc" ? cmp : -cmp;
}

export function sortPoolNodes(nodes: ProxyPoolNodeView[], sortKey: PoolSortKey, sortDir: SortDir): ProxyPoolNodeView[] {
  if (sortKey === "default") return nodes;
  return [...nodes].sort((a, b) => {
    let diff = 0;
    if (sortKey === "latency") {
      diff = compareNullableNumber(a.lastLatencyMs, b.lastLatencyMs, sortDir)
        || compareNullableNumber(a.lastRiskScore, b.lastRiskScore, "asc");
    } else if (sortKey === "risk") {
      diff = compareNullableNumber(a.lastRiskScore, b.lastRiskScore, sortDir)
        || compareNullableNumber(a.lastLatencyMs, b.lastLatencyMs, "asc");
    } else if (sortKey === "status") {
      const aUnchecked = !a.lastStatus;
      const bUnchecked = !b.lastStatus;
      if (aUnchecked !== bUnchecked) diff = aUnchecked ? 1 : -1;
      else diff = (statusRank(a.lastStatus) - statusRank(b.lastStatus)) * (sortDir === "asc" ? 1 : -1);
      if (!diff) diff = compareNullableNumber(a.lastLatencyMs, b.lastLatencyMs, "asc");
    } else if (sortKey === "country") {
      diff = compareNullableString(a.lastCountry || a.lastIp, b.lastCountry || b.lastIp, sortDir)
        || compareNullableNumber(a.lastRiskScore, b.lastRiskScore, "asc");
    } else if (sortKey === "protocol") {
      diff = compareNullableString(a.type, b.type, sortDir);
    } else if (sortKey === "name") {
      diff = compareNullableString(a.name, b.name, sortDir);
    }
    return diff || a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
  });
}

export function sortCheckRows(rows: ProxyCheckView[], sortKey: CheckSortKey, sortDir: SortDir): ProxyCheckView[] {
  if (sortKey === "default") return rows;
  return [...rows].sort((a, b) => {
    let diff = 0;
    if (sortKey === "latency") {
      diff = compareNullableNumber(a.latencyMs, b.latencyMs, sortDir)
        || compareNullableNumber(a.riskScore, b.riskScore, "asc");
    } else if (sortKey === "risk") {
      diff = compareNullableNumber(a.riskScore, b.riskScore, sortDir)
        || compareNullableNumber(a.latencyMs, b.latencyMs, "asc");
    } else if (sortKey === "status") {
      diff = (statusRank(a.status) - statusRank(b.status)) * (sortDir === "asc" ? 1 : -1)
        || compareNullableNumber(a.latencyMs, b.latencyMs, "asc");
    } else if (sortKey === "ip") {
      diff = compareNullableString(a.country || a.ip, b.country || b.ip, sortDir)
        || compareNullableNumber(a.riskScore, b.riskScore, "asc");
    }
    return diff || (a.proxy ?? "").localeCompare(b.proxy ?? "");
  });
}

export function sortNodesForPicker(nodes: ProxyPoolNodeView[]): ProxyPoolNodeView[] {
  const tier = (status: ProxyPoolNodeView["lastStatus"]): number => {
    if (status === "working") return 0;
    if (status === "unstable") return 1;
    if (status === "") return 2;
    if (status === "unavailable") return 3;
    return 4;
  };
  return [...nodes].sort((a, b) => (
    tier(a.lastStatus) - tier(b.lastStatus)
    || compareNullableNumber(a.lastRiskScore, b.lastRiskScore, "asc")
    || compareNullableNumber(a.lastLatencyMs, b.lastLatencyMs, "asc")
    || a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" })
  ));
}

export function formatPoolPickerOption(node: ProxyPoolNodeView, t: (key: string) => string): string {
  const prefix = `[${node.type.toUpperCase()}] ${node.name}`;
  if (node.lastStatus === "failed") {
    return `${prefix} · ${t("Dead")}`;
  }
  const parts: string[] = [];
  if (node.lastCountry) parts.push(node.lastCountry);
  if (node.lastLatencyMs != null) parts.push(`${node.lastLatencyMs}ms`);
  if (node.lastRiskScore != null && node.lastRiskLevel) {
    parts.push(`${getRiskLevelLabel(t, node.lastRiskLevel)} ${node.lastRiskScore}`);
  }
  if (!parts.length) return `${prefix} (${node.host}:${node.port})`;
  return `${prefix} · ${parts.join(" · ")}`;
}

function formatBytes(bytes?: number): string {
  if (!bytes || !Number.isFinite(bytes)) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = bytes;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val.toFixed(val >= 100 ? 0 : 1)} ${units[idx]}`;
}

export function proxyScope(all: boolean, groups: string[], ids?: string[]): ProxyScope {
  return { ...(all ? { all: true } : { groups: [...new Set(groups)] }), ...(ids ? { ids: [...new Set(ids)] } : {}) };
}

export function proxyResultPage<T>(rows: T[], requestedPage: number) {
  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const page = Math.min(Math.max(0, requestedPage), pages - 1);
  return { items: rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), page, pages, total: rows.length };
}

function checkNeedsRetry(row: ProxyCheckView): boolean {
  return row.status === "failed" || row.status === "unstable" || row.status === "unavailable";
}

export function failedProxyProfileIds(rows: ProxyCheckView[]): string[] {
  return [...new Set(rows.filter(checkNeedsRetry).flatMap((row) => row.profiles.map((profile) => profile.id)))];
}

export function mergeProxyCheckResult(rows: ProxyCheckView[], next: ProxyCheckView): ProxyCheckView[] {
  const updatedIds = new Set(next.profiles.map((profile) => profile.id));
  const remaining = rows.flatMap((row) => {
    const profiles = row.profiles.filter((profile) => !updatedIds.has(profile.id));
    return profiles.length ? [{ ...row, profiles }] : [];
  });
  return [...remaining, next];
}

export function retryProxyProfileIds(rows: ProxyReplacementView[]): string[] {
  return [...new Set(rows.filter((row) => row.status === "failed" || row.status === "skipped")
    .flatMap((row) => row.profileId ? [row.profileId] : []))];
}

export function proxyRequest(path: string, body: unknown, signal?: AbortSignal): Promise<Response> {
  return fetch(`/ui/api/proxies/${path}`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal,
  });
}

async function previewResponse(response: Response, t: (key: string) => string): Promise<ProxyPreview> {
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new ProxyToolsError(t("You do not have access to this proxy operation."));
    if (response.status === 404 || response.status === 501 || response.status === 503) throw new ProxyToolsError(t("Bulk proxy tools are not available on this server."));
    throw new ProxyToolsError(t("Could not preview replacements. Check the input format and selected folders."));
  }
  let body: ProxyPreview;
  try { body = await response.json(); } catch { throw new ProxyToolsError(t("The proxy preview returned invalid data.")); }
  if (body?.ok !== true || typeof body.previewId !== "string" || !Array.isArray(body.rows) || !Number.isInteger(body.unusedProxies)) {
    throw new ProxyToolsError(t("The proxy preview returned invalid data."));
  }
  return body;
}

export async function requestProxyPreview(input: ProxyPreviewInput, t: (key: string) => string, signal?: AbortSignal): Promise<ProxyPreview> {
  return previewResponse(await proxyRequest("preview", input, signal), t);
}

export async function readProxyProgress(
  response: Response, onEvent: (event: ProxyProgressEvent) => void, t: (key: string) => string, signal?: AbortSignal,
): Promise<void> {
  if (!response.ok || !response.body || !response.headers.get("content-type")?.includes("application/x-ndjson")) {
    throw new ProxyToolsError(t("The proxy operation could not start. Check your connection and server version."));
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = "";
  let done = false;
  const abort = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener("abort", abort, { once: true });
  const accept = (line: string) => {
    if (!line.trim()) return;
    let event: ProxyProgressEvent;
    try { event = JSON.parse(line); } catch { throw new ProxyToolsError(t("The proxy operation returned incomplete data.")); }
    if (!event || typeof event !== "object" || done) throw new ProxyToolsError(t("The proxy operation returned invalid data."));
    switch (event.type) {
      case "progress":
        if (!["loading", "checking", "applying"].includes(event.phase) || !Number.isFinite(event.completed) || !Number.isFinite(event.total)) throw new ProxyToolsError(t("Invalid proxy progress."));
        break;
      case "summary":
        if (![event.selectedProfiles, event.uniqueProxies, event.duplicatesSkipped].every(Number.isFinite)) throw new ProxyToolsError(t("Invalid proxy summary."));
        break;
      case "check":
        if (!event.row || !(CHECK_STATUSES as readonly string[]).includes(event.row.status) || !Array.isArray(event.row.profiles)) throw new ProxyToolsError(t("Invalid proxy check result."));
        break;
      case "replacement":
        if (!event.row || !Number.isInteger(event.row.index) || !["ready", "updated", "unchanged", "missing", "skipped", "failed"].includes(event.row.status)) throw new ProxyToolsError(t("Invalid proxy replacement result."));
        break;
      case "done": done = true; break;
      case "error": throw new ProxyToolsError(t("The proxy operation failed. Completed results remain available."));
      default: throw new ProxyToolsError(t("The proxy operation returned invalid data."));
    }
    onEvent(event);
  };
  try {
    while (true) {
      if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
      const chunk = await reader.read();
      if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
      if (chunk.done) break;
      pending += decoder.decode(chunk.value, { stream: true });
      let end: number;
      while ((end = pending.indexOf("\n")) !== -1) {
        accept(pending.slice(0, end));
        pending = pending.slice(end + 1);
      }
    }
    pending += decoder.decode();
    if (pending.trim()) accept(pending);
    if (!done) throw new ProxyToolsError(t("The proxy operation was interrupted. Some rows were not completed."));
  } finally {
    signal?.removeEventListener("abort", abort);
    if (!done) await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function Pager({ page, pages, total, onPage }: { page: number; pages: number; total: number; onPage: (page: number) => void }) {
  const { t } = useTranslation();
  return <div className="proxy-pager">
    <span>{t("{total} rows", { total: total.toLocaleString() })}</span>
    <button type="button" className="btn" disabled={page === 0} onClick={() => onPage(page - 1)}>{t("Previous")}</button>
    <span>{t("Page {page} / {pages}", { page: page + 1, pages })}</span>
    <button type="button" className="btn" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>{t("Next")}</button>
  </div>;
}

function AffectedProfiles({ profiles }: { profiles: ProxyCheckView["profiles"] }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(0);
  const result = proxyResultPage(profiles, page);
  const folders = [...new Set(profiles.map((profile) => profile.group || t("Ungrouped")))];
  return <details className="proxy-affected">
    <summary>{t("{profiles} profiles · {folders} folders", { profiles: profiles.length.toLocaleString(), folders: folders.length })}</summary>
    <div>{folders.join(", ")}</div>
    <ul>{result.items.map((profile) => <li key={profile.id}>{profile.name || profile.id} · {profile.group || t("Ungrouped")}</li>)}</ul>
    {result.pages > 1 && <Pager {...result} onPage={setPage} />}
  </details>;
}

export function ProxiesPage({ groups, folders = [], onChanged, active, profilesWithoutProxy = 0, store }: {
  groups: string[];
  folders?: FolderInfo[];
  onChanged: () => Promise<void>;
  active: boolean;
  /** Profiles with no proxy, or 0 when the count is unknown (Cloud mode). */
  profilesWithoutProxy?: number;
  /** The Cloud page with the in-app shop. It gets the proxy tools and shows them in its Tools tab. */
  store?: (tools: ReactNode) => ReactNode;
}) {
  const { t } = useTranslation();
  const [all, setAll] = useState(true);
  const [selectedGroups, setSelectedGroups] = useState<string[]>([]);
  const [task, setTask] = useState<"check" | "replace" | "pool">("check");
  const [mode, setMode] = useState<ProxyReplacementMode>("list");
  const [input, setInput] = useState("");
  const [perProxy, setPerProxy] = useState(1);
  const [preview, setPreview] = useState<ProxyPreview | null>(null);
  const [checks, setChecks] = useState<ProxyCheckView[]>([]);
  const [checkSummary, setCheckSummary] = useState<Extract<ProxyProgressEvent, { type: "summary" }> | null>(null);
  const [progress, setProgress] = useState<Extract<ProxyProgressEvent, { type: "progress" }> | null>(null);
  const [busy, setBusy] = useState<"preview" | "apply" | "check" | "file" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [replacementPage, setReplacementPage] = useState(0);
  const [checkPage, setCheckPage] = useState(0);
  const [replacementFailures, setReplacementFailures] = useState(false);
  const [checkFailures, setCheckFailures] = useState(false);
  const [checkSortKey, setCheckSortKey] = useState<CheckSortKey>("default");
  const [checkSortDir, setCheckSortDir] = useState<SortDir>("asc");

  // ---- Node pool & subscriptions state (sing-box + chain proxy) ----
  const [kernel, setKernel] = useState<SingBoxKernelStatusView | null>(null);
  const [subscriptions, setSubscriptions] = useState<ProxySubscriptionView[]>([]);
  const [poolNodes, setPoolNodes] = useState<ProxyPoolNodeView[]>([]);
  const [poolBusy, setPoolBusy] = useState<"load" | "kernel" | "sub" | "import" | "check" | "assign" | "delete" | null>(null);
  const [subName, setSubName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [subUseLocalClash, setSubUseLocalClash] = useState(false);
  const [nodePaste, setNodePaste] = useState("");
  const [poolQuery, setPoolQuery] = useState("");
  const [poolSource, setPoolSource] = useState<string>("all");
  const [poolRiskFilter, setPoolRiskFilter] = useState<PoolRiskFilter>("all");
  const [poolSortKey, setPoolSortKey] = useState<PoolSortKey>("default");
  const [poolSortDir, setPoolSortDir] = useState<SortDir>("asc");
  const [poolIncludeRisk, setPoolIncludeRisk] = useState(true);
  const [poolCheckProgress, setPoolCheckProgress] = useState<{ completed: number; total: number } | null>(null);
  const [copiedNodeId, setCopiedNodeId] = useState<string | null>(null);
  const [selectedNodeIds, setSelectedNodeIds] = useState<string[]>([]);
  const [poolPreProxyId, setPoolPreProxyId] = useState("");
  const [poolPerNode, setPoolPerNode] = useState(1);
  const [poolPage, setPoolPage] = useState(0);

  const controller = useRef<AbortController | null>(null);
  const poolController = useRef<AbortController | null>(null);
  const scope = proxyScope(all, selectedGroups);
  const scopeReady = all || selectedGroups.length > 0;
  const folderNames = [...new Set(groups)];
  const retries = retryProxyProfileIds(preview?.rows ?? []);
  const failedChecks = failedProxyProfileIds(checks);
  const replacements = proxyResultPage((preview?.rows ?? []).filter((row) => !replacementFailures || ["failed", "skipped", "missing"].includes(row.status)), replacementPage);
  const sortedChecks = useMemo(
    () => sortCheckRows(checks.filter((row) => !checkFailures || row.status !== "working"), checkSortKey, checkSortDir),
    [checks, checkFailures, checkSortKey, checkSortDir],
  );
  const checkResults = proxyResultPage(sortedChecks, checkPage);
  const ready = preview?.rows.filter((row) => row.status === "ready").length ?? 0;

  const filteredPoolNodes = useMemo(() => {
    const q = poolQuery.trim().toLowerCase();
    const filtered = poolNodes.filter((node) => {
      if (poolSource === "manual" && node.subscriptionId !== "") return false;
      if (poolSource !== "all" && poolSource !== "manual" && node.subscriptionId !== poolSource) return false;
      if (poolRiskFilter === "working" && node.lastStatus !== "working") return false;
      if (poolRiskFilter === "low" && node.lastRiskLevel !== "low") return false;
      if (poolRiskFilter === "medium_or_low" && node.lastRiskLevel !== "low" && node.lastRiskLevel !== "medium") return false;
      if (poolRiskFilter === "high" && node.lastRiskLevel !== "high") return false;
      if (poolRiskFilter === "unchecked" && node.lastStatus !== "") return false;
      if (!q) return true;
      return (
        node.name.toLowerCase().includes(q)
        || node.type.toLowerCase().includes(q)
        || node.host.toLowerCase().includes(q)
        || node.lastCountry.toLowerCase().includes(q)
        || (node.lastCity ?? "").toLowerCase().includes(q)
        || (node.lastIsp ?? "").toLowerCase().includes(q)
        || (node.lastIpType ?? "").toLowerCase().includes(q)
        || node.lastIp.toLowerCase().includes(q)
      );
    });
    return sortPoolNodes(filtered, poolSortKey, poolSortDir);
  }, [poolNodes, poolQuery, poolSource, poolRiskFilter, poolSortKey, poolSortDir]);
  const pagedPoolNodes = proxyResultPage(filteredPoolNodes, poolPage);

  const togglePoolSort = (key: Exclude<PoolSortKey, "default">) => {
    if (poolSortKey === key) setPoolSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    else { setPoolSortKey(key); setPoolSortDir("asc"); }
    setPoolPage(0);
  };

  const toggleCheckSort = (key: Exclude<CheckSortKey, "default">) => {
    if (checkSortKey === key) setCheckSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    else { setCheckSortKey(key); setCheckSortDir("asc"); }
    setCheckPage(0);
  };

  const sortIndicator = (activeKey: string, targetKey: string, dir: SortDir) =>
    activeKey === targetKey ? (dir === "asc" ? " ↑" : " ↓") : "";

  useEffect(() => () => {
    controller.current?.abort(); controller.current = null;
    poolController.current?.abort(); poolController.current = null;
  }, []);

  const loadPool = async () => {
    setPoolBusy("load");
    try {
      const state = await fetchProxyPool();
      setKernel(state.kernel);
      setSubscriptions(state.subscriptions);
      setPoolNodes(state.nodes);
      const validIds = new Set(state.nodes.map((n) => n.id));
      setSelectedNodeIds((prev) => prev.filter((id) => validIds.has(id)));
      if (poolPreProxyId && poolPreProxyId !== "__local_clash__" && !validIds.has(poolPreProxyId)) setPoolPreProxyId("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPoolBusy(null);
    }
  };

  useEffect(() => {
    if (active && task === "pool") void loadPool();
  }, [active, task]);

  const invalidatePreview = () => {
    setPreview(null); setReplacementPage(0); setError(null); setNotice(null);
  };
  const invalidateScope = () => {
    invalidatePreview(); setChecks([]); setCheckSummary(null); setCheckPage(0); setProgress(null);
  };
  const start = (operation: NonNullable<typeof busy>) => {
    if (controller.current) return null;
    const current = new AbortController();
    controller.current = current;
    setBusy(operation); setError(null); setNotice(null); setProgress(null);
    return current;
  };
  const finish = (current: AbortController) => {
    if (controller.current !== current) return;
    controller.current = null; setBusy(null);
  };
  const failed = (current: AbortController, operation: string, failure: unknown) => {
    if (controller.current !== current) return;
    // Raw fetch errors can include URLs. Only fixed client messages reach the page.
    if (current.signal.aborted) setNotice(t("Cancelled. Completed results remain saved; some rows may be incomplete."));
    else if (failure instanceof ProxyToolsError) setError(failure.message);
    else setError(t("{operation} failed. Check the input, folder access, and connection, then try again.", { operation }));
  };

  const makePreview = async (retry = false) => {
    const current = start("preview");
    if (!current) return;
    try {
      const next = retry && preview
        ? await previewResponse(await proxyRequest("retry-preview", { previewId: preview.previewId, ids: retries }, current.signal), t)
        : await requestProxyPreview({ scope, mode, input, ...(mode === "list" ? { profilesPerProxy: perProxy } : {}) }, t, current.signal);
      if (controller.current !== current || current.signal.aborted) return;
      setPreview(next); setReplacementPage(0); setReplacementFailures(false);
      setNotice(t("Review these assignments before applying. Open profiles are skipped."));
    } catch (failure) { failed(current, "Preview", failure); }
    finally { finish(current); }
  };

  const apply = async () => {
    if (!preview || !ready) return;
    const current = start("apply");
    if (!current) return;
    setChecks([]); setCheckSummary(null); setCheckPage(0);
    try {
      await readProxyProgress(await proxyRequest("apply", { previewId: preview.previewId }, current.signal), (event) => {
        if (controller.current !== current) return;
        if (event.type === "progress") setProgress(event);
        if (event.type === "replacement") setPreview((previous) => previous && ({
          ...previous, rows: previous.rows.map((row) => row.index === event.row.index ? event.row : row),
        }));
      }, t, current.signal);
      if (controller.current === current) setNotice(t("Replacement run finished. Review the results for skipped or failed profiles."));
    } catch (failure) { failed(current, "Replacement", failure); }
    finally {
      if (controller.current === current) {
        try { await onChanged(); } catch { setError(t("Results are saved, but the profile list could not refresh.")); }
      }
      finish(current);
    }
  };

  const runChecks = async (retry = false) => {
    const current = start("check");
    if (!current) return;
    if (!retry) setChecks([]);
    setCheckSummary(null); setCheckPage(0);
    try {
      await readProxyProgress(await proxyRequest("check", {
        scope: proxyScope(all, selectedGroups, retry ? failedChecks : undefined),
      }, current.signal), (event) => {
        if (controller.current !== current) return;
        if (event.type === "progress") setProgress(event);
        if (event.type === "summary") setCheckSummary(event);
        if (event.type === "check") setChecks((rows) => retry ? mergeProxyCheckResult(rows, event.row) : [...rows, event.row]);
      }, t, current.signal);
      if (controller.current === current) setNotice(t("Proxy checks finished. Unknown means the check could not establish a result."));
    } catch (failure) { failed(current, "Proxy check", failure); }
    finally { finish(current); }
  };

  const loadFile = async (file: File) => {
    const current = start("file");
    if (!current) return;
    invalidatePreview();
    try {
      const text = await file.text();
      if (controller.current === current && !current.signal.aborted) setInput(text);
    } catch { if (controller.current === current) setError(t("The selected file could not be read.")); }
    finally { finish(current); }
  };

  // ---- Node pool actions ----
  const handleInstallKernel = async () => {
    setPoolBusy("kernel"); setError(null); setNotice(null);
    try {
      const status = await installSingBoxKernel();
      setKernel(status);
      setNotice(`sing-box v${status.version} ${t("Installed")}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPoolBusy(null);
    }
  };

  const handleAddSub = async () => {
    if (!subUrl.trim()) return;
    setPoolBusy("sub"); setError(null); setNotice(null);
    try {
      const res = await addProxySubscription({
        name: subName.trim() || undefined,
        url: subUrl.trim(),
        useLocalClash: subUseLocalClash,
      });
      setSubName(""); setSubUrl("");
      setNotice(t("Synced {count} nodes from subscription.", { count: res.imported }));
      await loadPool();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPoolBusy(null);
    }
  };

  const handleRefreshSub = async (id: string) => {
    setPoolBusy("sub"); setError(null); setNotice(null);
    try {
      const res = await refreshProxySubscription(id, subUseLocalClash);
      setNotice(res.preserved
        ? t("Synced {count} nodes from subscription ({preserved} check results preserved).", {
            count: res.imported,
            preserved: res.preserved,
          })
        : t("Synced {count} nodes from subscription.", { count: res.imported }));
      await loadPool();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      await loadPool();
    }
  };

  const handleDeleteSub = async (id: string) => {
    setPoolBusy("delete"); setError(null); setNotice(null);
    try {
      await deleteProxySubscription(id);
      await loadPool();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPoolBusy(null);
    }
  };

  const handleImportNodes = async () => {
    if (!nodePaste.trim()) return;
    setPoolBusy("import"); setError(null); setNotice(null);
    try {
      const res = await importProxyPoolNodes(nodePaste);
      setNodePaste("");
      setNotice(t("Imported {imported} nodes ({duplicates} duplicates, {skipped} skipped).", {
        imported: res.imported, duplicates: res.duplicates, skipped: res.skipped,
      }));
      await loadPool();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPoolBusy(null);
    }
  };

  const handleCheckPoolNodes = async (targetIds: string[]) => {
    if (!targetIds.length || poolController.current) return;
    const current = new AbortController();
    poolController.current = current;
    setPoolBusy("check");
    setPoolCheckProgress({ completed: 0, total: targetIds.length });
    setError(null);
    setNotice(null);
    let aliveCount = 0;
    let finishedCount = 0;
    let wasCancelled = false;
    try {
      await streamCheckProxyPoolNodes(
        {
          ids: targetIds,
          preProxyNodeId: poolPreProxyId || undefined,
          includeRisk: poolIncludeRisk,
        },
        (event) => {
          if (poolController.current !== current) return;
          if (event.type === "progress") {
            setPoolCheckProgress({ completed: event.completed, total: event.total });
          } else if (event.type === "result") {
            const item = event.item;
            finishedCount++;
            if (item.status === "working") aliveCount++;
            setPoolNodes((prev) => prev.map((node) => (
              node.id === item.id
                ? {
                    ...node,
                    lastStatus: item.status,
                    lastReason: item.reason,
                    lastIp: item.ip,
                    lastCountry: item.country,
                    lastCity: item.city,
                    lastIsp: item.isp,
                    lastIpType: item.ipType,
                    lastRiskScore: item.riskScore,
                    lastRiskLevel: item.riskLevel,
                    lastRiskFlags: item.riskFlags,
                    lastLatencyMs: item.latencyMs,
                    lastCheckedAt: item.checkedAt,
                  }
                : node
            )));
          } else if (event.type === "done") {
            wasCancelled = event.cancelled;
          }
        },
        current.signal,
      );
      if (poolController.current === current) {
        setNotice(wasCancelled
          ? t("Cancelled node check. {completed} completed results were saved.", { completed: finishedCount })
          : t("Checked {total} nodes: {alive} alive.", { total: finishedCount, alive: aliveCount }));
      }
    } catch (e) {
      if (poolController.current === current) {
        if (current.signal.aborted || (e instanceof DOMException && e.name === "AbortError")) {
          setNotice(t("Cancelled node check. {completed} completed results were saved.", { completed: finishedCount }));
        } else {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    } finally {
      if (poolController.current === current) {
        poolController.current = null;
        setPoolCheckProgress(null);
        setPoolBusy(null);
      }
    }
  };

  const handleDeletePoolNodes = async (ids: string[]) => {
    if (!ids.length) return;
    setPoolBusy("delete"); setError(null); setNotice(null);
    try {
      const deleted = await deleteProxyPoolNodes(ids);
      setSelectedNodeIds((prev) => prev.filter((id) => !ids.includes(id)));
      setNotice(t("Deleted {count} proxy nodes.", { count: deleted }));
      await loadPool();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPoolBusy(null);
    }
  };

  const handleDeleteFailedPoolNodes = async () => {
    if (!failedPoolNodeIds.length) return;
    if (!confirm(t("Delete {count} failed proxy nodes from the current filter?", { count: failedPoolNodeIds.length }))) return;
    await handleDeletePoolNodes(failedPoolNodeIds);
  };

  const handleCopyNodeUri = (node: ProxyPoolNodeView) => {
    void navigator.clipboard?.writeText(node.value);
    setCopiedNodeId(node.id);
    setTimeout(() => setCopiedNodeId((cur) => (cur === node.id ? null : cur)), 1500);
  };

  const handleAssignPoolNodes = async () => {
    const nodeById = new Map(poolNodes.map((n) => [n.id, n]));
    const selectedSet = new Set(selectedNodeIds);
    const orderedIds = selectedSet.size
      ? [
          ...filteredPoolNodes.filter((n) => selectedSet.has(n.id)).map((n) => n.id),
          ...selectedNodeIds.filter((id) => !filteredPoolNodes.some((n) => n.id === id)),
        ]
      : filteredPoolNodes.map((n) => n.id);
    const nonFailedIds = orderedIds.filter((id) => nodeById.get(id)?.lastStatus !== "failed");
    const skippedFailed = orderedIds.length - nonFailedIds.length;
    if (!orderedIds.length || !scopeReady) return;
    if (!nonFailedIds.length) {
      setError(t("All selected nodes are failed. Select working or unchecked nodes to assign."));
      return;
    }
    setPoolBusy("assign"); setError(null); setNotice(null);
    try {
      const res = await assignProxyPoolNodes({
        scope,
        nodeIds: nonFailedIds,
        preProxyNodeId: poolPreProxyId || undefined,
        profilesPerNode: poolPerNode,
        skipFailed: true,
      });
      const totalSkippedFailed = skippedFailed + (res.skippedFailedNodes ?? 0);
      setNotice(totalSkippedFailed > 0
        ? t("Assigned {assigned} profiles ({skipped} skipped, {failed} failed · auto-skipped {dead} dead nodes).", {
            assigned: res.assigned, skipped: res.skipped, failed: res.failed, dead: totalSkippedFailed,
          })
        : t("Assigned {assigned} profiles ({skipped} skipped, {failed} failed).", {
            assigned: res.assigned, skipped: res.skipped, failed: res.failed,
          }));
      await onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setPoolBusy(null);
    }
  };

  const hasFailedChecks = !busy && checks.some((row) => row.status === "failed" || row.status === "unstable");
  const allVisibleSelected = pagedPoolNodes.items.length > 0 && pagedPoolNodes.items.every((n) => selectedNodeIds.includes(n.id));
  const allFilteredSelected = filteredPoolNodes.length > 0 && filteredPoolNodes.every((n) => selectedNodeIds.includes(n.id));
  const failedPoolNodeIds = useMemo(
    () => filteredPoolNodes.filter((n) => n.lastStatus === "failed").map((n) => n.id),
    [filteredPoolNodes],
  );
  const sortedPreProxyNodes = useMemo(() => sortNodesForPicker(poolNodes), [poolNodes]);

  const tools = <>
    <div className="tools-tabs" aria-label={t("Proxy tools")}>
      <button className={task === "check" ? "selected" : ""} aria-pressed={task === "check"} onClick={() => setTask("check")}>{t("Check proxies")} <small>{t("Find connection problems")}</small></button>
      <button className={task === "replace" ? "selected" : ""} aria-pressed={task === "replace"} onClick={() => setTask("replace")}>{t("Replace proxies")} <small>{t("Assign new connections")}</small></button>
      <button className={task === "pool" ? "selected" : ""} aria-pressed={task === "pool"} onClick={() => setTask("pool")}>{t("Node pool & subscriptions")} <small>{t("Manage sing-box nodes & chains")}</small></button>
    </div>
    <section className="tools-panel proxy-scope">
      <div className="tools-panel-head"><div><h3>{task === "replace" && <span className="tools-step">1</span>}{t("Choose folders")}</h3><p>{t("Includes every profile in these folders, across all pages.")}</p></div><span className="tools-folder-tag">{all ? t("All folders") : t("{count} selected", { count: selectedGroups.length })}</span></div>
      <div className="proxy-folder-list">
        <label className={`folder-chip${all ? " selected" : ""}`}><input type="checkbox" checked={all} disabled={!!busy} onChange={(event) => { setAll(event.target.checked); setSelectedGroups([]); invalidateScope(); }} />{t("All folders")}</label>
        {folderNames.map((name) => <label className={`folder-chip${!all && selectedGroups.includes(name) ? " selected" : ""}`} key={name}>
          <input type="checkbox" checked={all || selectedGroups.includes(name)} disabled={!!busy} onChange={(event) => {
            const branch = new Set([name, ...folderScope(folders, name)]);
            const current = all ? folderNames : selectedGroups;
            setSelectedGroups(event.target.checked ? [...new Set([...current, ...branch])] : current.filter((group) => !branch.has(group)));
            setAll(false); invalidateScope();
          }} />{name || t("Ungrouped")}
        </label>)}
      </div>
      {!scopeReady && <p className="tools-hint">{t("Select at least one folder to continue.")}</p>}
    </section>
    {error && <div className="tools-alert" role="alert">{error}</div>}
    {notice && <div className="tools-notice" role="status">{notice}</div>}
    {busy && <div className="tools-progress" role="status">
      <div className="proxy-actions"><strong>{progress ? `${progress.phase === "loading" ? t("Loading profiles") : progress.phase === "checking" ? t("Checking proxies") : t("Applying changes")}: ${progress.completed.toLocaleString()} / ${progress.total.toLocaleString()}` : t("Preparing…")}</strong>
        <button type="button" className="btn" onClick={() => controller.current?.abort()}>{t("Cancel")}</button></div>
      <progress aria-label={t("Proxy operation progress")} {...(progress && progress.total > 0 ? { value: progress.completed, max: progress.total } : {})} />
    </div>}
    {task === "check" ? <>
      <section className="tools-panel">
        <div className="tools-panel-head"><div><h3>{t("Check your connections")}</h3><p>{t("Shared proxies are checked once. No browsers open and no settings change.")}</p></div>
          <button type="button" className="btn primary" disabled={!!busy || !scopeReady} onClick={() => void runChecks()}>{busy === "check" ? t("Checking…") : t("Check proxies")}</button></div>
        {checkSummary && <div className="tools-stats">
          <div><strong>{checkSummary.selectedProfiles.toLocaleString()}</strong><span>{t("Profiles included")}</span></div>
          <div><strong>{checkSummary.uniqueProxies.toLocaleString()}</strong><span>{t("Unique proxies")}</span></div>
          <div><strong>{checkSummary.duplicatesSkipped.toLocaleString()}</strong><span>{t("Duplicate checks avoided")}</span></div>
          <div><strong>{checks.filter((row) => row.status === "working").length.toLocaleString()}</strong><span>{t("Alive")}</span></div>
        </div>}
        {checks.length > 0 ? <>
          <div className="tools-result-bar"><h3>{t("Check results")}</h3><div className="proxy-actions">
            <select
              aria-label={t("Sort by")}
              value={`${checkSortKey}:${checkSortDir}`}
              onChange={(event) => {
                const [k, d] = event.target.value.split(":") as [CheckSortKey, SortDir];
                setCheckSortKey(k || "default");
                setCheckSortDir(d === "desc" ? "desc" : "asc");
                setCheckPage(0);
              }}
            >
              <option value="default:asc">{t("Default order")}</option>
              <option value="latency:asc">{t("Latency: low to high")}</option>
              <option value="latency:desc">{t("Latency: high to low")}</option>
              <option value="risk:asc">{t("Risk: low to high")}</option>
              <option value="risk:desc">{t("Risk: high to low")}</option>
              <option value="status:asc">{t("Status: alive first")}</option>
              <option value="ip:asc">{t("Country / Exit IP")}</option>
            </select>
            <label className="proxy-choice"><input type="checkbox" checked={checkFailures} onChange={(event) => { setCheckFailures(event.target.checked); setCheckPage(0); }} />{t("Only problems")}</label>
            <button type="button" className="btn" disabled={!!busy || !failedChecks.length} onClick={() => void runChecks(true)}>{t("Retry failed checks")}</button>
          </div></div>
          <div className="proxy-table-wrap"><table className="profile-table proxy-table"><thead><tr>
            <th>{t("Proxy address")}</th>
            <th><button type="button" className="pool-sort-btn" onClick={() => toggleCheckSort("status")}>{t("Connection")}{sortIndicator(checkSortKey, "status", checkSortDir)}</button></th>
            <th><button type="button" className="pool-sort-btn" onClick={() => toggleCheckSort("ip")}>{t("Exit IP")}{sortIndicator(checkSortKey, "ip", checkSortDir)}</button></th>
            <th><button type="button" className="pool-sort-btn" onClick={() => toggleCheckSort("risk")}>{t("Risk")}{sortIndicator(checkSortKey, "risk", checkSortDir)}</button></th>
            <th><button type="button" className="pool-sort-btn" onClick={() => toggleCheckSort("latency")}>{t("Latency")}{sortIndicator(checkSortKey, "latency", checkSortDir)}</button></th>
            <th>{t("Used by")}</th>
            <th>{t("Checked")}</th>
          </tr></thead>
            <tbody>{checkResults.items.map((row) => {
              const loc = [row.country, row.city].filter(Boolean).join(" · ");
              const riskLabel = row.riskLevel ? getRiskLevelLabel(t, row.riskLevel) : "";
              const ipTypeLabel = getIpTypeLabel(t, row.ipType);
              return <tr key={`${row.key}-${row.profiles[0]?.id}`}>
                <td className="tools-mono">{row.proxy || t("No proxy assigned")}</td>
                <td><span className={`tools-status ${row.status}`}>{getCheckLabel(t, row.status)}</span><small>{row.reason ? getReasonLabel(t, row.reason || "") : ""}</small></td>
                <td className="tools-mono">
                  {row.ip || "—"}
                  {loc && <small>{loc}</small>}
                  {row.isp && <small className="pool-isp">{row.isp}</small>}
                </td>
                <td>
                  {row.riskScore != null && row.riskLevel ? (
                    <>
                      <span className={`risk-badge ${row.riskLevel}`}>{riskLabel} · {row.riskScore}</span>
                      {ipTypeLabel && <small>{ipTypeLabel}</small>}
                    </>
                  ) : <span className="tools-hint">—</span>}
                </td>
                <td className={`tools-mono latency-cell ${latencyTierClass(row.latencyMs)}`}>
                  {row.latencyMs != null ? `${row.latencyMs} ms` : "—"}
                </td>
                <td><AffectedProfiles profiles={row.profiles} /></td>
                <td>{new Date(row.checkedAt).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}</td>
              </tr>;
            })}</tbody></table></div>
          {!checkResults.total && <p className="tools-hint tools-result-empty">{t("No problems found in the completed checks.")}</p>}
          <Pager {...checkResults} onPage={setCheckPage} />
        </> : <div className="tools-empty"><span className="tools-empty-symbol" aria-hidden="true">↗</span><h3>{busy === "check" ? t("Checking selected folders…") : t("Ready when you are")}</h3><p>{t("Choose your folders above, then check which proxies are alive, dead, or need attention.")}</p></div>}
      </section>
      <p className="tools-footnote">{t("Supports HTTP, SOCKS5, and sing-box protocols (VLESS, VMess, Trojan, SS, Hysteria 2, TUIC, WireGuard) as well as chained proxies.")}</p>
    </> : task === "replace" ? <>
      <section className="tools-panel proxy-input-panel">
        <div className="tools-panel-head"><div><h3><span className="tools-step">2</span>{t("Add replacement proxies")}</h3><p>{t("Nothing changes until you review and apply the assignments.")}</p></div></div>
        <div className="tools-panel-body">
          <label className="fld"><span>{t("Assignment method")}</span><select value={mode} disabled={!!busy} onChange={(event) => { setMode(event.target.value as ProxyReplacementMode); invalidatePreview(); }}>
            <option value="list">{t("Paste a proxy list")}</option><option value="profileId">{t("Match specific profile IDs — CSV")}</option><option value="oldProxy">{t("Replace matching old proxies — CSV")}</option>
          </select></label>
          <p className="tools-hint">{mode === "profileId" ? <>{t("Include a header row:")} <code>profileId,type,host,port,user,pass</code>.</>
            : mode === "oldProxy" ? <>{t("Include a header row:")} <code>oldProxy,newProxy</code>. {t("Each old proxy is replaced wherever it appears in the selected folders.")}</>
            : t("Paste one proxy per line. We match them to profiles in profile-ID order. Each proxy is used for the number of profiles you set below. You will see every assignment next.")}</p>
          {mode === "list" && <label className="fld"><span>{t("Profiles per proxy")}</span><input type="number" aria-label={t("Profiles per proxy")} min={1} step={1} value={perProxy} disabled={!!busy} onChange={(event) => { setPerProxy(Math.max(1, Math.floor(Number(event.target.value)) || 1)); invalidatePreview(); }} /></label>}
          <label className="fld"><span>{mode === "list" ? t("Your new proxy list") : t("Your replacement CSV")}</span><textarea aria-label={t("Replacement input")} rows={5} value={input} disabled={!!busy} spellCheck={false} autoComplete="off" placeholder={mode === "list" ? "proxy.example.com:8080:username:password\nsocks5://username:password@proxy.example.com:1080\nvless://uuid@node.example.com:443?security=reality&pbk=...#US-1\nhy2://password@node.example.com:443?sni=example.com#JP-1" : mode === "profileId" ? "profileId,type,host,port,user,pass" : "oldProxy,newProxy"} onChange={(event) => { setInput(event.target.value); invalidatePreview(); }} /></label>
          <div className="tools-result-bar"><label className="proxy-upload">{t("Or upload a file")}<input type="file" accept=".csv,.txt,text/csv,text/plain" disabled={!!busy} onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) void loadFile(file); }} /></label>
            <button type="button" className="btn primary" disabled={!!busy || !scopeReady || !input.trim()} onClick={() => void makePreview()}>{busy === "preview" ? t("Preparing preview…") : t("Preview changes")}</button></div>
        </div>
      </section>
      <section className="tools-panel">
        <div className="tools-panel-head"><div><h3><span className="tools-step">3</span>{t("Review changes")}</h3><p>{t("Check the old and new proxy for each profile. Open profiles are skipped.")}</p></div>
          {preview && <button type="button" className="btn primary" disabled={!!busy || !ready} onClick={() => void apply()}>{busy === "apply" ? t("Applying…") : t("Apply {count} changes", { count: ready.toLocaleString() })}</button>}</div>
        {preview ? <>
          <div className="tools-stats">
            <div><strong>{ready.toLocaleString()}</strong><span>{t("Ready to apply")}</span></div>
            <div><strong>{preview.rows.filter((row) => row.status === "updated").length.toLocaleString()}</strong><span>{t("Updated")}</span></div>
            <div><strong>{preview.rows.filter((row) => ["skipped", "failed", "missing"].includes(row.status)).length.toLocaleString()}</strong><span>{t("Need attention")}</span></div>
            <div><strong>{preview.rows.filter((row) => row.status === "unchanged").length.toLocaleString()}</strong><span>{t("Unchanged")}</span></div>
          </div>
          <div className="tools-result-bar"><span className="tools-hint">{t("{assignments} assignments · {unused} unused proxies", { assignments: preview.rows.length.toLocaleString(), unused: preview.unusedProxies.toLocaleString() })}</span><div className="proxy-actions">
            <label className="proxy-choice"><input type="checkbox" checked={replacementFailures} onChange={(event) => { setReplacementFailures(event.target.checked); setReplacementPage(0); }} />{t("Only problems")}</label>
            <button type="button" className="btn" disabled={!!busy || !retries.length} onClick={() => void makePreview(true)}>{t("Preview failed rows again")}</button>
          </div></div>
          <div className="proxy-table-wrap"><table className="profile-table proxy-table"><thead><tr><th>{t("Profile")}</th><th>{t("Folder")}</th><th>{t("Current proxy")}</th><th>{t("New proxy")}</th><th>{t("Status")}</th></tr></thead>
            <tbody>{replacements.items.map((row) => <tr key={row.index}>
              <td><strong>{row.name || row.profileId || t("Input row {index}", { index: row.index + 1 })}</strong><small className="tools-mono">{row.name ? row.profileId : ""}</small></td>
              <td>{row.group === undefined ? "—" : row.group || t("Ungrouped")}</td><td className="tools-mono">{row.previousProxy || "—"}</td><td className="tools-mono">{row.proxy || "—"}</td>
              <td><span className={`tools-status ${row.status}`}>{getReplacementLabel(t, row.status)}</span><small>{row.code ? getReasonLabel(t, row.code || "") : ""}</small></td>
            </tr>)}</tbody></table></div>
          <Pager {...replacements} onPage={setReplacementPage} />
        </> : <div className="tools-empty compact"><p>{t("Your preview will appear here. Saved sessions and fingerprints stay unchanged.")}</p></div>}
      </section>
    </> : <>
      <section className="tools-panel">
        <div className="tools-panel-head">
          <div>
            <h3>{t("sing-box kernel")}</h3>
            <p>{t("Required for VLESS, VMess, Trojan, SS, Hysteria 2, TUIC, WireGuard, and chained proxies.")}</p>
          </div>
          <div className="proxy-actions">
            <span className={`tools-status ${kernel?.installed ? "working" : "missing"}`}>
              {kernel?.installed ? `${t("Installed")} (v${kernel.version})` : t("Not installed")}
            </span>
            {!kernel?.installed && (
              <button type="button" className="btn primary" disabled={poolBusy !== null} onClick={() => void handleInstallKernel()}>
                {poolBusy === "kernel" ? t("Installing…") : t("Install sing-box")}
              </button>
            )}
          </div>
        </div>
        {kernel?.path && <div className="tools-panel-body"><span className="tools-mono tools-hint">{kernel.path}</span></div>}
      </section>

      <section className="tools-panel">
        <div className="tools-panel-head">
          <div>
            <h3>{t("Subscriptions")}</h3>
            <p>{t("Add subscription links to sync VLESS, VMess, Trojan, SS, Hysteria 2, or Clash YAML nodes.")}</p>
          </div>
        </div>
        <div className="tools-panel-body">
          <div className="pool-sub-form">
            <input value={subName} disabled={poolBusy !== null} placeholder={t("Subscription name (optional)")} onChange={(e) => setSubName(e.target.value)} />
            <input value={subUrl} disabled={poolBusy !== null} placeholder={t("Subscription URL")} onChange={(e) => setSubUrl(e.target.value)} />
            <button type="button" className="btn primary" disabled={poolBusy !== null || !subUrl.trim()} onClick={() => void handleAddSub()}>
              {poolBusy === "sub" ? t("Syncing…") : t("Add & sync")}
            </button>
          </div>
          <label className="proxy-choice">
            <input
              type="checkbox"
              checked={subUseLocalClash}
              disabled={poolBusy !== null}
              onChange={(e) => setSubUseLocalClash(e.target.checked)}
            />
            <span>{t("Fetch subscriptions via local Clash")}</span>
          </label>
          {subscriptions.length > 0 ? (
            <div className="pool-sub-list">
              {subscriptions.map((sub) => (
                <div className="pool-sub-row" key={sub.id}>
                  <div className="pool-sub-meta">
                    <strong>{sub.name}</strong>
                    <span className="tools-folder-tag">{t("{count} nodes", { count: sub.nodeCount })}</span>
                    {sub.userInfo?.total ? (
                      <small>{formatBytes((sub.userInfo.upload ?? 0) + (sub.userInfo.download ?? 0))} / {formatBytes(sub.userInfo.total)}</small>
                    ) : null}
                    {sub.lastError && <small className="pool-err-inline">{sub.lastError}</small>}
                  </div>
                  <div className="proxy-actions">
                    <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleRefreshSub(sub.id)}>{t("Refresh")}</button>
                    <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleDeleteSub(sub.id)}>{t("Delete")}</button>
                  </div>
                </div>
              ))}
            </div>
          ) : <p className="tools-hint">{t("No subscriptions added yet.")}</p>}
        </div>
      </section>

      <section className="tools-panel proxy-input-panel">
        <div className="tools-panel-head">
          <div>
            <h3>{t("Import proxy nodes")}</h3>
            <p>{t("Paste one or more share URIs (vless://, vmess://, trojan://, ss://, hy2://, tuic://, wg://, socks5://, http://), Base64, or Clash YAML.")}</p>
          </div>
        </div>
        <div className="tools-panel-body">
          <textarea
            rows={4}
            value={nodePaste}
            disabled={poolBusy !== null}
            spellCheck={false}
            autoComplete="off"
            placeholder={"vless://uuid@example.com:443?security=reality&pbk=...#US-Transit\nsocks5://user:pass@203.0.113.10:1080"}
            onChange={(e) => setNodePaste(e.target.value)}
          />
          <div className="tools-result-bar">
            <span />
            <button type="button" className="btn primary" disabled={poolBusy !== null || !nodePaste.trim()} onClick={() => void handleImportNodes()}>
              {poolBusy === "import" ? t("Importing nodes…") : t("Import nodes")}
            </button>
          </div>
        </div>
      </section>

      <section className="tools-panel">
        <div className="tools-panel-head">
          <div>
            <h3>{t("Node pool")} <span className="tools-folder-tag">{t("{count} nodes", { count: filteredPoolNodes.length })}</span></h3>
            <p>{t("Select nodes to check connectivity or assign to profiles in the chosen folders above.")}</p>
          </div>
          <div className="proxy-actions">
            {selectedNodeIds.length > 0 && (
              <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleCheckPoolNodes(selectedNodeIds)}>
                {poolBusy === "check" ? t("Checking…") : `${t("Check selected")} (${selectedNodeIds.length})`}
              </button>
            )}
            <button type="button" className="btn" disabled={poolBusy !== null || !filteredPoolNodes.length} onClick={() => void handleCheckPoolNodes(filteredPoolNodes.map((n) => n.id))}>
              {poolBusy === "check" ? t("Checking…") : `${t("Check all")} (${filteredPoolNodes.length})`}
            </button>
            <button type="button" className="btn primary" disabled={poolBusy !== null || !scopeReady || !filteredPoolNodes.length} onClick={() => void handleAssignPoolNodes()}>
              {poolBusy === "assign" ? t("Assigning…") : t("Assign to folders")}
            </button>
            {failedPoolNodeIds.length > 0 && (
              <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleDeleteFailedPoolNodes()}>
                {t("Delete failed")} ({failedPoolNodeIds.length})
              </button>
            )}
            {selectedNodeIds.length > 0 && (
              <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleDeletePoolNodes(selectedNodeIds)}>
                {t("Delete selected")} ({selectedNodeIds.length})
              </button>
            )}
          </div>
        </div>
        <div className="tools-panel-body">
          {poolBusy === "check" && poolCheckProgress && (
            <div className="tools-progress" role="status">
              <div className="proxy-actions">
                <strong>
                  {t("Checking nodes")}: {poolCheckProgress.completed.toLocaleString()} / {poolCheckProgress.total.toLocaleString()}
                </strong>
                <button type="button" className="btn" onClick={() => poolController.current?.abort()}>{t("Cancel")}</button>
              </div>
              <progress
                aria-label={t("Checking nodes")}
                value={poolCheckProgress.completed}
                max={Math.max(1, poolCheckProgress.total)}
              />
            </div>
          )}
          <div className="pool-controls">
            <input value={poolQuery} placeholder={t("Filter by name, host, IP, ISP, protocol, or country…")} onChange={(e) => { setPoolQuery(e.target.value); setPoolPage(0); }} />
            <select value={poolSource} onChange={(e) => { setPoolSource(e.target.value); setPoolPage(0); }}>
              <option value="all">{t("All sources")}</option>
              <option value="manual">{t("Manual nodes")}</option>
              {subscriptions.map((sub) => <option key={sub.id} value={sub.id}>{sub.name}</option>)}
            </select>
            <select value={poolRiskFilter} aria-label={t("Filter by risk level")} onChange={(e) => { setPoolRiskFilter(e.target.value as PoolRiskFilter); setPoolPage(0); }}>
              <option value="all">{t("All risks & statuses")}</option>
              <option value="working">{t("Alive only")}</option>
              <option value="low">{t("Low risk (0–34)")}</option>
              <option value="medium_or_low">{t("Low & medium risk (0–69)")}</option>
              <option value="high">{t("High risk (70–100)")}</option>
              <option value="unchecked">{t("Unchecked")}</option>
            </select>
            <select
              aria-label={t("Sort by")}
              value={`${poolSortKey}:${poolSortDir}`}
              onChange={(e) => {
                const [k, d] = e.target.value.split(":") as [PoolSortKey, SortDir];
                setPoolSortKey(k || "default");
                setPoolSortDir(d === "desc" ? "desc" : "asc");
                setPoolPage(0);
              }}
            >
              <option value="default:asc">{t("Default order")}</option>
              <option value="latency:asc">{t("Latency: low to high")}</option>
              <option value="latency:desc">{t("Latency: high to low")}</option>
              <option value="risk:asc">{t("Risk: low to high")}</option>
              <option value="risk:desc">{t("Risk: high to low")}</option>
              <option value="status:asc">{t("Status: alive first")}</option>
              <option value="country:asc">{t("Country / Exit IP")}</option>
              <option value="protocol:asc">{t("Protocol")}</option>
              <option value="name:asc">{t("Node name")}</option>
            </select>
          </div>
          <div className="pool-controls-row2">
            <select value={poolPreProxyId} aria-label={t("Transit / pre-proxy (optional chain)")} onChange={(e) => setPoolPreProxyId(e.target.value)}>
              <option value="">{t("No pre-proxy (direct to node)")}</option>
              <option value="__local_clash__">{t("Local Clash (host proxy)")}</option>
              {sortedPreProxyNodes.map((n) => <option key={n.id} value={n.id}>{formatPoolPickerOption(n, t)}</option>)}
            </select>
            <label className="proxy-choice">
              <span>{t("Profiles per node")}</span>
              <input type="number" className="pool-per-node" min={1} step={1} value={poolPerNode} onChange={(e) => setPoolPerNode(Math.max(1, Math.floor(Number(e.target.value)) || 1))} />
            </label>
            <label className="proxy-choice">
              <input
                type="checkbox"
                checked={poolIncludeRisk}
                disabled={poolBusy === "check"}
                onChange={(e) => setPoolIncludeRisk(e.target.checked)}
              />
              <span>{t("Also check IP risk")}</span>
            </label>
            {filteredPoolNodes.length > 0 && (
              <button
                type="button"
                className="btn"
                disabled={poolBusy !== null}
                onClick={() => {
                  const filteredIds = filteredPoolNodes.map((n) => n.id);
                  setSelectedNodeIds((prev) => allFilteredSelected
                    ? prev.filter((id) => !filteredIds.includes(id))
                    : [...new Set([...prev, ...filteredIds])]);
                }}
              >
                {allFilteredSelected
                  ? t("Clear selection")
                  : t("Select all filtered ({count})", { count: filteredPoolNodes.length })}
              </button>
            )}
          </div>
        </div>
        {pagedPoolNodes.items.length > 0 ? <>
          <div className="proxy-table-wrap">
            <table className="profile-table proxy-table pool-table">
              <thead>
                <tr>
                  <th className="tools-checkbox">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      onChange={(e) => {
                        const pageIds = pagedPoolNodes.items.map((n) => n.id);
                        setSelectedNodeIds((prev) => e.target.checked
                          ? [...new Set([...prev, ...pageIds])]
                          : prev.filter((id) => !pageIds.includes(id)));
                      }}
                    />
                  </th>
                  <th><button type="button" className="pool-sort-btn" onClick={() => togglePoolSort("name")}>{t("Node")}{sortIndicator(poolSortKey, "name", poolSortDir)}</button></th>
                  <th><button type="button" className="pool-sort-btn" onClick={() => togglePoolSort("protocol")}>{t("Protocol")}{sortIndicator(poolSortKey, "protocol", poolSortDir)}</button></th>
                  <th>{t("Address")}</th>
                  <th><button type="button" className="pool-sort-btn" onClick={() => togglePoolSort("status")}>{t("Connection")}{sortIndicator(poolSortKey, "status", poolSortDir)}</button></th>
                  <th><button type="button" className="pool-sort-btn" onClick={() => togglePoolSort("country")}>{t("Exit IP")}{sortIndicator(poolSortKey, "country", poolSortDir)}</button></th>
                  <th><button type="button" className="pool-sort-btn" onClick={() => togglePoolSort("risk")}>{t("Risk")}{sortIndicator(poolSortKey, "risk", poolSortDir)}</button></th>
                  <th><button type="button" className="pool-sort-btn" onClick={() => togglePoolSort("latency")}>{t("Latency")}{sortIndicator(poolSortKey, "latency", poolSortDir)}</button></th>
                  <th>{t("Actions")}</th>
                </tr>
              </thead>
              <tbody>
                {pagedPoolNodes.items.map((node) => {
                  const checked = selectedNodeIds.includes(node.id);
                  const loc = [node.lastCountry, node.lastCity].filter(Boolean).join(" · ");
                  const riskLabel = node.lastRiskLevel ? getRiskLevelLabel(t, node.lastRiskLevel) : "";
                  const ipTypeLabel = getIpTypeLabel(t, node.lastIpType);
                  const riskTitle = node.lastRiskFlags?.length ? node.lastRiskFlags.join(", ") : undefined;
                  return (
                    <tr key={node.id}>
                      <td className="tools-checkbox">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={(e) => setSelectedNodeIds((prev) => e.target.checked ? [...prev, node.id] : prev.filter((id) => id !== node.id))}
                        />
                      </td>
                      <td><strong>{node.name}</strong>{node.hasChain && <small>{t("Chain active")}</small>}</td>
                      <td><span className="tools-folder-tag">{node.type.toUpperCase()}</span></td>
                      <td className="tools-mono">{node.host}:{node.port}</td>
                      <td>
                        {node.lastStatus ? (
                          <>
                            <span className={`tools-status ${node.lastStatus}`}>{getCheckLabel(t, node.lastStatus)}</span>
                            {node.lastReason && <small>{getReasonLabel(t, node.lastReason)}</small>}
                          </>
                        ) : <span className="tools-hint">—</span>}
                      </td>
                      <td className="tools-mono">
                        {node.lastIp || "—"}
                        {loc && <small>{loc}</small>}
                        {node.lastIsp && <small className="pool-isp">{node.lastIsp}</small>}
                      </td>
                      <td>
                        {node.lastRiskScore != null && node.lastRiskLevel ? (
                          <>
                            <span className={`risk-badge ${node.lastRiskLevel}`} title={riskTitle}>{riskLabel} · {node.lastRiskScore}</span>
                            {ipTypeLabel && <small>{ipTypeLabel}</small>}
                          </>
                        ) : <span className="tools-hint">—</span>}
                      </td>
                      <td className={`tools-mono latency-cell ${latencyTierClass(node.lastLatencyMs)}`}>
                        {node.lastLatencyMs != null ? `${node.lastLatencyMs} ms` : "—"}
                      </td>
                      <td>
                        <div className="proxy-actions">
                          <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleCheckPoolNodes([node.id])}>{t("Check proxies")}</button>
                          <button type="button" className="btn" onClick={() => handleCopyNodeUri(node)}>{copiedNodeId === node.id ? t("Copied") : t("Copy link")}</button>
                          <button type="button" className="btn" disabled={poolBusy !== null} onClick={() => void handleDeletePoolNodes([node.id])}>{t("Delete")}</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pager {...pagedPoolNodes} onPage={setPoolPage} />
        </> : (
          <div className="tools-empty compact">
            <p>{poolNodes.length > 0 ? t("No proxy nodes match the current filters.") : t("No proxy nodes in your pool yet. Add a subscription or paste node links above.")}</p>
          </div>
        )}
      </section>
    </>}
  </>;

  return <div className="workspace proxy-page" hidden={!active}>
    {store ? store(tools) : <>
      <div className="tools-intro"><div><span className="tools-eyebrow">{t("PROXY TOOLS")}</span><h2>{t("Keep your profiles connected.")}</h2><p>{t("Check saved connections or replace proxies across entire folders.")}</p></div></div>
      {/* Local mode: one NobleProxy card, worded for what the page shows right now. */}
      {profilesWithoutProxy > 0
        ? <ProxyProviderOffer placement="proxies-no-proxy" missing={profilesWithoutProxy} />
        : <ProxyProviderOffer placement={hasFailedChecks ? "proxies-check-failed" : "proxies-check"} replacement={hasFailedChecks} />}
      {tools}
    </>}
  </div>;
}
