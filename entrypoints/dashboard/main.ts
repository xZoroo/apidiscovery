/**
 * Dashboard logic: reads the endpoint/secret catalog from IndexedDB directly (no round-trip
 * through the background service worker), renders the table, wires search/filter, the two
 * exports, "clear all", and the opt-in Active Probe section.
 */

import { splitUrl } from "../../src/capture/normalizer.js";
import {
  clearAll,
  getEndpoints,
  getRequestsByIds,
  getSecrets,
  upsertCapture,
} from "../../src/capture/store.js";
import type { EndpointRecord, ProbeResult } from "../../src/capture/types.js";
import { toCurl, toEndpointListLine } from "../../src/export/curl.js";
import { buildHar } from "../../src/export/har.js";
import type { RuntimeMessage } from "../../src/messaging.js";
import { probeOrigin } from "../../src/probe/prober.js";
import { renderDetail, renderEndpointRows, renderSecretRows } from "../../src/ui/renderTable.js";

const els = {
  rows: document.querySelector<HTMLTableSectionElement>("#endpoint-rows")!,
  detail: document.querySelector<HTMLElement>("#detail")!,
  secretRows: document.querySelector<HTMLTableSectionElement>("#secret-rows")!,
  search: document.querySelector<HTMLInputElement>("#search")!,
  methodFilter: document.querySelector<HTMLSelectElement>("#method-filter")!,
  severityFilter: document.querySelector<HTMLSelectElement>("#severity-filter")!,
  exportHar: document.querySelector<HTMLButtonElement>("#export-har")!,
  exportList: document.querySelector<HTMLButtonElement>("#export-list")!,
  clearAll: document.querySelector<HTMLButtonElement>("#clear-all")!,
  probeOrigin: document.querySelector<HTMLElement>("#probe-origin")!,
  probeRun: document.querySelector<HTMLButtonElement>("#probe-run")!,
  probeStatus: document.querySelector<HTMLElement>("#probe-status")!,
};

let allEndpoints: EndpointRecord[] = [];

function matchesFilters(endpoint: EndpointRecord): boolean {
  const query = els.search.value.trim().toLowerCase();
  if (
    query.length > 0 &&
    !`${endpoint.host}${endpoint.templatedPath}`.toLowerCase().includes(query)
  ) {
    return false;
  }
  const method = els.methodFilter.value;
  if (method.length > 0 && endpoint.method !== method) return false;
  const severity = els.severityFilter.value;
  if (severity.length > 0 && !endpoint.findings.some((f) => f.severity === severity)) return false;
  return true;
}

async function onSelectEndpoint(endpoint: EndpointRecord): Promise<void> {
  const requests = await getRequestsByIds(endpoint.sampleRequestIds);
  renderDetail(els.detail, endpoint, requests);
}

function renderTable(): void {
  const visible = allEndpoints.filter(matchesFilters);
  renderEndpointRows(els.rows, visible, (endpoint) => {
    void onSelectEndpoint(endpoint);
  });
}

function populateMethodFilter(): void {
  const methods = [...new Set(allEndpoints.map((e) => e.method))].sort();
  const previousValue = els.methodFilter.value;
  els.methodFilter.replaceChildren(
    Object.assign(document.createElement("option"), { value: "", textContent: "All methods" }),
    ...methods.map((method) =>
      Object.assign(document.createElement("option"), { value: method, textContent: method }),
    ),
  );
  els.methodFilter.value = methods.includes(previousValue) ? previousValue : "";
}

async function refresh(): Promise<void> {
  allEndpoints = await getEndpoints();
  populateMethodFilter();
  renderTable();
  renderSecretRows(els.secretRows, await getSecrets());
}

function downloadBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

function downloadJson(filename: string, data: object): void {
  downloadBlob(filename, new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
}

function downloadText(filename: string, text: string): void {
  downloadBlob(filename, new Blob([text], { type: "text/plain" }));
}

async function exportHar(): Promise<void> {
  const visible = allEndpoints.filter(matchesFilters);
  const requestIds = visible.flatMap((e) => e.sampleRequestIds);
  const requests = await getRequestsByIds(requestIds);
  downloadJson("api-discovery.har", buildHar(requests));
}

async function exportEndpointList(): Promise<void> {
  const visible = allEndpoints.filter(matchesFilters);
  const lines = visible.map(toEndpointListLine);

  const requestIds = visible.flatMap((e) => e.sampleRequestIds);
  const requests = await getRequestsByIds(requestIds);
  const curlLines = requests.map(toCurl);

  downloadText(
    "api-discovery-endpoints.txt",
    [...lines, "", "# curl commands", ...curlLines].join("\n"),
  );
}

async function recordProbeHit(hit: ProbeResult): Promise<void> {
  const url = new URL(hit.path, hit.origin).toString();
  const { host, path } = splitUrl(url);
  await upsertCapture({
    id: crypto.randomUUID(),
    ts: hit.ts,
    tabId: null,
    method: "GET",
    url,
    host,
    path,
    responseStatus: hit.status,
    source: "probe",
  });
}

async function runProbe(origin: string): Promise<void> {
  els.probeRun.disabled = true;
  els.probeStatus.textContent = "Probing...";
  try {
    const results = await probeOrigin(origin);
    const hits = results.filter((r) => r.looksLikeApiDoc);
    await Promise.all(hits.map(recordProbeHit));
    els.probeStatus.textContent = `Checked ${String(results.length)} paths, ${String(hits.length)} hit(s).`;
    await refresh();
  } finally {
    els.probeRun.disabled = false;
  }
}

function setUpProbeSection(): void {
  const origin = new URLSearchParams(window.location.search).get("origin");
  if (origin === null) {
    els.probeOrigin.textContent = "No origin known -- open the dashboard from the toolbar icon.";
    els.probeRun.disabled = true;
    return;
  }
  els.probeOrigin.textContent = origin;
  els.probeRun.addEventListener("click", () => {
    void runProbe(origin);
  });
}

function setUpToolbar(): void {
  els.search.addEventListener("input", renderTable);
  els.methodFilter.addEventListener("change", renderTable);
  els.severityFilter.addEventListener("change", renderTable);
  els.exportHar.addEventListener("click", () => {
    void exportHar();
  });
  els.exportList.addEventListener("click", () => {
    void exportEndpointList();
  });
  els.clearAll.addEventListener("click", () => {
    void clearAll().then(refresh);
  });
}

function setUpLiveUpdates(): void {
  browser.runtime.onMessage.addListener((message: RuntimeMessage) => {
    if (message.type === "endpoint-updated" || message.type === "secrets-updated") {
      void refresh();
    }
  });
}

setUpToolbar();
setUpProbeSection();
setUpLiveUpdates();
void refresh();
