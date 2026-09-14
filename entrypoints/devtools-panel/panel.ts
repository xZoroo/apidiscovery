/**
 * DevTools panel logic: the thin, tab-scoped convenience shortcut described in the plan --
 * table + row-expand only, filtered to the inspected tab, with a link out to the full dashboard
 * for exports and the probe.
 */

import "../../assets/tailwind.css";
import { getEndpoints, getRequestsByIds, getRequestsByTabId } from "../../src/capture/store.js";
import type { EndpointRecord } from "../../src/capture/types.js";
import type { RuntimeMessage } from "../../src/messaging.js";
import { renderDetail, renderEndpointRows } from "../../src/ui/renderTable.js";
import { sortEndpoints } from "../../src/ui/tableState.js";

const rowsEl = document.querySelector<HTMLTableSectionElement>("#endpoint-rows")!;
const detailEl = document.querySelector<HTMLElement>("#detail")!;
const openDashboardEl = document.querySelector<HTMLButtonElement>("#open-dashboard")!;

// No toggle here by design (this panel stays a thin shortcut) -- it just mirrors whatever the
// dashboard's theme toggle last chose, so the two surfaces never look mismatched.
function applyStoredTheme(): void {
  const stored = localStorage.getItem("theme");
  const isDark =
    stored === "dark" || (stored === null && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", isDark);
}
applyStoredTheme();
window.addEventListener("storage", (event) => {
  if (event.key === "theme") applyStoredTheme();
});

async function onSelectEndpoint(endpoint: EndpointRecord, focusRuleId?: string): Promise<void> {
  const requests = await getRequestsByIds(endpoint.sampleRequestIds);
  renderDetail(detailEl, endpoint, requests, focusRuleId);
}

async function refresh(): Promise<void> {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  const [allEndpoints, tabRequests] = await Promise.all([
    getEndpoints(),
    getRequestsByTabId(tabId),
  ]);
  const tabRequestIds = new Set(tabRequests.map((r) => r.id));
  const visible = allEndpoints.filter((endpoint) =>
    endpoint.sampleRequestIds.some((id) => tabRequestIds.has(id)),
  );
  // Highest-risk first by default -- this panel has no sort-header UI (kept thin), but the
  // reviewer's attention should still go to the riskiest endpoint on this tab first.
  renderEndpointRows(rowsEl, sortEndpoints(visible, "risk", "desc"), (endpoint, focusRuleId) => {
    void onSelectEndpoint(endpoint, focusRuleId);
  });
}

openDashboardEl.addEventListener("click", () => {
  void browser.tabs.create({ url: browser.runtime.getURL("/dashboard.html") });
});

browser.runtime.onMessage.addListener((message: RuntimeMessage) => {
  if (message.type === "endpoint-updated") void refresh();
});

void refresh();
