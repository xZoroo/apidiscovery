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

const rowsEl = document.querySelector<HTMLTableSectionElement>("#endpoint-rows")!;
const detailEl = document.querySelector<HTMLElement>("#detail")!;
const openDashboardEl = document.querySelector<HTMLButtonElement>("#open-dashboard")!;

async function onSelectEndpoint(endpoint: EndpointRecord): Promise<void> {
  const requests = await getRequestsByIds(endpoint.sampleRequestIds);
  renderDetail(detailEl, endpoint, requests);
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
  renderEndpointRows(rowsEl, visible, (endpoint) => {
    void onSelectEndpoint(endpoint);
  });
}

openDashboardEl.addEventListener("click", () => {
  void browser.tabs.create({ url: browser.runtime.getURL("/dashboard.html") });
});

browser.runtime.onMessage.addListener((message: RuntimeMessage) => {
  if (message.type === "endpoint-updated") void refresh();
});

void refresh();
