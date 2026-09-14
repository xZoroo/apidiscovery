/**
 * Renders the Site Map built by src/ui/siteMap.ts: one collapsible `<details>` tree per host,
 * branching by path segment, with a severity dot rolled up from every descendant so you can see
 * which branch to drill into without expanding everything. Native `<details>`/`<summary>` gives
 * keyboard-accessible expand/collapse for free, no custom toggle state needed.
 */

import { badge, methodLabel, SEVERITY_STYLES, type SelectHandler } from "./renderTable.js";
import {
  buildSiteMap,
  countEndpointsInSubtree,
  maxSeverityInSubtree,
  type SiteMapNode,
} from "./siteMap.js";
import type { EndpointRecord, Severity } from "../capture/types.js";

function severityDot(severity: Severity): HTMLSpanElement {
  const dot = document.createElement("span");
  dot.className = `inline-block h-2 w-2 shrink-0 rounded-full ${SEVERITY_STYLES[severity].icon.replace("text-", "bg-")}`;
  dot.setAttribute("aria-hidden", "true");
  return dot;
}

function buildEndpointRow(endpoint: EndpointRecord, onSelect: SelectHandler): HTMLButtonElement {
  const row = document.createElement("button");
  row.type = "button";
  row.className =
    "flex w-full items-center gap-2 rounded px-2 py-1 text-left hover:bg-page focus:outline-none focus:ring-1 focus:ring-brand";
  row.appendChild(methodLabel(endpoint.method));

  const severities = endpoint.findings.map((f) => f.severity);
  const worst = severities.includes("high")
    ? "high"
    : severities.includes("medium")
      ? "medium"
      : severities.includes("low")
        ? "low"
        : undefined;
  if (worst !== undefined) {
    row.appendChild(badge(String(endpoint.findings.length), SEVERITY_STYLES[worst].badge));
  }

  const meta = document.createElement("span");
  meta.className = "text-xs text-ink-muted";
  meta.textContent = `seen ${String(endpoint.seenCount)}×`;
  row.appendChild(meta);

  row.addEventListener("click", () => onSelect(endpoint));
  return row;
}

/**
 * Every node -- whether it's a folder with children, a leaf with one endpoint, or both -- renders
 * the same way: a `<details>` labeled with its own segment name, severity dot, and descendant
 * count, expanding to its own endpoint row(s) followed by its children. Rendering leaves
 * differently (skipping the label, always showing the row) previously made a lone endpoint like
 * `/health` look like a stray, unlabeled sibling of whatever folder happened to sort next to it.
 */
function buildNode(node: SiteMapNode, onSelect: SelectHandler, depth: number): HTMLElement {
  const details = document.createElement("details");
  details.open = depth === 0;

  const summary = document.createElement("summary");
  summary.className =
    "flex cursor-pointer list-none items-center gap-2 rounded px-2 py-1 hover:bg-page";
  const severity = maxSeverityInSubtree(node);
  if (severity !== null) summary.appendChild(severityDot(severity));
  const label = document.createElement("span");
  label.className = "font-mono text-sm text-ink";
  label.textContent = node.segment;
  summary.appendChild(label);
  const count = document.createElement("span");
  count.className = "text-xs text-ink-muted";
  count.textContent = `(${String(countEndpointsInSubtree(node))})`;
  summary.appendChild(count);
  details.appendChild(summary);

  const body = document.createElement("div");
  body.className = "ml-4 space-y-0.5 border-l border-line py-1 pl-2";
  for (const endpoint of node.endpoints) {
    body.appendChild(buildEndpointRow(endpoint, onSelect));
  }
  const sortedChildren = [...node.children.values()].sort((a, b) =>
    a.segment.localeCompare(b.segment),
  );
  for (const child of sortedChildren) {
    body.appendChild(buildNode(child, onSelect, depth + 1));
  }
  details.appendChild(body);
  return details;
}

/** Renders the full Site Map (all hosts) into `container`, replacing any existing content. */
export function renderSiteMap(
  container: HTMLElement,
  endpoints: EndpointRecord[],
  onSelect: SelectHandler,
): void {
  container.replaceChildren();
  const hosts = buildSiteMap(endpoints);
  if (hosts.size === 0) {
    const empty = document.createElement("p");
    empty.className = "px-3 py-6 text-center text-sm text-ink-muted";
    empty.textContent =
      "No endpoints match the current filters. Browse the target site to see more.";
    container.appendChild(empty);
    return;
  }

  const list = document.createElement("div");
  list.className = "space-y-1 p-2";
  const sortedHosts = [...hosts.entries()].sort(([a], [b]) => a.localeCompare(b));
  for (const [host, node] of sortedHosts) {
    // The host node itself is rendered like any other tree node, just always starting expanded
    // (depth 0) with the host string as its label.
    list.appendChild(buildNode({ ...node, segment: host }, onSelect, 0));
  }
  container.appendChild(list);
}
