/**
 * Pure sort/filter logic for the endpoint table -- kept separate from renderTable.ts's DOM
 * construction so it's directly unit-testable without a browser environment.
 */

import { maxSeverity } from "../score/scorer.js";
import type { EndpointRecord } from "../capture/types.js";

export type SortKey = "method" | "host" | "path" | "risk" | "seen" | "source";
export type SortDirection = "asc" | "desc";

const SEVERITY_RANK: Record<"high" | "medium" | "low", number> = { high: 3, medium: 2, low: 1 };

function riskRank(endpoint: EndpointRecord): number {
  const severity = maxSeverity(endpoint.findings);
  return severity === null ? 0 : SEVERITY_RANK[severity];
}

function compareBy(key: SortKey, a: EndpointRecord, b: EndpointRecord): number {
  if (key === "method") return a.method.localeCompare(b.method);
  if (key === "host") return a.host.localeCompare(b.host);
  if (key === "path") return a.templatedPath.localeCompare(b.templatedPath);
  if (key === "risk") return riskRank(a) - riskRank(b);
  if (key === "seen") return a.seenCount - b.seenCount;
  return a.sources.join(",").localeCompare(b.sources.join(","));
}

/** Sorts a copy of `endpoints` by `key`; ties keep their original relative order (stable sort). */
export function sortEndpoints(
  endpoints: EndpointRecord[],
  key: SortKey,
  direction: SortDirection,
): EndpointRecord[] {
  const sorted = [...endpoints].sort((a, b) => compareBy(key, a, b));
  return direction === "asc" ? sorted : sorted.reverse();
}

/**
 * Broad substring search across everything a reviewer might plausibly search for: not just
 * host/path, but method, capture source, body field names, and each finding's label/rationale/
 * OWASP category -- so typing "mass assignment" or "API5" or "role" all find the right rows.
 */
export function matchesQuery(endpoint: EndpointRecord, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (needle.length === 0) return true;
  const haystacks = [
    endpoint.host,
    endpoint.templatedPath,
    endpoint.method,
    ...endpoint.sources,
    ...endpoint.bodyKeysSeen,
    ...endpoint.findings.flatMap((f) => [f.label, f.rationale, f.owaspCategory ?? ""]),
  ];
  return haystacks.some((h) => h.toLowerCase().includes(needle));
}

/** True if `endpoint` has at least one finding tagged with the given OWASP category (empty category matches everything). */
export function matchesOwaspCategory(endpoint: EndpointRecord, category: string): boolean {
  if (category.length === 0) return true;
  return endpoint.findings.some((f) => f.owaspCategory === category);
}

/** Every distinct OWASP category present in the catalog, sorted -- populates the filter dropdown. */
export function distinctOwaspCategories(endpoints: EndpointRecord[]): string[] {
  const categories = new Set<string>();
  for (const endpoint of endpoints) {
    for (const finding of endpoint.findings) {
      if (finding.owaspCategory !== undefined) categories.add(finding.owaspCategory);
    }
  }
  return [...categories].sort();
}
