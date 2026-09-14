/**
 * Groups the flat endpoint catalog into a Burp-style Site Map: a tree keyed by host, then by each
 * templated path segment, so a large catalog can be browsed by structure instead of only scanned
 * as one flat table. Pure and DOM-free -- src/ui/siteMapView.ts renders whatever this builds.
 */

import type { EndpointRecord, Severity } from "../capture/types.js";

export interface SiteMapNode {
  /** This node's own path segment (or the host string, for a top-level node). */
  segment: string;
  /** Every endpoint whose templated path terminates exactly at this node (may be several methods). */
  endpoints: EndpointRecord[];
  children: Map<string, SiteMapNode>;
}

function createNode(segment: string): SiteMapNode {
  return { segment, endpoints: [], children: new Map() };
}

/** Builds one root {@link SiteMapNode} per distinct host, keyed by host string. */
export function buildSiteMap(endpoints: EndpointRecord[]): Map<string, SiteMapNode> {
  const hosts = new Map<string, SiteMapNode>();
  for (const endpoint of endpoints) {
    let hostNode = hosts.get(endpoint.host);
    if (hostNode === undefined) {
      hostNode = createNode(endpoint.host);
      hosts.set(endpoint.host, hostNode);
    }
    const segments = endpoint.templatedPath.split("/").filter((s) => s.length > 0);
    let current = hostNode;
    for (const segment of segments) {
      let child = current.children.get(segment);
      if (child === undefined) {
        child = createNode(segment);
        current.children.set(segment, child);
      }
      current = child;
    }
    current.endpoints.push(endpoint);
  }
  return hosts;
}

const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3 };

/** The highest finding severity anywhere in this node's own endpoints or any descendant's. */
export function maxSeverityInSubtree(node: SiteMapNode): Severity | null {
  let best: Severity | null = null;
  for (const endpoint of node.endpoints) {
    for (const finding of endpoint.findings) {
      if (best === null || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[best]) {
        best = finding.severity;
      }
    }
  }
  for (const child of node.children.values()) {
    const childBest = maxSeverityInSubtree(child);
    if (childBest !== null && (best === null || SEVERITY_RANK[childBest] > SEVERITY_RANK[best])) {
      best = childBest;
    }
  }
  return best;
}

/** Total endpoint count (across all methods) at this node and every descendant. */
export function countEndpointsInSubtree(node: SiteMapNode): number {
  let count = node.endpoints.length;
  for (const child of node.children.values()) {
    count += countEndpointsInSubtree(child);
  }
  return count;
}
