/** Runs the {@link RULES} table (plus the cross-endpoint shadow-version check) against endpoints. */

import type { EndpointRecord, Finding } from "../capture/types.js";
import { RULES, shadowUnversionedFinding } from "./rules.js";

/** Scores a single endpoint in isolation (used when `allEndpoints` isn't available/needed). */
export function scoreEndpoint(endpoint: EndpointRecord): Finding[] {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    const rationale = rule.evidence(endpoint);
    if (rationale !== null) {
      findings.push({ ruleId: rule.id, label: rule.label, rationale, severity: rule.severity });
    }
  }
  return findings;
}

/**
 * Scores an endpoint against the full catalog, adding the cross-endpoint
 * `shadow-unversioned-api` finding when applicable. This is what {@link store} should call on
 * every upsert, since the shadow-version check needs to see sibling endpoints.
 */
export function scoreEndpointInCatalog(
  endpoint: EndpointRecord,
  allEndpoints: EndpointRecord[],
): Finding[] {
  const findings = scoreEndpoint(endpoint);
  const shadow = shadowUnversionedFinding(endpoint, allEndpoints);
  if (shadow !== null) findings.push(shadow);
  return findings;
}

/** Highest severity across an endpoint's findings, or `null` if it has none -- the table's risk column. */
export function maxSeverity(findings: Finding[]): Finding["severity"] | null {
  if (findings.some((f) => f.severity === "high")) return "high";
  if (findings.some((f) => f.severity === "medium")) return "medium";
  if (findings.some((f) => f.severity === "low")) return "low";
  return null;
}
