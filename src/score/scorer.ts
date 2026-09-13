/** Runs the {@link RULES} table (plus the cross-endpoint checks) against endpoints. */

import type { EndpointRecord, Finding } from "../capture/types.js";
import { inconsistentAuthFinding, RULES, shadowUnversionedFinding } from "./rules.js";

/** Scores a single endpoint in isolation (used when `allEndpoints` isn't available/needed). */
export function scoreEndpoint(endpoint: EndpointRecord): Finding[] {
  const findings: Finding[] = [];
  for (const rule of RULES) {
    const evidence = rule.evidence(endpoint);
    if (evidence !== null) {
      findings.push({
        ruleId: rule.id,
        label: rule.label,
        rationale: evidence.rationale,
        severity: rule.severity,
        owaspCategory: rule.owaspCategory,
        ...(evidence.matchedValue !== undefined ? { matchedValue: evidence.matchedValue } : {}),
      });
    }
  }
  return findings;
}

/**
 * Scores an endpoint against the full catalog, adding the cross-endpoint `shadow-unversioned-api`
 * and `inconsistent-auth` findings when applicable. This is what {@link store} should call on
 * every upsert, since these checks need to see sibling endpoints.
 */
export function scoreEndpointInCatalog(
  endpoint: EndpointRecord,
  allEndpoints: EndpointRecord[],
): Finding[] {
  const findings = scoreEndpoint(endpoint);
  const shadow = shadowUnversionedFinding(endpoint, allEndpoints);
  if (shadow !== null) findings.push(shadow);
  const inconsistentAuth = inconsistentAuthFinding(endpoint, allEndpoints);
  if (inconsistentAuth !== null) findings.push(inconsistentAuth);
  return findings;
}

/** Highest severity across an endpoint's findings, or `null` if it has none -- the table's risk column. */
export function maxSeverity(findings: Finding[]): Finding["severity"] | null {
  if (findings.some((f) => f.severity === "high")) return "high";
  if (findings.some((f) => f.severity === "medium")) return "medium";
  if (findings.some((f) => f.severity === "low")) return "low";
  return null;
}
