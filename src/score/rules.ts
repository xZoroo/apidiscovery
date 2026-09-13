/**
 * The finite, human-reviewable rule table used to flag which endpoints are worth manual
 * security testing in Burp. Every rule is a small, independently testable predicate -- there is
 * no "AI decides" step here, and every finding carries the concrete evidence that fired it.
 *
 * This is the plan's heuristic-scorer rule table verbatim; see the plan doc for provenance
 * (OWASP API Security Top 10 categories, idor-hunter/idor-tester-ai id-shape heuristics).
 */

import {
  isIdSegment,
  isNumericIdSegment,
  isObjectIdOrHashSegment,
  isUuidSegment,
} from "../capture/normalizer.js";
import type { EndpointRecord, Finding, Severity } from "../capture/types.js";

const SENSITIVE_PATH_RE = /admin|internal|debug|staging|actuator|manage|console|_private/i;
const MASS_ASSIGNMENT_KEYS = new Set([
  "role",
  "isadmin",
  "admin",
  "permissions",
  "scope",
  "price",
  "balance",
  "credit",
  "verified",
  "status",
]);
const AUTH_HEADER_NAMES = new Set(["authorization", "cookie", "x-api-key"]);
const JWT_RE = /^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const WRITE_METHODS = new Set(["PUT", "PATCH", "DELETE", "POST"]);
const VERSION_SEGMENT_RE = /^v\d+$/i;

/** What a rule found: the human-readable reason, and (when there is one) the exact literal text responsible. */
export interface RuleEvidence {
  rationale: string;
  matchedValue?: string;
}

/** One row of the rule table: a predicate that inspects an endpoint and optionally raises a {@link Finding}. */
export interface Rule {
  id: string;
  label: string;
  severity: Severity;
  /** Returns evidence if the rule fires, or `null` if it doesn't. */
  evidence: (endpoint: EndpointRecord) => RuleEvidence | null;
}

function firstIdSegment(path: string, matches: (segment: string) => boolean): string | undefined {
  return path.split("/").find((segment) => segment.length > 0 && matches(segment));
}

function firstPathSegmentEvidence(
  endpoint: EndpointRecord,
  matches: (segment: string) => boolean,
  rationale: (segment: string) => string,
): RuleEvidence | null {
  const example = endpoint.exampleUrls[0];
  if (example === undefined) return null;
  const segment = firstIdSegment(new URL(example).pathname, matches);
  return segment === undefined ? null : { rationale: rationale(segment), matchedValue: segment };
}

export const RULES: Rule[] = [
  {
    id: "idor-numeric-id",
    label: "Numeric ID in path",
    severity: "high",
    evidence: (endpoint) =>
      firstPathSegmentEvidence(
        endpoint,
        isNumericIdSegment,
        (segment) =>
          `Path segment '${segment}' looks like a sequential numeric ID -- try adjacent IDs`,
      ),
  },
  {
    id: "idor-uuid",
    label: "UUID in path",
    severity: "medium",
    evidence: (endpoint) =>
      firstPathSegmentEvidence(
        endpoint,
        isUuidSegment,
        (segment) =>
          `Path segment is a UUID (${segment}) -- check for enumerable/predictable values`,
      ),
  },
  {
    id: "idor-objectid-or-hash",
    label: "ObjectId/hash in path",
    severity: "medium",
    evidence: (endpoint) =>
      firstPathSegmentEvidence(
        endpoint,
        isObjectIdOrHashSegment,
        (segment) =>
          `Path segment '${segment}' looks like an ObjectId/hash-based ID -- candidate for enumeration`,
      ),
  },
  {
    id: "sensitive-path",
    label: "Sensitive path",
    severity: "high",
    evidence: (endpoint) => {
      const match = SENSITIVE_PATH_RE.exec(endpoint.templatedPath);
      return match === null
        ? null
        : {
            rationale: `Path contains '${match[0]}' -- likely internal/admin surface`,
            matchedValue: match[0],
          };
    },
  },
  {
    id: "auth-bearing",
    label: "Auth header present",
    severity: "medium",
    evidence: (endpoint) =>
      endpoint.hasAuthHeader
        ? { rationale: "Auth header present -- retest with a different/lower-privileged account" }
        : null,
  },
  {
    id: "state-changing-on-object",
    label: "State-changing call on an object ID",
    severity: "high",
    evidence: (endpoint) => {
      if (!WRITE_METHODS.has(endpoint.method.toUpperCase())) return null;
      const hasIdSegment = endpoint.templatedPath.split("/").includes("{id}");
      return hasIdSegment
        ? {
            rationale: `State-changing ${endpoint.method} targets an object by ID -- check ownership/role enforcement (BOLA/BFLA)`,
            matchedValue: endpoint.method,
          }
        : null;
    },
  },
  {
    id: "mass-assignment-candidate",
    label: "Sensitive body field",
    severity: "high",
    evidence: (endpoint) => {
      const hit = endpoint.bodyKeysSeen.find((key) => MASS_ASSIGNMENT_KEYS.has(key.toLowerCase()));
      return hit === undefined
        ? null
        : {
            rationale: `Body includes sensitive field '${hit}' -- check for mass assignment / BOPLA`,
            matchedValue: hit,
          };
    },
  },
  {
    id: "graphql-endpoint",
    label: "GraphQL endpoint",
    severity: "medium",
    evidence: (endpoint) =>
      endpoint.templatedPath.endsWith("/graphql")
        ? { rationale: "GraphQL endpoint -- check introspection exposure and field-level authz" }
        : null,
  },
  {
    id: "jwt-present",
    label: "JWT-shaped token observed",
    severity: "low",
    evidence: (endpoint) =>
      endpoint.jwtObserved
        ? { rationale: "JWT-shaped token observed -- decode and check alg/claims/expiry" }
        : null,
  },
  {
    id: "doc-path-found",
    label: "API doc/introspection path found",
    severity: "high",
    evidence: (endpoint) =>
      endpoint.sources.includes("probe")
        ? { rationale: "Well-known API doc/introspection path responded -- review directly" }
        : null,
  },
];

/**
 * Catalog-wide rule: an endpoint whose path has no `/vN/` version segment while a sibling
 * endpoint on the same host does is flagged as a possible shadow/older API version. This is a
 * cross-endpoint check, so it runs separately from {@link RULES} (which only ever see one
 * endpoint at a time) over the full endpoint list.
 */
export function shadowUnversionedFinding(
  endpoint: EndpointRecord,
  allEndpoints: EndpointRecord[],
): Finding | null {
  const segments = endpoint.templatedPath.split("/");
  if (segments.some((segment) => VERSION_SEGMENT_RE.test(segment))) return null;

  const hasVersionedSibling = allEndpoints.some(
    (other) =>
      other.host === endpoint.host &&
      other.key !== endpoint.key &&
      other.templatedPath.split("/").some((segment) => VERSION_SEGMENT_RE.test(segment)),
  );
  if (!hasVersionedSibling) return null;

  return {
    ruleId: "shadow-unversioned-api",
    label: "Unversioned API",
    rationale: "No version segment unlike sibling endpoints -- possible shadow/older API version",
    severity: "low",
  };
}

export function hasAuthHeaderName(name: string): boolean {
  return AUTH_HEADER_NAMES.has(name.toLowerCase());
}

export function looksLikeJwt(value: string): boolean {
  return JWT_RE.test(value);
}

export function isMassAssignmentKey(key: string): boolean {
  return MASS_ASSIGNMENT_KEYS.has(key.toLowerCase());
}

// Re-exported so callers building EndpointRecord.bodyKeysSeen can reuse the same id-shape check
// used above without importing normalizer.ts directly in every consumer.
export { isIdSegment };
