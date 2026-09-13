/**
 * The finite, human-reviewable rule table used to flag which endpoints are worth manual
 * security testing in Burp. Every rule is a small, independently testable predicate -- there is
 * no "AI decides" step here, and every finding carries the concrete evidence that fired it.
 *
 * Each rule also carries an `owaspCategory` (OWASP API Security Top 10, 2023 edition) so a
 * reviewer can filter/group the catalog the way a web-app assessment report is structured.
 *
 * This is the plan's heuristic-scorer rule table, extended with OWASP tagging plus a few
 * additional passive checks; see the plan doc for provenance (OWASP API Security Top 10
 * categories, idor-hunter/idor-tester-ai id-shape heuristics).
 */

import {
  isIdSegment,
  isNumericIdSegment,
  isObjectIdOrHashSegment,
  isUuidSegment,
} from "../capture/normalizer.js";
import type { EndpointRecord, Finding, HeaderEntry, Severity } from "../capture/types.js";

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

const OWASP = {
  bola: "API1:2023 Broken Object Level Authorization",
  brokenAuth: "API2:2023 Broken Authentication",
  bopla: "API3:2023 Broken Object Property Level Authorization",
  bfla: "API5:2023 Broken Function Level Authorization",
  misconfig: "API8:2023 Security Misconfiguration",
  inventory: "API9:2023 Improper Inventory Management",
} as const;

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
  owaspCategory: string;
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
    owaspCategory: OWASP.bola,
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
    owaspCategory: OWASP.bola,
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
    owaspCategory: OWASP.bola,
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
    owaspCategory: OWASP.inventory,
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
    owaspCategory: OWASP.brokenAuth,
    evidence: (endpoint) =>
      endpoint.hasAuthHeader
        ? { rationale: "Auth header present -- retest with a different/lower-privileged account" }
        : null,
  },
  {
    id: "state-changing-on-object",
    label: "State-changing call on an object ID",
    severity: "high",
    owaspCategory: OWASP.bfla,
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
    owaspCategory: OWASP.bopla,
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
    owaspCategory: OWASP.inventory,
    evidence: (endpoint) =>
      endpoint.templatedPath.endsWith("/graphql")
        ? { rationale: "GraphQL endpoint -- check introspection exposure and field-level authz" }
        : null,
  },
  {
    id: "jwt-present",
    label: "JWT-shaped token observed",
    severity: "low",
    owaspCategory: OWASP.brokenAuth,
    evidence: (endpoint) =>
      endpoint.jwtObserved
        ? { rationale: "JWT-shaped token observed -- decode and check alg/claims/expiry" }
        : null,
  },
  {
    id: "jwt-alg-none",
    label: "JWT accepts alg=none",
    severity: "high",
    owaspCategory: OWASP.brokenAuth,
    evidence: (endpoint) =>
      endpoint.jwtAlgNone
        ? {
            rationale:
              'A captured JWT decodes to "alg":"none" -- test whether the server accepts an unsigned token',
            matchedValue: "none",
          }
        : null,
  },
  {
    id: "cors-wildcard-credentials",
    label: "CORS wildcard with credentials",
    severity: "high",
    owaspCategory: OWASP.misconfig,
    evidence: (endpoint) =>
      endpoint.corsWildcardWithCredentials
        ? {
            rationale:
              "Response allows any origin (Access-Control-Allow-Origin: *) while allowing credentials -- a critical CORS misconfiguration",
            matchedValue: "*",
          }
        : null,
  },
  {
    id: "doc-path-found",
    label: "API doc/introspection path found",
    severity: "high",
    owaspCategory: OWASP.inventory,
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
    owaspCategory: OWASP.inventory,
  };
}

/**
 * Catalog-wide rule: an endpoint with no auth header while another method on the exact same
 * templated path DOES carry one (e.g. `GET /admin/users/{id}` is authenticated but
 * `DELETE /admin/users/{id}` isn't) -- a classic function-level-authorization smell worth
 * testing by hand.
 */
export function inconsistentAuthFinding(
  endpoint: EndpointRecord,
  allEndpoints: EndpointRecord[],
): Finding | null {
  if (endpoint.hasAuthHeader) return null;

  const hasAuthedSibling = allEndpoints.some(
    (other) =>
      other.host === endpoint.host &&
      other.templatedPath === endpoint.templatedPath &&
      other.key !== endpoint.key &&
      other.hasAuthHeader,
  );
  if (!hasAuthedSibling) return null;

  return {
    ruleId: "inconsistent-auth",
    label: "Inconsistent authorization",
    rationale: `${endpoint.method} has no auth header while another method on the same path does -- check function-level authorization`,
    severity: "high",
    matchedValue: endpoint.method,
    owaspCategory: OWASP.bfla,
  };
}

export function hasAuthHeaderName(name: string): boolean {
  return AUTH_HEADER_NAMES.has(name.toLowerCase());
}

export function looksLikeJwt(value: string): boolean {
  return JWT_RE.test(value);
}

const JWT_CANDIDATE_RE = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;

/** Finds JWT-shaped substrings within a larger string (a header value, a JSON body, ...). */
export function findJwtCandidates(text: string): string[] {
  const candidates = text.match(JWT_CANDIDATE_RE) ?? [];
  return candidates.filter((candidate) => looksLikeJwt(candidate));
}

export function isMassAssignmentKey(key: string): boolean {
  return MASS_ASSIGNMENT_KEYS.has(key.toLowerCase());
}

function headerValue(headers: HeaderEntry[] | undefined, name: string): string | undefined {
  return headers?.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
}

/** True if a response pairs an open CORS origin with credentials allowed -- a critical misconfiguration. */
export function hasCorsWildcardWithCredentials(headers: HeaderEntry[] | undefined): boolean {
  const origin = headerValue(headers, "access-control-allow-origin");
  const credentials = headerValue(headers, "access-control-allow-credentials");
  return origin === "*" && credentials?.toLowerCase() === "true";
}

function base64UrlDecode(segment: string): string {
  const base64 = segment.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return atob(padded);
}

/**
 * Decodes a JWT's header and payload for display/inspection. Never verifies the signature --
 * this is a passive recon aid, not a JWT validator, and the token is attacker/target-controlled
 * input either way.
 */
export function decodeJwtParts(token: string): { header: unknown; payload: unknown } | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header: unknown = JSON.parse(base64UrlDecode(parts[0] ?? ""));
    const payload: unknown = JSON.parse(base64UrlDecode(parts[1] ?? ""));
    return { header, payload };
  } catch {
    return null;
  }
}

/** Extracts `header.alg` from a JWT, if it decodes cleanly and `alg` is a string. */
export function jwtHeaderAlg(token: string): string | undefined {
  const decoded = decodeJwtParts(token);
  if (decoded === null || typeof decoded.header !== "object" || decoded.header === null) {
    return undefined;
  }
  const alg = (decoded.header as Record<string, unknown>)["alg"];
  return typeof alg === "string" ? alg : undefined;
}

// Re-exported so callers building EndpointRecord.bodyKeysSeen can reuse the same id-shape check
// used above without importing normalizer.ts directly in every consumer.
export { isIdSegment };
