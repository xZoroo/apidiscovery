/** Shared data model for captured requests, deduplicated endpoints, and security findings. */

/** How a {@link CapturedRequest} was observed. */
export type CaptureSource = "fetch" | "xhr" | "websocket" | "webRequest" | "js-mined" | "probe";

/** Severity of a heuristic {@link Finding}. */
export type Severity = "high" | "medium" | "low";

/** A single header pair, kept as a plain array to survive structured-clone/postMessage transit. */
export interface HeaderEntry {
  name: string;
  value: string;
}

/**
 * One observed request/response, as seen by any capture path (MAIN-world patch, webRequest
 * fallback, JS miner, or the opt-in doc-path probe).
 *
 * Body fields are optional and size-capped in the capturing code (see `MAX_BODY_BYTES` in
 * normalizer.ts) because not every source can see bodies (webRequest never can) and because
 * large payloads must not be stored in full.
 */
export interface CapturedRequest {
  id: string;
  ts: number;
  tabId: number | null;
  method: string;
  url: string;
  host: string;
  path: string;
  requestHeaders?: HeaderEntry[] | undefined;
  requestBody?: string | undefined;
  responseStatus?: number | undefined;
  responseHeaders?: HeaderEntry[] | undefined;
  responseBody?: string | undefined;
  source: CaptureSource;
}

/**
 * One heuristic flag raised against an {@link EndpointRecord}, with a human-readable reason.
 *
 * `matchedValue`, when present, is the exact literal text (a path segment, a body field name, a
 * path keyword) that caused the rule to fire -- structured data, not scraped from `rationale`'s
 * prose, so the UI can highlight precisely what was flagged and why without guessing.
 */
export interface Finding {
  ruleId: string;
  label: string;
  rationale: string;
  severity: Severity;
  matchedValue?: string | undefined;
}

/**
 * A deduplicated group of {@link CapturedRequest}s that share the same method and templated
 * path (e.g. every `/users/1`, `/users/2`, ... collapses into one `/users/{id}` record).
 */
export interface EndpointRecord {
  key: string;
  method: string;
  host: string;
  templatedPath: string;
  exampleUrls: string[];
  firstSeen: number;
  lastSeen: number;
  seenCount: number;
  sources: CaptureSource[];
  sampleRequestIds: string[];
  hasAuthHeader: boolean;
  bodyKeysSeen: string[];
  /** True if any sample's headers or body contained a JWT-shaped (`xxx.yyy.zzz`) token. */
  jwtObserved: boolean;
  findings: Finding[];
}

/** Result of the opt-in, current-origin-only well-known API-doc path probe. */
export interface ProbeResult {
  origin: string;
  path: string;
  status: number;
  looksLikeApiDoc: boolean;
  ts: number;
}

/** A secret-shaped string found by the JS miner. Kept separate from {@link EndpointRecord} -- a secret isn't an endpoint. */
export interface StoredSecret {
  id: string;
  label: string;
  match: string;
  sourceFile: string;
  ts: number;
}
