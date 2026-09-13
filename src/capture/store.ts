/**
 * IndexedDB-backed persistence for captured requests and their deduplicated endpoint records.
 *
 * MV3 service workers keep IndexedDB access (unlike `localStorage`), so this is written directly
 * against IndexedDB rather than an offscreen document -- offscreen documents are Chrome-only and
 * would break the Firefox build. The background service worker writes on every capture; the
 * dashboard and devtools panel read the same database directly instead of round-tripping through
 * a service worker that may have been killed for idling.
 */

import { openDB, type DBSchema, type IDBPDatabase } from "idb";
import {
  findJwtCandidates,
  hasAuthHeaderName,
  hasCorsWildcardWithCredentials,
  jwtHeaderAlg,
} from "../score/rules.js";
import { scoreEndpointInCatalog } from "../score/scorer.js";
import { endpointKey, splitUrl, templatePath, truncateBody } from "./normalizer.js";
import type { CapturedRequest, EndpointRecord, StoredSecret } from "./types.js";

const DB_NAME = "apidiscovery";
const DB_VERSION = 1;
const MAX_EXAMPLE_URLS = 5;
const MAX_SAMPLE_REQUEST_IDS = 5;

interface ApiDiscoverySchema extends DBSchema {
  requests: {
    key: string;
    value: CapturedRequest;
    indexes: { "by-ts": number };
  };
  endpoints: {
    key: string;
    value: EndpointRecord;
  };
  secrets: {
    key: string;
    value: StoredSecret;
  };
}

let dbPromise: Promise<IDBPDatabase<ApiDiscoverySchema>> | undefined;

function getDb(): Promise<IDBPDatabase<ApiDiscoverySchema>> {
  dbPromise ??= openDB<ApiDiscoverySchema>(DB_NAME, DB_VERSION, {
    upgrade(db) {
      const requests = db.createObjectStore("requests", { keyPath: "id" });
      requests.createIndex("by-ts", "ts");
      db.createObjectStore("endpoints", { keyPath: "key" });
      db.createObjectStore("secrets", { keyPath: "id" });
    },
  });
  return dbPromise;
}

function bodyKeys(body: string | undefined): string[] {
  if (body === undefined) return [];
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return [];
    return Object.keys(parsed);
  } catch {
    return [];
  }
}

function requestHasAuthHeader(request: CapturedRequest): boolean {
  const headers = [...(request.requestHeaders ?? []), ...(request.responseHeaders ?? [])];
  return headers.some((h) => hasAuthHeaderName(h.name));
}

function requestJwtCandidates(request: CapturedRequest): string[] {
  const values = [
    ...(request.requestHeaders ?? []).map((h) => h.value),
    ...(request.responseHeaders ?? []).map((h) => h.value),
    request.requestBody,
    request.responseBody,
  ];
  return values.flatMap((value) => (value === undefined ? [] : findJwtCandidates(value)));
}

function requestHasJwt(request: CapturedRequest): boolean {
  return requestJwtCandidates(request).length > 0;
}

/** True if any JWT-shaped token in the request decodes to a header with `"alg":"none"`. */
function requestHasJwtAlgNone(request: CapturedRequest): boolean {
  return requestJwtCandidates(request).some(
    (token) => jwtHeaderAlg(token)?.toLowerCase() === "none",
  );
}

function mergeEndpoint(
  existing: EndpointRecord | undefined,
  request: CapturedRequest,
  key: string,
  templated: string,
): EndpointRecord {
  const bodyKeysThisRequest = bodyKeys(request.requestBody);
  const existingBodyKeys = existing?.bodyKeysSeen ?? [];
  const mergedBodyKeys = Array.from(new Set([...existingBodyKeys, ...bodyKeysThisRequest]));

  const exampleUrls = existing?.exampleUrls ?? [];
  const nextExampleUrls = exampleUrls.includes(request.url)
    ? exampleUrls
    : [...exampleUrls, request.url].slice(0, MAX_EXAMPLE_URLS);

  const sampleRequestIds = existing?.sampleRequestIds ?? [];
  const nextSampleRequestIds = [...sampleRequestIds, request.id].slice(-MAX_SAMPLE_REQUEST_IDS);

  const sources = new Set(existing?.sources ?? []);
  sources.add(request.source);

  return {
    key,
    method: request.method.toUpperCase(),
    host: request.host,
    templatedPath: templated,
    exampleUrls: nextExampleUrls,
    firstSeen: existing?.firstSeen ?? request.ts,
    lastSeen: request.ts,
    seenCount: (existing?.seenCount ?? 0) + 1,
    sources: [...sources],
    sampleRequestIds: nextSampleRequestIds,
    hasAuthHeader: (existing?.hasAuthHeader ?? false) || requestHasAuthHeader(request),
    bodyKeysSeen: mergedBodyKeys,
    jwtObserved: (existing?.jwtObserved ?? false) || requestHasJwt(request),
    jwtAlgNone: (existing?.jwtAlgNone ?? false) || requestHasJwtAlgNone(request),
    corsWildcardWithCredentials:
      (existing?.corsWildcardWithCredentials ?? false) ||
      hasCorsWildcardWithCredentials(request.responseHeaders),
    findings: existing?.findings ?? [],
  };
}

/**
 * Stores a raw {@link CapturedRequest}, merges it into its {@link EndpointRecord}, re-scores that
 * record against the full catalog, and returns the updated record's key (for the caller to
 * broadcast an `endpoint-updated` message).
 */
export async function upsertCapture(request: CapturedRequest): Promise<string> {
  const normalizedRequest: CapturedRequest = {
    ...request,
    requestBody: truncateBody(request.requestBody),
    responseBody: truncateBody(request.responseBody),
  };
  const { host, path } = splitUrl(request.url);
  const templated = templatePath(path);
  const key = endpointKey(request.method, host, templated);

  const db = await getDb();
  const tx = db.transaction(["requests", "endpoints"], "readwrite");
  await tx.objectStore("requests").put(normalizedRequest);
  const existing = await tx.objectStore("endpoints").get(key);
  const merged = mergeEndpoint(existing, normalizedRequest, key, templated);
  await tx.objectStore("endpoints").put(merged);
  await tx.done;

  // Re-score against the full catalog outside the write transaction (read-only, and scoring
  // every endpoint on every capture would be wasteful -- only the endpoint that changed needs
  // fresh findings, but shadow-unversioned-api needs the sibling list to decide).
  const allEndpoints = await getEndpoints();
  const rescored = { ...merged, findings: scoreEndpointInCatalog(merged, allEndpoints) };
  const rescoreTx = db.transaction("endpoints", "readwrite");
  await rescoreTx.store.put(rescored);
  await rescoreTx.done;

  return key;
}

export async function getEndpoints(): Promise<EndpointRecord[]> {
  const db = await getDb();
  return db.getAll("endpoints");
}

export async function getEndpoint(key: string): Promise<EndpointRecord | undefined> {
  const db = await getDb();
  return db.get("endpoints", key);
}

export async function getRequestsByIds(ids: string[]): Promise<CapturedRequest[]> {
  const db = await getDb();
  const results = await Promise.all(ids.map((id) => db.get("requests", id)));
  return results.filter((r): r is CapturedRequest => r !== undefined);
}

/**
 * All requests captured from a given browser tab -- used by the DevTools panel to scope the
 * catalog to the inspected tab. Scans the full `requests` store rather than using a dedicated
 * index: capture volume for a single browsing session is small enough that this is fine, and it
 * avoids a second index to keep in sync for what is a rarely-called, UI-only query.
 */
export async function getRequestsByTabId(tabId: number): Promise<CapturedRequest[]> {
  const db = await getDb();
  const all = await db.getAll("requests");
  return all.filter((request) => request.tabId === tabId);
}

/**
 * Stores a secret found by the miner. The id is derived from (label, sourceFile, match) so
 * finding the same secret again (e.g. on a repeat page load) overwrites the same row instead of
 * duplicating it.
 */
export async function upsertSecret(secret: Omit<StoredSecret, "id">): Promise<void> {
  const db = await getDb();
  const id = `${secret.label}::${secret.sourceFile}::${secret.match}`;
  await db.put("secrets", { ...secret, id });
}

export async function getSecrets(): Promise<StoredSecret[]> {
  const db = await getDb();
  return db.getAll("secrets");
}

export async function clearAll(): Promise<void> {
  const db = await getDb();
  const tx = db.transaction(["requests", "endpoints", "secrets"], "readwrite");
  await tx.objectStore("requests").clear();
  await tx.objectStore("endpoints").clear();
  await tx.objectStore("secrets").clear();
  await tx.done;
}
