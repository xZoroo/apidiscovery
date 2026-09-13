/**
 * Scans fetched script/HTML text for endpoint and secret patterns, dedupes matches, and resolves
 * relative paths against the blob's own source URL.
 *
 * Secret matches are kept separate from endpoint stubs -- a secret isn't an endpoint -- per the
 * plan's miner design.
 */

import { ENDPOINT_PATTERNS, SECRET_PATTERNS } from "./patterns.js";

export interface ScriptBlob {
  sourceUrl: string;
  text: string;
}

export interface MinedEndpoint {
  /** Absolute URL resolved against the blob's source URL. */
  url: string;
  sourceFile: string;
}

export interface MinedSecret {
  label: string;
  match: string;
  sourceFile: string;
}

export interface MineResult {
  endpoints: MinedEndpoint[];
  secrets: MinedSecret[];
}

function resolveAgainst(baseUrl: string, candidate: string): string | undefined {
  try {
    return new URL(candidate, baseUrl).toString();
  } catch {
    return undefined;
  }
}

function scanEndpoints(blob: ScriptBlob): MinedEndpoint[] {
  const found: MinedEndpoint[] = [];
  for (const pattern of ENDPOINT_PATTERNS) {
    for (const match of blob.text.matchAll(pattern.regex)) {
      const raw = match[1];
      if (raw === undefined) continue;
      const resolved = resolveAgainst(blob.sourceUrl, raw);
      if (resolved !== undefined) found.push({ url: resolved, sourceFile: blob.sourceUrl });
    }
  }
  return found;
}

function scanSecrets(blob: ScriptBlob): MinedSecret[] {
  const found: MinedSecret[] = [];
  for (const pattern of SECRET_PATTERNS) {
    for (const match of blob.text.matchAll(pattern.regex)) {
      found.push({ label: pattern.label, match: match[0], sourceFile: blob.sourceUrl });
    }
  }
  return found;
}

function dedupeEndpoints(endpoints: MinedEndpoint[]): MinedEndpoint[] {
  const seen = new Map<string, MinedEndpoint>();
  for (const endpoint of endpoints) {
    if (!seen.has(endpoint.url)) seen.set(endpoint.url, endpoint);
  }
  return [...seen.values()];
}

function dedupeSecrets(secrets: MinedSecret[]): MinedSecret[] {
  const seen = new Map<string, MinedSecret>();
  for (const secret of secrets) {
    const key = `${secret.label}:${secret.match}`;
    if (!seen.has(key)) seen.set(key, secret);
  }
  return [...seen.values()];
}

/** Scans every blob (external scripts, sourcemap sources, inline scripts) and dedupes across all of them. */
export function mineBlobs(blobs: ScriptBlob[]): MineResult {
  const endpoints = blobs.flatMap(scanEndpoints);
  const secrets = blobs.flatMap(scanSecrets);
  return { endpoints: dedupeEndpoints(endpoints), secrets: dedupeSecrets(secrets) };
}
