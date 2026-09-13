/**
 * The opt-in, current-origin-only well-known-path probe. This is the ONLY module in the codebase
 * that ever makes a request beyond what the page itself already loaded -- `capture/` and
 * `mine/` never call it, per the plan's scope boundary.
 */

import type { ProbeResult } from "../capture/types.js";
import { WELL_KNOWN_API_DOC_PATHS } from "./wellKnownPaths.js";

const CONCURRENCY = 4;
const API_DOC_CONTENT_TYPE_RE = /json|yaml|yml/i;

/**
 * Classifies a response as "looks like an API doc" only when it's 2xx AND the content genuinely
 * looks like structured schema data -- guards against SPA catch-all routes that return 200 HTML
 * for every path, which would otherwise flag every single probed path as a hit.
 */
function looksLikeApiDoc(status: number, contentType: string, bodyStart: string): boolean {
  if (status < 200 || status >= 300) return false;
  if (API_DOC_CONTENT_TYPE_RE.test(contentType)) return true;
  const trimmed = bodyStart.trimStart();
  return trimmed.startsWith("{") || trimmed.startsWith("[") || trimmed.startsWith("openapi:");
}

async function probeOnePath(origin: string, path: string): Promise<ProbeResult> {
  const url = new URL(path, origin).toString();
  try {
    const response = await fetch(url);
    const contentType = response.headers.get("content-type") ?? "";
    const bodyStart = (await response.text()).slice(0, 512);
    return {
      origin,
      path,
      status: response.status,
      looksLikeApiDoc: looksLikeApiDoc(response.status, contentType, bodyStart),
      ts: Date.now(),
    };
  } catch {
    return { origin, path, status: 0, looksLikeApiDoc: false, ts: Date.now() };
  }
}

/** Runs the fixed well-known-path list against `origin` only, with bounded concurrency. */
export async function probeOrigin(origin: string): Promise<ProbeResult[]> {
  const results: ProbeResult[] = [];
  const queue = [...WELL_KNOWN_API_DOC_PATHS];

  async function worker(): Promise<void> {
    let path = queue.shift();
    while (path !== undefined) {
      results.push(await probeOnePath(origin, path));
      path = queue.shift();
    }
  }

  await Promise.all(Array.from({ length: CONCURRENCY }, () => worker()));
  return results;
}
