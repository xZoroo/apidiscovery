/**
 * Sends a single, user-edited request straight from the browser -- a lightweight, one-request
 * "Repeater" for manual testing (edit a captured request's method/URL/headers/body, resend it, see
 * the raw response). No proxy and no CA certificate: the browser makes the real HTTPS request
 * itself, exactly as the page would, so there's nothing to install or trust.
 *
 * Two send paths, chosen automatically:
 *  - Tab context: injected into the request's original tab via `scripting.executeScript({world:
 *    "MAIN"})`, so it reuses that tab's real cookies/session and is same-origin from the page's own
 *    perspective -- the right choice whenever the tab is still open.
 *  - Extension context: a plain `fetch` run here instead, relying on this extension's
 *    `host_permissions` to bypass CORS for cross-origin targets. Used whenever there's no live tab
 *    to inject into (the tab was closed, or the endpoint came from JS mining and was never actually
 *    requested by a tab).
 */

import type { HeaderEntry } from "../capture/types.js";

export interface RepeaterRequest {
  method: string;
  url: string;
  headers: HeaderEntry[];
  body: string;
  includeCredentials: boolean;
}

export interface RepeaterResponse {
  status: number;
  statusText: string;
  headers: HeaderEntry[];
  body: string;
  timedMs: number;
}

export interface RepeaterError {
  error: string;
}

/** Header names a browser manages itself; `fetch()` silently drops any attempt to set these. */
const FORBIDDEN_HEADER_NAMES = new Set([
  "accept-charset",
  "accept-encoding",
  "access-control-request-headers",
  "access-control-request-method",
  "connection",
  "content-length",
  "cookie",
  "cookie2",
  "date",
  "dnt",
  "expect",
  "host",
  "keep-alive",
  "origin",
  "referer",
  "set-cookie",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "via",
]);

/** True for a header `fetch()` won't let a caller set -- surfaced in the UI so an edit that has no effect isn't a silent mystery. */
export function isForbiddenRequestHeader(name: string): boolean {
  const lower = name.trim().toLowerCase();
  return (
    FORBIDDEN_HEADER_NAMES.has(lower) || lower.startsWith("proxy-") || lower.startsWith("sec-")
  );
}

/** Parses the Repeater's `Name: value`-per-line header textarea. Blank lines and lines without a colon are skipped. */
export function parseHeaderLines(text: string): HeaderEntry[] {
  const headers: HeaderEntry[] = [];
  for (const line of text.split("\n")) {
    const separatorIndex = line.indexOf(":");
    if (separatorIndex === -1) continue;
    const name = line.slice(0, separatorIndex).trim();
    if (name.length === 0) continue;
    headers.push({ name, value: line.slice(separatorIndex + 1).trim() });
  }
  return headers;
}

/** Inverse of {@link parseHeaderLines}, for seeding the textarea from a captured sample. */
export function formatHeaderLines(headers: HeaderEntry[]): string {
  return headers.map((h) => `${h.name}: ${h.value}`).join("\n");
}

/**
 * The actual network call. Kept fully self-contained -- no closures over anything outside this
 * function body -- so the identical function can either run locally in the extension's own
 * context, or be injected into a page via `scripting.executeScript({func: performFetch})`, which
 * requires the function to work standalone in that page's world.
 */
async function performFetch(request: RepeaterRequest): Promise<RepeaterResponse | RepeaterError> {
  // Duplicated from isForbiddenRequestHeader rather than imported: a page-injected function can't
  // reference this module's other exports, since only this function body travels with it.
  const forbidden = new Set([
    "accept-charset",
    "accept-encoding",
    "access-control-request-headers",
    "access-control-request-method",
    "connection",
    "content-length",
    "cookie",
    "cookie2",
    "date",
    "dnt",
    "expect",
    "host",
    "keep-alive",
    "origin",
    "referer",
    "set-cookie",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
  ]);
  const sendableHeaders = request.headers.filter((h) => {
    const lower = h.name.trim().toLowerCase();
    return !forbidden.has(lower) && !lower.startsWith("proxy-") && !lower.startsWith("sec-");
  });

  const method = request.method.trim().toUpperCase() || "GET";
  const hasBody = method !== "GET" && method !== "HEAD";
  const started = performance.now();
  try {
    const response = await fetch(request.url, {
      method,
      headers: sendableHeaders.map((h): [string, string] => [h.name, h.value]),
      body: hasBody ? request.body : null,
      credentials: request.includeCredentials ? "include" : "omit",
    });
    const body = await response.text();
    const headers: HeaderEntry[] = [];
    response.headers.forEach((value, name) => headers.push({ name, value }));
    return {
      status: response.status,
      statusText: response.statusText,
      headers,
      body,
      timedMs: Math.round(performance.now() - started),
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

/** Sends `request`, preferring the given tab's own page context when it's still available. */
export async function sendRepeaterRequest(
  request: RepeaterRequest,
  tabId: number | null,
): Promise<RepeaterResponse | RepeaterError> {
  if (tabId !== null) {
    try {
      const [injection] = await browser.scripting.executeScript({
        target: { tabId },
        world: "MAIN",
        func: performFetch,
        args: [request],
      });
      if (injection?.result !== undefined) return injection.result;
    } catch {
      // Tab closed, navigated away, or otherwise not injectable -- fall back to sending directly
      // from the extension's own context below.
    }
  }
  return performFetch(request);
}
