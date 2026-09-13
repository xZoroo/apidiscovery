/**
 * MAIN-world capture patch: the primary capture path (see plan doc's "Capture pipeline").
 * Monkey-patches `fetch`, `XMLHttpRequest`, and `WebSocket` in the page's own JS context so full
 * request/response bodies can be seen without the `chrome.debugger` banner or a DevTools
 * dependency. Runs at `document_start` on every frame.
 *
 * This file has no access to `browser`/`chrome` APIs (MAIN world is the page's own JS realm), so
 * captures are relayed out via `window.postMessage` for `content.ts` (isolated world) to pick up.
 */

import { splitUrl } from "../src/capture/normalizer.js";
import { INJECTED_MESSAGE_SOURCE, type InjectedCaptureMessage } from "../src/messaging.js";
import type { CapturedRequest, HeaderEntry } from "../src/capture/types.js";

type CapturePayload = Omit<CapturedRequest, "id" | "tabId">;

function safeAbsoluteUrl(url: string): string {
  try {
    return new URL(url, window.location.href).toString();
  } catch {
    return url;
  }
}

function safeHostAndPath(url: string): { host: string; path: string } {
  try {
    return splitUrl(url);
  } catch {
    return { host: "", path: "" };
  }
}

function postCapture(payload: CapturePayload): void {
  const message: InjectedCaptureMessage = { source: INJECTED_MESSAGE_SOURCE, payload };
  window.postMessage(message, "*");
}

function headersToEntries(headers: HeadersInit | undefined): HeaderEntry[] {
  if (headers === undefined) return [];
  if (headers instanceof Headers) {
    return [...headers.entries()].map(([name, value]) => ({ name, value }));
  }
  if (Array.isArray(headers)) {
    return headers.map(([name, value]) => ({ name: name ?? "", value: value ?? "" }));
  }
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

function fetchBodyToString(body: BodyInit | null | undefined): string | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  // FormData/Blob/ArrayBuffer/streams are intentionally left uncaptured for the MVP -- see plan's
  // "explicitly out of scope" note on keeping the miner/capture surface small and correct.
  return undefined;
}

async function patchedFetch(
  originalFetch: typeof fetch,
  input: RequestInfo | URL,
  init: RequestInit | undefined,
): Promise<Response> {
  const startedAt = Date.now();
  const request = input instanceof Request ? input : undefined;
  const method = (init?.method ?? request?.method ?? "GET").toUpperCase();
  const url = safeAbsoluteUrl(request?.url ?? input.toString());
  const { host, path } = safeHostAndPath(url);
  const requestHeaders = headersToEntries(init?.headers ?? request?.headers);
  const requestBody = fetchBodyToString(init?.body);

  const base: CapturePayload = {
    ts: startedAt,
    method,
    url,
    host,
    path,
    requestHeaders,
    requestBody,
    source: "fetch",
  };

  try {
    const response = await originalFetch(input, init);
    const cloned = response.clone();
    const responseHeaders = headersToEntries(cloned.headers);
    let responseBody: string | undefined;
    try {
      responseBody = await cloned.text();
    } catch {
      responseBody = undefined;
    }
    postCapture({ ...base, responseStatus: response.status, responseHeaders, responseBody });
    return response;
  } catch (error) {
    postCapture(base);
    throw error;
  }
}

function patchFetch(): void {
  const originalFetch = window.fetch.bind(window);
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) =>
    patchedFetch(originalFetch, input, init);
}

interface XhrCaptureState {
  method: string;
  url: string;
  headers: HeaderEntry[];
  startedAt: number;
}

function parseXhrResponseHeaders(raw: string): HeaderEntry[] {
  return raw
    .trim()
    .split(/\r?\n/)
    .filter((line) => line.length > 0)
    .map((line) => {
      const separatorIndex = line.indexOf(":");
      return {
        name: line.slice(0, separatorIndex).trim(),
        value: line.slice(separatorIndex + 1).trim(),
      };
    });
}

function xhrBodyToString(
  body: Document | XMLHttpRequestBodyInit | null | undefined,
): string | undefined {
  if (body === null || body === undefined) return undefined;
  if (typeof body === "string") return body;
  if (body instanceof URLSearchParams) return body.toString();
  return undefined;
}

function patchXhr(): void {
  const XhrProto = XMLHttpRequest.prototype;
  const originalOpen = XhrProto.open;
  const originalSend = XhrProto.send;
  const originalSetRequestHeader = XhrProto.setRequestHeader;
  const state = new WeakMap<XMLHttpRequest, XhrCaptureState>();

  XhrProto.open = function patchedOpen(
    this: XMLHttpRequest,
    method: string,
    url: string | URL,
    ...rest: unknown[]
  ) {
    state.set(this, {
      method: method.toUpperCase(),
      url: url.toString(),
      headers: [],
      startedAt: Date.now(),
    });
    return (originalOpen as (...args: unknown[]) => void).apply(this, [method, url, ...rest]);
  };

  XhrProto.setRequestHeader = function patchedSetRequestHeader(
    this: XMLHttpRequest,
    name: string,
    value: string,
  ) {
    state.get(this)?.headers.push({ name, value });
    return originalSetRequestHeader.call(this, name, value);
  };

  XhrProto.send = function patchedSend(
    this: XMLHttpRequest,
    body?: Document | XMLHttpRequestBodyInit | null,
  ) {
    const entry = state.get(this);
    this.addEventListener("loadend", () => {
      if (entry === undefined) return;
      const url = safeAbsoluteUrl(entry.url);
      const { host, path } = safeHostAndPath(url);
      postCapture({
        ts: entry.startedAt,
        method: entry.method,
        url,
        host,
        path,
        requestHeaders: entry.headers,
        requestBody: xhrBodyToString(body),
        responseStatus: this.status,
        responseHeaders: parseXhrResponseHeaders(this.getAllResponseHeaders()),
        responseBody:
          this.responseType === "" || this.responseType === "text" ? this.responseText : undefined,
        source: "xhr",
      });
    });
    return (originalSend as (...args: unknown[]) => void).apply(this, [body]);
  };
}

function patchWebSocket(): void {
  const OriginalWebSocket = window.WebSocket;

  class PatchedWebSocket extends OriginalWebSocket {
    constructor(url: string | URL, protocols?: string | string[]) {
      super(url, protocols);
      const absolute = safeAbsoluteUrl(url.toString());
      const { host, path } = safeHostAndPath(absolute);
      postCapture({
        ts: Date.now(),
        method: "GET",
        url: absolute,
        host,
        path,
        source: "websocket",
      });
    }
  }

  window.WebSocket = PatchedWebSocket as unknown as typeof WebSocket;
}

export default defineContentScript({
  matches: ["<all_urls>"],
  allFrames: true,
  world: "MAIN",
  runAt: "document_start",
  main() {
    patchFetch();
    patchXhr();
    patchWebSocket();
  },
});
