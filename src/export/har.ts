/** Builds a HAR 1.2 log from captured requests, for import into Burp's HAR Importer/Pro, ZAP, or DevTools. */

import type { CapturedRequest, HeaderEntry } from "../capture/types.js";

interface HarHeader {
  name: string;
  value: string;
}

interface HarEntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    headers: HarHeader[];
    queryString: { name: string; value: string }[];
    postData?: { mimeType: string; text: string };
    headersSize: number;
    bodySize: number;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: HarHeader[];
    content: { size: number; mimeType: string; text?: string };
    headersSize: number;
    bodySize: number;
  };
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

function toHarHeaders(headers: HeaderEntry[] | undefined): HarHeader[] {
  return (headers ?? []).map((h) => ({ name: h.name, value: h.value }));
}

function mimeTypeFromHeaders(headers: HeaderEntry[] | undefined): string {
  return headers?.find((h) => h.name.toLowerCase() === "content-type")?.value ?? "text/plain";
}

function toHarEntry(request: CapturedRequest): HarEntry {
  const url = new URL(request.url);
  const queryString = [...url.searchParams.entries()].map(([name, value]) => ({ name, value }));

  return {
    startedDateTime: new Date(request.ts).toISOString(),
    time: 0,
    request: {
      method: request.method,
      url: request.url,
      httpVersion: "HTTP/1.1",
      headers: toHarHeaders(request.requestHeaders),
      queryString,
      ...(request.requestBody !== undefined
        ? {
            postData: {
              mimeType: mimeTypeFromHeaders(request.requestHeaders),
              text: request.requestBody,
            },
          }
        : {}),
      headersSize: -1,
      bodySize: request.requestBody?.length ?? 0,
    },
    response: {
      status: request.responseStatus ?? 0,
      statusText: "",
      httpVersion: "HTTP/1.1",
      headers: toHarHeaders(request.responseHeaders),
      content: {
        size: request.responseBody?.length ?? 0,
        mimeType: mimeTypeFromHeaders(request.responseHeaders),
        ...(request.responseBody !== undefined ? { text: request.responseBody } : {}),
      },
      headersSize: -1,
      bodySize: request.responseBody?.length ?? 0,
    },
    cache: {},
    timings: { send: 0, wait: 0, receive: 0 },
  };
}

/** Builds a full HAR 1.2 document from a list of captured requests. */
export function buildHar(requests: CapturedRequest[]): object {
  return {
    log: {
      version: "1.2",
      creator: { name: "API Discovery", version: "0.1.0" },
      entries: requests.map(toHarEntry),
    },
  };
}
