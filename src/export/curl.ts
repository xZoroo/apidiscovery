/** Reconstructs a shell-safe `curl` command and a plain endpoint-list line from a captured request. */

import type { CapturedRequest, EndpointRecord } from "../capture/types.js";

/** Single-quotes a value for POSIX shells, escaping any embedded single quotes. */
function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

/** Builds a `curl` command that replays the given request as closely as the captured data allows. */
export function toCurl(request: CapturedRequest): string {
  const parts = ["curl", "-X", request.method];
  for (const header of request.requestHeaders ?? []) {
    parts.push("-H", shellQuote(`${header.name}: ${header.value}`));
  }
  if (request.requestBody !== undefined) {
    parts.push("--data-raw", shellQuote(request.requestBody));
  }
  parts.push(shellQuote(request.url));
  return parts.join(" ");
}

/** One plain-text `METHOD https://host/path` line per endpoint, for a quick reviewable list. */
export function toEndpointListLine(endpoint: EndpointRecord): string {
  const url = endpoint.exampleUrls[0] ?? `https://${endpoint.host}${endpoint.templatedPath}`;
  return `${endpoint.method} ${url}`;
}
