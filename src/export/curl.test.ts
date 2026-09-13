import { describe, expect, it } from "vitest";
import type { CapturedRequest, EndpointRecord } from "../capture/types.js";
import { toCurl, toEndpointListLine } from "./curl.js";

function request(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: "1",
    ts: 0,
    tabId: 1,
    method: "GET",
    url: "https://api.example.com/users/1",
    host: "api.example.com",
    path: "/users/1",
    source: "fetch",
    ...overrides,
  };
}

function endpoint(overrides: Partial<EndpointRecord> = {}): EndpointRecord {
  return {
    key: "GET api.example.com/users/{id}",
    method: "GET",
    host: "api.example.com",
    templatedPath: "/users/{id}",
    exampleUrls: ["https://api.example.com/users/1"],
    firstSeen: 0,
    lastSeen: 0,
    seenCount: 1,
    sources: ["fetch"],
    sampleRequestIds: [],
    hasAuthHeader: false,
    bodyKeysSeen: [],
    jwtObserved: false,
    jwtAlgNone: false,
    corsWildcardWithCredentials: false,
    findings: [],
    ...overrides,
  };
}

describe("toCurl", () => {
  it("builds a basic GET command with no headers or body", () => {
    expect(toCurl(request())).toBe("curl -X GET 'https://api.example.com/users/1'");
  });

  it("includes headers and a body for a POST", () => {
    const cmd = toCurl(
      request({
        method: "POST",
        requestHeaders: [{ name: "Content-Type", value: "application/json" }],
        requestBody: '{"a":1}',
      }),
    );
    expect(cmd).toBe(
      "curl -X POST -H 'Content-Type: application/json' --data-raw '{\"a\":1}' 'https://api.example.com/users/1'",
    );
  });

  it("escapes an embedded single quote in a header value", () => {
    const cmd = toCurl(request({ requestHeaders: [{ name: "X-Note", value: "it's here" }] }));
    expect(cmd).toContain(`'X-Note: it'\\''s here'`);
  });

  it("omits --data-raw entirely when there is no body", () => {
    expect(toCurl(request())).not.toContain("--data-raw");
  });
});

describe("toEndpointListLine", () => {
  it("uses the first example URL when present", () => {
    expect(toEndpointListLine(endpoint())).toBe("GET https://api.example.com/users/1");
  });

  it("falls back to host + templated path when there are no example URLs", () => {
    expect(toEndpointListLine(endpoint({ exampleUrls: [] }))).toBe(
      "GET https://api.example.com/users/{id}",
    );
  });
});
