import { describe, expect, it } from "vitest";
import type { CapturedRequest } from "../capture/types.js";
import { buildHar } from "./har.js";

function request(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: "1",
    ts: Date.parse("2026-01-01T00:00:00.000Z"),
    tabId: 1,
    method: "GET",
    url: "https://api.example.com/users/1?verbose=true",
    host: "api.example.com",
    path: "/users/1",
    source: "fetch",
    ...overrides,
  };
}

describe("buildHar", () => {
  it("produces a HAR 1.2 log with one entry per request", () => {
    const har = buildHar([request()]) as {
      log: { version: string; entries: unknown[] };
    };
    expect(har.log.version).toBe("1.2");
    expect(har.log.entries).toHaveLength(1);
  });

  it("extracts the query string into a separate array", () => {
    const har = buildHar([request()]) as {
      log: { entries: { request: { queryString: { name: string; value: string }[] } }[] };
    };
    expect(har.log.entries[0]?.request.queryString).toEqual([{ name: "verbose", value: "true" }]);
  });

  it("includes postData only when a request body is present", () => {
    const withBody = buildHar([request({ method: "POST", requestBody: '{"a":1}' })]) as {
      log: { entries: { request: { postData?: { text: string } } }[] };
    };
    expect(withBody.log.entries[0]?.request.postData?.text).toBe('{"a":1}');

    const withoutBody = buildHar([request()]) as {
      log: { entries: { request: { postData?: { text: string } } }[] };
    };
    expect(withoutBody.log.entries[0]?.request.postData).toBeUndefined();
  });

  it("carries response status and body through to the HAR entry", () => {
    const har = buildHar([request({ responseStatus: 200, responseBody: "{}" })]) as {
      log: { entries: { response: { status: number; content: { text?: string } } }[] };
    };
    expect(har.log.entries[0]?.response.status).toBe(200);
    expect(har.log.entries[0]?.response.content.text).toBe("{}");
  });

  it("returns an empty entries array for no requests", () => {
    const har = buildHar([]) as { log: { entries: unknown[] } };
    expect(har.log.entries).toEqual([]);
  });
});
