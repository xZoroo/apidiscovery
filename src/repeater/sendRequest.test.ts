import { afterEach, describe, expect, it, vi } from "vitest";
import {
  formatHeaderLines,
  isForbiddenRequestHeader,
  parseHeaderLines,
  sendRepeaterRequest,
} from "./sendRequest.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

function baseRequest(overrides: Partial<Parameters<typeof sendRepeaterRequest>[0]> = {}) {
  return {
    method: "GET",
    url: "https://api.example.com/users/1",
    headers: [],
    body: "",
    includeCredentials: true,
    ...overrides,
  };
}

describe("parseHeaderLines", () => {
  it("parses one header per line, trimming name and value", () => {
    expect(parseHeaderLines("Authorization: Bearer abc\nX-Test:  value  ")).toEqual([
      { name: "Authorization", value: "Bearer abc" },
      { name: "X-Test", value: "value" },
    ]);
  });

  it("skips blank lines and lines without a colon", () => {
    expect(parseHeaderLines("Authorization: Bearer abc\n\nnot-a-header\n")).toEqual([
      { name: "Authorization", value: "Bearer abc" },
    ]);
  });

  it("skips a line with an empty header name", () => {
    expect(parseHeaderLines(": no name")).toEqual([]);
  });
});

describe("formatHeaderLines", () => {
  it("round-trips through parseHeaderLines", () => {
    const headers = [
      { name: "Authorization", value: "Bearer abc" },
      { name: "X-Test", value: "value" },
    ];
    expect(parseHeaderLines(formatHeaderLines(headers))).toEqual(headers);
  });
});

describe("isForbiddenRequestHeader", () => {
  it("flags browser-managed headers case-insensitively", () => {
    expect(isForbiddenRequestHeader("Host")).toBe(true);
    expect(isForbiddenRequestHeader("cookie")).toBe(true);
    expect(isForbiddenRequestHeader("Content-Length")).toBe(true);
  });

  it("flags Proxy- and Sec- prefixed headers", () => {
    expect(isForbiddenRequestHeader("Proxy-Authorization")).toBe(true);
    expect(isForbiddenRequestHeader("Sec-Fetch-Mode")).toBe(true);
  });

  it("does not flag an ordinary editable header", () => {
    expect(isForbiddenRequestHeader("Authorization")).toBe(false);
    expect(isForbiddenRequestHeader("X-Custom-Header")).toBe(false);
  });
});

describe("sendRepeaterRequest (extension-context fallback, no tab)", () => {
  it("sends the request and returns a parsed response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        status: 200,
        statusText: "OK",
        headers: {
          forEach: (cb: (v: string, n: string) => void) => cb("application/json", "content-type"),
        },
        text: async () => '{"ok":true}',
      })),
    );
    const result = await sendRepeaterRequest(baseRequest(), null);
    expect(result).toMatchObject({ status: 200, statusText: "OK", body: '{"ok":true}' });
    expect("headers" in result && result.headers).toEqual([
      { name: "content-type", value: "application/json" },
    ]);
  });

  it("drops forbidden headers before sending", async () => {
    let sentHeaders: [string, string][] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        sentHeaders = init.headers as [string, string][];
        return {
          status: 204,
          statusText: "No Content",
          headers: { forEach: () => undefined },
          text: async () => "",
        };
      }),
    );
    await sendRepeaterRequest(
      baseRequest({
        headers: [
          { name: "Host", value: "evil.example.com" },
          { name: "Authorization", value: "Bearer abc" },
        ],
      }),
      null,
    );
    expect(sentHeaders).toEqual([["Authorization", "Bearer abc"]]);
  });

  it("omits a body for GET requests even if one is supplied", async () => {
    let sentBody: unknown;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url: string, init: RequestInit) => {
        sentBody = init.body;
        return {
          status: 200,
          statusText: "OK",
          headers: { forEach: () => undefined },
          text: async () => "",
        };
      }),
    );
    await sendRepeaterRequest(baseRequest({ method: "GET", body: "should be ignored" }), null);
    expect(sentBody).toBeNull();
  });

  it("returns an error object instead of throwing when fetch rejects", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const result = await sendRepeaterRequest(baseRequest(), null);
    expect(result).toEqual({ error: "network down" });
  });
});

describe("sendRepeaterRequest (tab context)", () => {
  it("injects into the given tab and returns its result", async () => {
    const executeScript = vi.fn(async () => [
      { result: { status: 200, statusText: "OK", headers: [], body: "hi", timedMs: 5 } },
    ]);
    vi.stubGlobal("browser", { scripting: { executeScript } });
    const result = await sendRepeaterRequest(baseRequest(), 42);
    expect(executeScript).toHaveBeenCalledWith(
      expect.objectContaining({ target: { tabId: 42 }, world: "MAIN" }),
    );
    expect(result).toEqual({ status: 200, statusText: "OK", headers: [], body: "hi", timedMs: 5 });
  });

  it("falls back to a local fetch when the tab injection fails", async () => {
    vi.stubGlobal("browser", {
      scripting: {
        executeScript: vi.fn(async () => {
          throw new Error("no tab with id 99");
        }),
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        status: 200,
        statusText: "OK",
        headers: { forEach: () => undefined },
        text: async () => "fallback",
      })),
    );
    const result = await sendRepeaterRequest(baseRequest(), 99);
    expect("body" in result && result.body).toBe("fallback");
  });
});
