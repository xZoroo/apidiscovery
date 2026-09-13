import { afterEach, describe, expect, it, vi } from "vitest";
import { probeOrigin } from "./prober.js";
import { WELL_KNOWN_API_DOC_PATHS } from "./wellKnownPaths.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetch(
  byPath: (path: string) => { status: number; contentType: string; body: string },
) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const path = new URL(url).pathname;
      const { status, contentType, body } = byPath(path);
      return {
        status,
        headers: { get: (name: string) => (name === "content-type" ? contentType : null) },
        text: async () => body,
      };
    }),
  );
}

describe("probeOrigin", () => {
  it("probes only the given origin, once per well-known path", async () => {
    const seen: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        seen.push(url);
        return { status: 404, headers: { get: () => null }, text: async () => "" };
      }),
    );
    await probeOrigin("https://api.example.com");
    expect(seen).toHaveLength(WELL_KNOWN_API_DOC_PATHS.length);
    expect(seen.every((url) => url.startsWith("https://api.example.com/"))).toBe(true);
  });

  it("classifies a JSON-content-type 200 as an API doc hit", async () => {
    mockFetch((path) =>
      path === "/swagger.json"
        ? { status: 200, contentType: "application/json", body: '{"openapi":"3.0.0"}' }
        : { status: 404, contentType: "", body: "" },
    );
    const results = await probeOrigin("https://api.example.com");
    const hit = results.find((r) => r.path === "/swagger.json");
    expect(hit?.looksLikeApiDoc).toBe(true);
  });

  it("does not classify a 200 HTML SPA catch-all response as an API doc hit", async () => {
    mockFetch(() => ({ status: 200, contentType: "text/html", body: "<!doctype html><html>" }));
    const results = await probeOrigin("https://api.example.com");
    expect(results.every((r) => !r.looksLikeApiDoc)).toBe(true);
  });

  it("classifies a JSON-shaped body with no content-type header as an API doc hit", async () => {
    mockFetch((path) =>
      path === "/openapi.json"
        ? { status: 200, contentType: "", body: '{"paths":{}}' }
        : { status: 404, contentType: "", body: "" },
    );
    const results = await probeOrigin("https://api.example.com");
    expect(results.find((r) => r.path === "/openapi.json")?.looksLikeApiDoc).toBe(true);
  });

  it("does not classify a non-2xx status as a hit even with a JSON content-type", async () => {
    mockFetch(() => ({ status: 500, contentType: "application/json", body: '{"error":true}' }));
    const results = await probeOrigin("https://api.example.com");
    expect(results.every((r) => !r.looksLikeApiDoc)).toBe(true);
  });

  it("records a failed fetch as status 0 and not a hit, without throwing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network error");
      }),
    );
    const results = await probeOrigin("https://api.example.com");
    expect(results.every((r) => r.status === 0 && !r.looksLikeApiDoc)).toBe(true);
  });
});
