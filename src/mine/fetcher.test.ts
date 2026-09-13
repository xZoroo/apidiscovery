import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchScriptWithSourceMap } from "./fetcher.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetch(responses: Record<string, { ok: boolean; body: string }>) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) => {
      const entry = responses[url];
      if (entry === undefined) return { ok: false, text: async () => "", json: async () => ({}) };
      return {
        ok: entry.ok,
        text: async () => entry.body,
        json: async () => JSON.parse(entry.body) as unknown,
      };
    }),
  );
}

describe("fetchScriptWithSourceMap", () => {
  it("returns just the script blob when there is no sourcemap comment", async () => {
    mockFetch({ "https://cdn.example.com/app.js": { ok: true, body: "console.log(1)" } });
    const blobs = await fetchScriptWithSourceMap("https://cdn.example.com/app.js");
    expect(blobs).toEqual([
      { sourceUrl: "https://cdn.example.com/app.js", text: "console.log(1)" },
    ]);
  });

  it("returns an empty array when the script itself can't be fetched", async () => {
    mockFetch({});
    const blobs = await fetchScriptWithSourceMap("https://cdn.example.com/missing.js");
    expect(blobs).toEqual([]);
  });

  it("returns an empty array when fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    const blobs = await fetchScriptWithSourceMap("https://cdn.example.com/app.js");
    expect(blobs).toEqual([]);
  });

  it("adds sourcesContent blobs when the sourcemap has them", async () => {
    const map = JSON.stringify({
      sources: ["src/app.ts"],
      sourcesContent: ["export const x = 1;"],
    });
    mockFetch({
      "https://cdn.example.com/app.js": {
        ok: true,
        body: "console.log(1)\n//# sourceMappingURL=app.js.map",
      },
      "https://cdn.example.com/app.js.map": { ok: true, body: map },
    });
    const blobs = await fetchScriptWithSourceMap("https://cdn.example.com/app.js");
    expect(blobs).toHaveLength(2);
    expect(blobs[1]).toEqual({
      sourceUrl: "https://cdn.example.com/app.js.map#src/app.ts",
      text: "export const x = 1;",
    });
  });

  it("falls back to just the script blob when the sourcemap fetch fails", async () => {
    mockFetch({
      "https://cdn.example.com/app.js": {
        ok: true,
        body: "console.log(1)\n//# sourceMappingURL=app.js.map",
      },
    });
    const blobs = await fetchScriptWithSourceMap("https://cdn.example.com/app.js");
    expect(blobs).toHaveLength(1);
  });

  it("falls back to just the script blob when the sourcemap has no sourcesContent", async () => {
    mockFetch({
      "https://cdn.example.com/app.js": {
        ok: true,
        body: "console.log(1)\n//# sourceMappingURL=app.js.map",
      },
      "https://cdn.example.com/app.js.map": { ok: true, body: JSON.stringify({ sources: [] }) },
    });
    const blobs = await fetchScriptWithSourceMap("https://cdn.example.com/app.js");
    expect(blobs).toHaveLength(1);
  });
});
