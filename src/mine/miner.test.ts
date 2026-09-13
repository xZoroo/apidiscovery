import { describe, expect, it } from "vitest";
import { mineBlobs, type ScriptBlob } from "./miner.js";

function blob(text: string, sourceUrl = "https://cdn.example.com/app.js"): ScriptBlob {
  return { sourceUrl, text };
}

describe("mineBlobs endpoints", () => {
  it("finds an absolute URL literal", () => {
    const result = mineBlobs([blob(`fetch("https://api.example.com/v1/users")`)]);
    expect(result.endpoints.map((e) => e.url)).toContain("https://api.example.com/v1/users");
  });

  it("finds and resolves a relative /api-prefixed path against the blob's source URL", () => {
    const result = mineBlobs([blob(`axios.get('/api/v2/orders')`)]);
    expect(result.endpoints.map((e) => e.url)).toContain("https://cdn.example.com/api/v2/orders");
  });

  it("finds a /graphql path literal", () => {
    const result = mineBlobs([blob(`const url = "/graphql";`)]);
    expect(result.endpoints.map((e) => e.url)).toContain("https://cdn.example.com/graphql");
  });

  it("does not match a plain asset path with no api/vN/graphql prefix", () => {
    const result = mineBlobs([blob(`import css from "/static/app.css"`)]);
    expect(result.endpoints).toEqual([]);
  });

  it("dedupes the same URL found in two different blobs", () => {
    const result = mineBlobs([
      blob(`fetch("https://api.example.com/v1/users")`, "https://cdn.example.com/a.js"),
      blob(`fetch("https://api.example.com/v1/users")`, "https://cdn.example.com/b.js"),
    ]);
    expect(result.endpoints).toHaveLength(1);
  });

  it("tags each endpoint with the source file it came from", () => {
    const result = mineBlobs([blob(`fetch("https://api.example.com/v1/users")`)]);
    expect(result.endpoints[0]?.sourceFile).toBe("https://cdn.example.com/app.js");
  });
});

describe("mineBlobs secrets", () => {
  it("finds an AWS access key id", () => {
    const result = mineBlobs([blob(`const key = "AKIAIOSFODNN7EXAMPLE";`)]);
    expect(result.secrets.some((s) => s.label === "AWS Access Key ID")).toBe(true);
  });

  it("finds a JWT-shaped string", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dGhpc2lzYXNpZ25hdHVyZQ";
    const result = mineBlobs([blob(`const token = "${jwt}";`)]);
    expect(result.secrets.some((s) => s.label === "JWT" && s.match === jwt)).toBe(true);
  });

  it("finds a generic labeled secret assignment", () => {
    const result = mineBlobs([blob(`const apiKey = "sk_live_abcdef1234567890";`)]);
    expect(result.secrets.some((s) => s.label === "Generic labeled secret")).toBe(true);
  });

  it("returns no secrets for benign text", () => {
    const result = mineBlobs([blob(`function add(a, b) { return a + b; }`)]);
    expect(result.secrets).toEqual([]);
  });

  it("dedupes an identical secret found in two blobs", () => {
    const result = mineBlobs([
      blob(`const key = "AKIAIOSFODNN7EXAMPLE";`, "https://cdn.example.com/a.js"),
      blob(`const key = "AKIAIOSFODNN7EXAMPLE";`, "https://cdn.example.com/b.js"),
    ]);
    expect(result.secrets).toHaveLength(1);
  });
});
