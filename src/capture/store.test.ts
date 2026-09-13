import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import type { CapturedRequest } from "./types.js";
import {
  clearAll,
  getEndpoint,
  getEndpoints,
  getRequestsByTabId,
  getSecrets,
  upsertCapture,
  upsertSecret,
} from "./store.js";

function request(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: crypto.randomUUID(),
    ts: Date.now(),
    tabId: 1,
    method: "GET",
    url: "https://api.example.com/users/1",
    host: "api.example.com",
    path: "/users/1",
    source: "fetch",
    ...overrides,
  };
}

beforeEach(async () => {
  await clearAll();
});

describe("upsertCapture", () => {
  it("stores a new endpoint on first capture", async () => {
    await upsertCapture(request());
    const endpoint = await getEndpoint("GET api.example.com/users/{id}");
    expect(endpoint).toBeDefined();
    expect(endpoint?.seenCount).toBe(1);
    expect(endpoint?.templatedPath).toBe("/users/{id}");
  });

  it("merges two requests with different ids into one endpoint record", async () => {
    await upsertCapture(request({ id: "a", url: "https://api.example.com/users/1" }));
    await upsertCapture(request({ id: "b", url: "https://api.example.com/users/2" }));

    const endpoints = await getEndpoints();
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0]?.seenCount).toBe(2);
    expect(endpoints[0]?.exampleUrls).toEqual([
      "https://api.example.com/users/1",
      "https://api.example.com/users/2",
    ]);
  });

  it("keeps distinct methods on the same path as separate endpoints", async () => {
    await upsertCapture(request({ id: "a", method: "GET" }));
    await upsertCapture(request({ id: "b", method: "DELETE" }));

    const endpoints = await getEndpoints();
    expect(endpoints.map((e) => e.method).sort()).toEqual(["DELETE", "GET"]);
  });

  it("sets hasAuthHeader when a request carries an Authorization header", async () => {
    await upsertCapture(
      request({ requestHeaders: [{ name: "Authorization", value: "Bearer x" }] }),
    );
    const endpoint = await getEndpoint("GET api.example.com/users/{id}");
    expect(endpoint?.hasAuthHeader).toBe(true);
  });

  it("collects top-level JSON body keys from the request body", async () => {
    await upsertCapture(
      request({
        method: "POST",
        url: "https://api.example.com/users",
        requestBody: JSON.stringify({ name: "a", role: "admin" }),
      }),
    );
    const endpoint = await getEndpoint("POST api.example.com/users");
    expect(endpoint?.bodyKeysSeen.sort()).toEqual(["name", "role"]);
  });

  it("sets jwtObserved when a header value looks like a JWT", async () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dGhpc2lzYXNpZ25hdHVyZQ";
    await upsertCapture(
      request({ requestHeaders: [{ name: "Authorization", value: `Bearer ${jwt}` }] }),
    );
    const endpoint = await getEndpoint("GET api.example.com/users/{id}");
    expect(endpoint?.jwtObserved).toBe(true);
  });

  it("raises the idor-numeric-id finding once the endpoint has an id-shaped path", async () => {
    await upsertCapture(request());
    const endpoint = await getEndpoint("GET api.example.com/users/{id}");
    expect(endpoint?.findings.some((f) => f.ruleId === "idor-numeric-id")).toBe(true);
  });
});

describe("getRequestsByTabId", () => {
  it("returns only requests captured from the given tab", async () => {
    await upsertCapture(request({ id: "a", tabId: 1 }));
    await upsertCapture(request({ id: "b", tabId: 2 }));
    const forTab1 = await getRequestsByTabId(1);
    expect(forTab1.map((r) => r.id)).toEqual(["a"]);
  });

  it("returns an empty array when no requests match the tab", async () => {
    await upsertCapture(request({ id: "a", tabId: 1 }));
    expect(await getRequestsByTabId(999)).toEqual([]);
  });
});

describe("upsertSecret / getSecrets", () => {
  function secret(overrides: Partial<Parameters<typeof upsertSecret>[0]> = {}) {
    return {
      label: "AWS Access Key ID",
      match: "AKIAIOSFODNN7EXAMPLE",
      sourceFile: "https://cdn.example.com/app.js",
      ts: Date.now(),
      ...overrides,
    };
  }

  it("stores a new secret", async () => {
    await upsertSecret(secret());
    const secrets = await getSecrets();
    expect(secrets).toHaveLength(1);
    expect(secrets[0]?.match).toBe("AKIAIOSFODNN7EXAMPLE");
  });

  it("overwrites rather than duplicates when the same secret is seen again", async () => {
    await upsertSecret(secret());
    await upsertSecret(secret({ ts: Date.now() + 1000 }));
    expect(await getSecrets()).toHaveLength(1);
  });

  it("keeps secrets from different source files distinct", async () => {
    await upsertSecret(secret({ sourceFile: "https://cdn.example.com/a.js" }));
    await upsertSecret(secret({ sourceFile: "https://cdn.example.com/b.js" }));
    expect(await getSecrets()).toHaveLength(2);
  });
});

describe("clearAll", () => {
  it("removes all requests, endpoints, and secrets", async () => {
    await upsertCapture(request());
    await upsertSecret({
      label: "JWT",
      match: "eyJ.a.b",
      sourceFile: "https://cdn.example.com/app.js",
      ts: Date.now(),
    });
    await clearAll();
    expect(await getEndpoints()).toEqual([]);
    expect(await getSecrets()).toEqual([]);
  });
});
