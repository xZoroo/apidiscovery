import { describe, expect, it } from "vitest";
import type { EndpointRecord, Finding } from "../capture/types.js";
import { buildSiteMap, countEndpointsInSubtree, maxSeverityInSubtree } from "./siteMap.js";

function finding(severity: Finding["severity"]): Finding {
  return { ruleId: "r", label: "r", rationale: "r", severity };
}

function endpoint(overrides: Partial<EndpointRecord> = {}): EndpointRecord {
  return {
    key: "GET a/b",
    method: "GET",
    host: "api.example.com",
    templatedPath: "/users/{id}",
    exampleUrls: [],
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

describe("buildSiteMap", () => {
  it("creates one root node per distinct host", () => {
    const hosts = buildSiteMap([
      endpoint({ host: "a.example.com", templatedPath: "/x" }),
      endpoint({ host: "b.example.com", templatedPath: "/y" }),
    ]);
    expect([...hosts.keys()].sort()).toEqual(["a.example.com", "b.example.com"]);
  });

  it("nests path segments into a tree", () => {
    const hosts = buildSiteMap([endpoint({ templatedPath: "/users/{id}/orders" })]);
    const host = hosts.get("api.example.com")!;
    const users = host.children.get("users")!;
    const id = users.children.get("{id}")!;
    const orders = id.children.get("orders")!;
    expect(orders.endpoints).toHaveLength(1);
  });

  it("shares a node between two endpoints on the same path with different methods", () => {
    const hosts = buildSiteMap([
      endpoint({ key: "GET a/users", method: "GET", templatedPath: "/users" }),
      endpoint({ key: "POST a/users", method: "POST", templatedPath: "/users" }),
    ]);
    const users = hosts.get("api.example.com")!.children.get("users")!;
    expect(users.endpoints.map((e) => e.method).sort()).toEqual(["GET", "POST"]);
  });

  it("attaches a root-path endpoint directly to the host node", () => {
    const hosts = buildSiteMap([endpoint({ templatedPath: "/" })]);
    expect(hosts.get("api.example.com")!.endpoints).toHaveLength(1);
  });

  it("distinguishes a path that is both an intermediate segment and its own endpoint", () => {
    const hosts = buildSiteMap([
      endpoint({ key: "GET a/users", templatedPath: "/users" }),
      endpoint({ key: "GET a/users/{id}", templatedPath: "/users/{id}" }),
    ]);
    const users = hosts.get("api.example.com")!.children.get("users")!;
    expect(users.endpoints).toHaveLength(1);
    expect(users.children.get("{id}")?.endpoints).toHaveLength(1);
  });
});

describe("maxSeverityInSubtree", () => {
  it("returns null when nothing in the subtree has a finding", () => {
    const hosts = buildSiteMap([endpoint({ templatedPath: "/health", findings: [] })]);
    expect(maxSeverityInSubtree(hosts.get("api.example.com")!)).toBeNull();
  });

  it("returns the highest severity across a deeply nested descendant", () => {
    const hosts = buildSiteMap([
      endpoint({ templatedPath: "/a/b/c", findings: [finding("medium")] }),
      endpoint({ key: "2", templatedPath: "/a/b/d", findings: [finding("high")] }),
    ]);
    expect(maxSeverityInSubtree(hosts.get("api.example.com")!)).toBe("high");
    expect(maxSeverityInSubtree(hosts.get("api.example.com")!.children.get("a")!)).toBe("high");
  });
});

describe("countEndpointsInSubtree", () => {
  it("counts endpoints at every depth, not just direct children", () => {
    const hosts = buildSiteMap([
      endpoint({ key: "1", templatedPath: "/a" }),
      endpoint({ key: "2", templatedPath: "/a/b" }),
      endpoint({ key: "3", templatedPath: "/a/b/c" }),
    ]);
    expect(countEndpointsInSubtree(hosts.get("api.example.com")!)).toBe(3);
  });
});
