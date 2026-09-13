import { describe, expect, it } from "vitest";
import type { EndpointRecord } from "../capture/types.js";
import { maxSeverity, scoreEndpoint, scoreEndpointInCatalog } from "./scorer.js";

function endpoint(overrides: Partial<EndpointRecord> = {}): EndpointRecord {
  return {
    key: "GET api.example.com/things",
    method: "GET",
    host: "api.example.com",
    templatedPath: "/things",
    exampleUrls: ["https://api.example.com/things"],
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

describe("scoreEndpoint", () => {
  it("raises nothing for a plain, unauthenticated GET with no id", () => {
    expect(scoreEndpoint(endpoint())).toEqual([]);
  });

  it("idor-numeric-id: flags a numeric path segment and reports the exact matched value", () => {
    const findings = scoreEndpoint(endpoint({ exampleUrls: ["https://api.example.com/users/42"] }));
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "idor-numeric-id",
        rationale: "Path segment '42' looks like a sequential numeric ID -- try adjacent IDs",
        severity: "high",
        matchedValue: "42",
      }),
    );
  });

  it("idor-uuid: flags a UUID path segment", () => {
    const findings = scoreEndpoint(
      endpoint({
        exampleUrls: ["https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000"],
      }),
    );
    expect(findings.some((f) => f.ruleId === "idor-uuid")).toBe(true);
  });

  it("idor-objectid-or-hash: flags a Mongo ObjectId path segment", () => {
    const findings = scoreEndpoint(
      endpoint({ exampleUrls: ["https://api.example.com/users/507f1f77bcf86cd799439011"] }),
    );
    expect(findings.some((f) => f.ruleId === "idor-objectid-or-hash")).toBe(true);
  });

  it("sensitive-path: flags an admin path and reports the matched keyword", () => {
    const findings = scoreEndpoint(endpoint({ templatedPath: "/admin/users" }));
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "sensitive-path",
        rationale: "Path contains 'admin' -- likely internal/admin surface",
        matchedValue: "admin",
      }),
    );
  });

  it("auth-bearing: flags when hasAuthHeader is true, with no matchedValue (no single literal caused it)", () => {
    const findings = scoreEndpoint(endpoint({ hasAuthHeader: true }));
    const finding = findings.find((f) => f.ruleId === "auth-bearing");
    expect(finding).toBeDefined();
    expect(finding?.matchedValue).toBeUndefined();
  });

  it("state-changing-on-object: flags a write method against an id-templated path", () => {
    const findings = scoreEndpoint(
      endpoint({
        method: "DELETE",
        templatedPath: "/users/{id}",
        exampleUrls: ["https://api.example.com/users/42"],
      }),
    );
    expect(findings.some((f) => f.ruleId === "state-changing-on-object")).toBe(true);
  });

  it("state-changing-on-object: does not flag a write method with no id in the path", () => {
    const findings = scoreEndpoint(endpoint({ method: "POST", templatedPath: "/users" }));
    expect(findings.some((f) => f.ruleId === "state-changing-on-object")).toBe(false);
  });

  it("mass-assignment-candidate: flags a watchlisted body key", () => {
    const findings = scoreEndpoint(endpoint({ bodyKeysSeen: ["name", "role"] }));
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "mass-assignment-candidate",
        rationale: "Body includes sensitive field 'role' -- check for mass assignment / BOPLA",
        matchedValue: "role",
      }),
    );
  });

  it("graphql-endpoint: flags a /graphql path", () => {
    const findings = scoreEndpoint(endpoint({ templatedPath: "/graphql" }));
    expect(findings.some((f) => f.ruleId === "graphql-endpoint")).toBe(true);
  });

  it("jwt-present: flags when jwtObserved is true", () => {
    const findings = scoreEndpoint(endpoint({ jwtObserved: true }));
    expect(findings).toContainEqual(
      expect.objectContaining({ ruleId: "jwt-present", severity: "low" }),
    );
  });

  it("jwt-present: does not flag when jwtObserved is false", () => {
    const findings = scoreEndpoint(endpoint({ jwtObserved: false }));
    expect(findings.some((f) => f.ruleId === "jwt-present")).toBe(false);
  });

  it("doc-path-found: flags an endpoint sourced from the probe", () => {
    const findings = scoreEndpoint(endpoint({ sources: ["probe"] }));
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "doc-path-found",
        severity: "high",
      }),
    );
  });

  it("jwt-alg-none: flags an endpoint whose captured JWT decoded to alg=none", () => {
    const findings = scoreEndpoint(endpoint({ jwtAlgNone: true }));
    expect(findings).toContainEqual(
      expect.objectContaining({ ruleId: "jwt-alg-none", severity: "high", matchedValue: "none" }),
    );
  });

  it("cors-wildcard-credentials: flags a wildcard-origin-plus-credentials response", () => {
    const findings = scoreEndpoint(endpoint({ corsWildcardWithCredentials: true }));
    expect(findings).toContainEqual(
      expect.objectContaining({ ruleId: "cors-wildcard-credentials", severity: "high" }),
    );
  });

  it("every rule attaches an OWASP API Security Top 10 category to its finding", () => {
    const findings = scoreEndpoint(
      endpoint({
        exampleUrls: ["https://api.example.com/users/42"],
        hasAuthHeader: true,
        jwtObserved: true,
      }),
    );
    expect(findings.length).toBeGreaterThan(0);
    for (const finding of findings) {
      expect(finding.owaspCategory).toMatch(/^API\d{1,2}:2023/);
    }
  });
});

describe("scoreEndpointInCatalog", () => {
  it("adds shadow-unversioned-api when a sibling on the same host is versioned", () => {
    const target = endpoint({
      key: "GET api.example.com/users",
      templatedPath: "/users",
      exampleUrls: ["https://api.example.com/users"],
    });
    const sibling = endpoint({
      key: "GET api.example.com/v1/orders",
      templatedPath: "/v1/orders",
      exampleUrls: ["https://api.example.com/v1/orders"],
    });
    const findings = scoreEndpointInCatalog(target, [target, sibling]);
    expect(findings.some((f) => f.ruleId === "shadow-unversioned-api")).toBe(true);
  });

  it("does not add shadow-unversioned-api when no sibling is versioned", () => {
    const target = endpoint({ templatedPath: "/users" });
    const findings = scoreEndpointInCatalog(target, [target]);
    expect(findings.some((f) => f.ruleId === "shadow-unversioned-api")).toBe(false);
  });

  it("adds inconsistent-auth when a sibling method on the same path has an auth header", () => {
    const unauthed = endpoint({
      key: "DELETE api.example.com/admin/users/{id}",
      method: "DELETE",
      templatedPath: "/admin/users/{id}",
      hasAuthHeader: false,
    });
    const authed = endpoint({
      key: "GET api.example.com/admin/users/{id}",
      method: "GET",
      templatedPath: "/admin/users/{id}",
      hasAuthHeader: true,
    });
    const findings = scoreEndpointInCatalog(unauthed, [unauthed, authed]);
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "inconsistent-auth",
        severity: "high",
        matchedValue: "DELETE",
      }),
    );
  });

  it("does not add inconsistent-auth when the endpoint itself has an auth header", () => {
    const target = endpoint({ hasAuthHeader: true });
    const findings = scoreEndpointInCatalog(target, [target]);
    expect(findings.some((f) => f.ruleId === "inconsistent-auth")).toBe(false);
  });

  it("does not add inconsistent-auth when no sibling on the same path is authed", () => {
    const target = endpoint({ hasAuthHeader: false });
    const findings = scoreEndpointInCatalog(target, [target]);
    expect(findings.some((f) => f.ruleId === "inconsistent-auth")).toBe(false);
  });
});

describe("maxSeverity", () => {
  it("returns null for no findings", () => {
    expect(maxSeverity([])).toBeNull();
  });

  it("returns the highest severity present", () => {
    expect(
      maxSeverity([
        { ruleId: "a", label: "a", rationale: "a", severity: "low" },
        { ruleId: "b", label: "b", rationale: "b", severity: "high" },
        { ruleId: "c", label: "c", rationale: "c", severity: "medium" },
      ]),
    ).toBe("high");
  });
});
