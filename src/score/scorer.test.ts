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
    findings: [],
    ...overrides,
  };
}

describe("scoreEndpoint", () => {
  it("raises nothing for a plain, unauthenticated GET with no id", () => {
    expect(scoreEndpoint(endpoint())).toEqual([]);
  });

  it("idor-numeric-id: flags a numeric path segment", () => {
    const findings = scoreEndpoint(endpoint({ exampleUrls: ["https://api.example.com/users/42"] }));
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "idor-numeric-id",
        rationale: "Path segment '42' looks like a sequential numeric ID -- try adjacent IDs",
        severity: "high",
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

  it("sensitive-path: flags an admin path", () => {
    const findings = scoreEndpoint(endpoint({ templatedPath: "/admin/users" }));
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: "sensitive-path",
        rationale: "Path contains 'admin' -- likely internal/admin surface",
      }),
    );
  });

  it("auth-bearing: flags when hasAuthHeader is true", () => {
    const findings = scoreEndpoint(endpoint({ hasAuthHeader: true }));
    expect(findings.some((f) => f.ruleId === "auth-bearing")).toBe(true);
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
