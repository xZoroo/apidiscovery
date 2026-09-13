import { describe, expect, it } from "vitest";
import type { EndpointRecord, Finding } from "../capture/types.js";
import {
  distinctOwaspCategories,
  matchesOwaspCategory,
  matchesQuery,
  sortEndpoints,
} from "./tableState.js";

function endpoint(overrides: Partial<EndpointRecord> = {}): EndpointRecord {
  return {
    key: "GET a.com/b",
    method: "GET",
    host: "a.com",
    templatedPath: "/b",
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

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "r",
    label: "Sensitive path",
    rationale: "contains admin",
    severity: "high",
    ...overrides,
  };
}

describe("sortEndpoints", () => {
  it("sorts by method alphabetically", () => {
    const post = endpoint({ method: "POST" });
    const get = endpoint({ method: "GET" });
    expect(sortEndpoints([post, get], "method", "asc")).toEqual([get, post]);
  });

  it("reverses order for descending direction", () => {
    const post = endpoint({ method: "POST" });
    const get = endpoint({ method: "GET" });
    expect(sortEndpoints([get, post], "method", "desc")).toEqual([post, get]);
  });

  it("sorts by risk with high severity first in descending order", () => {
    const highRisk = endpoint({ key: "a", findings: [finding({ severity: "high" })] });
    const noRisk = endpoint({ key: "b", findings: [] });
    const mediumRisk = endpoint({ key: "c", findings: [finding({ severity: "medium" })] });
    expect(sortEndpoints([noRisk, mediumRisk, highRisk], "risk", "desc")).toEqual([
      highRisk,
      mediumRisk,
      noRisk,
    ]);
  });

  it("sorts by seen count numerically, not lexicographically", () => {
    const nine = endpoint({ key: "a", seenCount: 9 });
    const ten = endpoint({ key: "b", seenCount: 10 });
    const two = endpoint({ key: "c", seenCount: 2 });
    expect(sortEndpoints([nine, ten, two], "seen", "asc")).toEqual([two, nine, ten]);
  });

  it("does not mutate the input array", () => {
    const input = [endpoint({ method: "POST" }), endpoint({ method: "GET" })];
    const original = [...input];
    sortEndpoints(input, "method", "asc");
    expect(input).toEqual(original);
  });
});

describe("matchesQuery", () => {
  it("matches on host or path", () => {
    const ep = endpoint({ host: "api.example.com", templatedPath: "/users/{id}" });
    expect(matchesQuery(ep, "api.example")).toBe(true);
    expect(matchesQuery(ep, "users")).toBe(true);
    expect(matchesQuery(ep, "nope")).toBe(false);
  });

  it("matches on method and source, not just host/path", () => {
    const ep = endpoint({ method: "DELETE", sources: ["js-mined"] });
    expect(matchesQuery(ep, "delete")).toBe(true);
    expect(matchesQuery(ep, "js-mined")).toBe(true);
  });

  it("matches on a finding's label, rationale, or OWASP category", () => {
    const ep = endpoint({
      findings: [
        finding({
          label: "Sensitive body field",
          rationale: "Body includes sensitive field 'role'",
          owaspCategory: "API3:2023 Broken Object Property Level Authorization",
        }),
      ],
    });
    expect(matchesQuery(ep, "mass assignment")).toBe(false);
    expect(matchesQuery(ep, "sensitive body")).toBe(true);
    expect(matchesQuery(ep, "role")).toBe(true);
    expect(matchesQuery(ep, "api3")).toBe(true);
  });

  it("matches everything for an empty or whitespace-only query", () => {
    const ep = endpoint();
    expect(matchesQuery(ep, "")).toBe(true);
    expect(matchesQuery(ep, "   ")).toBe(true);
  });
});

describe("matchesOwaspCategory", () => {
  it("matches when a finding carries the given category", () => {
    const ep = endpoint({
      findings: [finding({ owaspCategory: "API1:2023 Broken Object Level Authorization" })],
    });
    expect(matchesOwaspCategory(ep, "API1:2023 Broken Object Level Authorization")).toBe(true);
    expect(matchesOwaspCategory(ep, "API2:2023 Broken Authentication")).toBe(false);
  });

  it("matches everything when the category filter is empty", () => {
    expect(matchesOwaspCategory(endpoint(), "")).toBe(true);
  });
});

describe("distinctOwaspCategories", () => {
  it("returns the sorted, deduplicated set of categories across all endpoints", () => {
    const a = endpoint({
      key: "a",
      findings: [finding({ owaspCategory: "API5:2023 Broken Function Level Authorization" })],
    });
    const b = endpoint({
      key: "b",
      findings: [finding({ owaspCategory: "API1:2023 Broken Object Level Authorization" })],
    });
    const c = endpoint({
      key: "c",
      findings: [finding({ owaspCategory: "API1:2023 Broken Object Level Authorization" })],
    });
    expect(distinctOwaspCategories([a, b, c])).toEqual([
      "API1:2023 Broken Object Level Authorization",
      "API5:2023 Broken Function Level Authorization",
    ]);
  });

  it("returns an empty array when no endpoint has any findings", () => {
    expect(distinctOwaspCategories([endpoint()])).toEqual([]);
  });
});
