import { describe, expect, it } from "vitest";
import type { EndpointRecord, Finding, StoredSecret } from "../capture/types.js";
import { summarize } from "./renderTable.js";

function finding(severity: Finding["severity"]): Finding {
  return { ruleId: "r", label: "r", rationale: "r", severity };
}

function endpoint(findings: Finding[]): EndpointRecord {
  return {
    key: "GET a/b",
    method: "GET",
    host: "a",
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
    findings,
  };
}

function secret(): StoredSecret {
  return { id: "1", label: "JWT", match: "x", sourceFile: "y", ts: 0 };
}

describe("summarize", () => {
  it("counts total endpoints and secrets", () => {
    const summary = summarize([endpoint([]), endpoint([])], [secret()]);
    expect(summary.total).toBe(2);
    expect(summary.secrets).toBe(1);
  });

  it("buckets each endpoint by its highest severity finding", () => {
    const summary = summarize(
      [
        endpoint([finding("high")]),
        endpoint([finding("medium"), finding("low")]),
        endpoint([finding("low")]),
        endpoint([]),
      ],
      [],
    );
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
    expect(summary.low).toBe(1);
    expect(summary.total).toBe(4);
  });

  it("returns all zeros for an empty catalog", () => {
    expect(summarize([], [])).toEqual({ total: 0, high: 0, medium: 0, low: 0, secrets: 0 });
  });
});
