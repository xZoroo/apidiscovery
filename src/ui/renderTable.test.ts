import { describe, expect, it } from "vitest";
import type { EndpointRecord, Finding, StoredSecret } from "../capture/types.js";
import { splitHighlightSegments, summarize } from "./renderTable.js";

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

describe("splitHighlightSegments", () => {
  it("highlights a standalone numeric ID but not the same digits embedded in a longer token", () => {
    // Regression test: a bare substring match on "1" would also highlight it inside "2026" or
    // "v1", painting large amounts of unrelated text yellow on a real capture.
    const segments = splitHighlightSegments("/users/1 in v1 (2026)", ["1"]);
    const highlighted = segments.filter((s) => s.highlighted).map((s) => s.text);
    expect(highlighted).toEqual(["1"]);
    expect(segments.map((s) => s.text).join("")).toBe("/users/1 in v1 (2026)");
  });

  it("does not highlight a number embedded in a longer alphanumeric word", () => {
    const segments = splitHighlightSegments("employee123 record", ["123"]);
    expect(segments.every((s) => !s.highlighted)).toBe(true);
  });

  it("highlights a multi-word phrase term as a whole", () => {
    const segments = splitHighlightSegments(
      "Response allows Access-Control-Allow-Origin: * with credentials",
      ["Access-Control-Allow-Origin: *"],
    );
    expect(segments.some((s) => s.highlighted && s.text === "Access-Control-Allow-Origin: *")).toBe(
      true,
    );
  });

  it("returns the whole text as one unhighlighted segment when there are no terms", () => {
    expect(splitHighlightSegments("plain text", [])).toEqual([
      { text: "plain text", highlighted: false },
    ]);
  });

  it("highlights every occurrence of a repeated term", () => {
    const segments = splitHighlightSegments("/orgs/42/users/42", ["42"]);
    expect(segments.filter((s) => s.highlighted)).toHaveLength(2);
  });
});
