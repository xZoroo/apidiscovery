import { describe, expect, it } from "vitest";
import {
  endpointKey,
  isNumericIdSegment,
  isObjectIdOrHashSegment,
  isUuidSegment,
  MAX_BODY_BYTES,
  splitUrl,
  templatePath,
  truncateBody,
} from "./normalizer.js";

describe("isNumericIdSegment", () => {
  it("accepts a run of digits", () => {
    expect(isNumericIdSegment("42")).toBe(true);
    expect(isNumericIdSegment("0")).toBe(true);
  });

  it("rejects non-numeric segments", () => {
    expect(isNumericIdSegment("users")).toBe(false);
    expect(isNumericIdSegment("42a")).toBe(false);
    expect(isNumericIdSegment("")).toBe(false);
  });
});

describe("isUuidSegment", () => {
  it("accepts a canonical UUID in either case", () => {
    expect(isUuidSegment("550e8400-e29b-41d4-a716-446655440000")).toBe(true);
    expect(isUuidSegment("550E8400-E29B-41D4-A716-446655440000")).toBe(true);
  });

  it("rejects malformed UUID-shaped strings", () => {
    expect(isUuidSegment("550e8400-e29b-41d4-a716")).toBe(false);
    expect(isUuidSegment("not-a-uuid")).toBe(false);
  });
});

describe("isObjectIdOrHashSegment", () => {
  it("accepts a 24-hex Mongo ObjectId and common hash lengths", () => {
    expect(isObjectIdOrHashSegment("507f1f77bcf86cd799439011")).toBe(true);
    expect(isObjectIdOrHashSegment("d".repeat(32))).toBe(true);
    expect(isObjectIdOrHashSegment("d".repeat(40))).toBe(true);
    expect(isObjectIdOrHashSegment("d".repeat(64))).toBe(true);
  });

  it("rejects non-hex or wrong-length strings", () => {
    expect(isObjectIdOrHashSegment("g".repeat(24))).toBe(false);
    expect(isObjectIdOrHashSegment("d".repeat(23))).toBe(false);
  });
});

describe("templatePath", () => {
  it("templates a single numeric id segment", () => {
    expect(templatePath("/users/42")).toBe("/users/{id}");
  });

  it("templates multiple id segments of different shapes", () => {
    expect(templatePath("/orgs/acme/users/507f1f77bcf86cd799439011/orders/42")).toBe(
      "/orgs/acme/users/{id}/orders/{id}",
    );
  });

  it("leaves paths with no id-shaped segments untouched", () => {
    expect(templatePath("/api/v1/health")).toBe("/api/v1/health");
  });

  it("preserves the leading and trailing slash structure", () => {
    expect(templatePath("/")).toBe("/");
    expect(templatePath("/users/42/")).toBe("/users/{id}/");
  });
});

describe("endpointKey", () => {
  it("upper-cases the method and joins host + templated path", () => {
    expect(endpointKey("get", "api.example.com", "/users/{id}")).toBe(
      "GET api.example.com/users/{id}",
    );
  });
});

describe("splitUrl", () => {
  it("drops the query string and fragment from path", () => {
    expect(splitUrl("https://api.example.com/users/42?x=1#frag")).toEqual({
      host: "api.example.com",
      path: "/users/42",
    });
  });

  it("defaults an empty path to '/'", () => {
    expect(splitUrl("https://api.example.com")).toEqual({
      host: "api.example.com",
      path: "/",
    });
  });
});

describe("truncateBody", () => {
  it("returns undefined unchanged", () => {
    expect(truncateBody(undefined)).toBeUndefined();
  });

  it("leaves short bodies untouched", () => {
    expect(truncateBody("short")).toBe("short");
  });

  it("truncates a body longer than MAX_BODY_BYTES", () => {
    const long = "a".repeat(MAX_BODY_BYTES + 100);
    const result = truncateBody(long);
    expect(result).toHaveLength(MAX_BODY_BYTES);
  });
});
