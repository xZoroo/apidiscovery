import { describe, expect, it } from "vitest";
import { decodeJwtParts, hasCorsWildcardWithCredentials, jwtHeaderAlg } from "./rules.js";

function toBase64Url(value: string): string {
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function jwt(header: object, payload: object): string {
  const encode = (obj: object) => toBase64Url(JSON.stringify(obj));
  return `${encode(header)}.${encode(payload)}.signature`;
}

describe("decodeJwtParts", () => {
  it("decodes a well-formed JWT's header and payload", () => {
    const token = jwt({ alg: "HS256", typ: "JWT" }, { sub: "1", exp: 123 });
    expect(decodeJwtParts(token)).toEqual({
      header: { alg: "HS256", typ: "JWT" },
      payload: { sub: "1", exp: 123 },
    });
  });

  it("returns null for a string with the wrong number of segments", () => {
    expect(decodeJwtParts("not.a.jwt.at.all")).toBeNull();
    expect(decodeJwtParts("onlyonepart")).toBeNull();
  });

  it("returns null when a segment isn't valid base64url JSON", () => {
    expect(decodeJwtParts("not-json.also-not-json.sig")).toBeNull();
  });
});

describe("jwtHeaderAlg", () => {
  it("extracts alg from a well-formed token", () => {
    expect(jwtHeaderAlg(jwt({ alg: "none" }, { sub: "1" }))).toBe("none");
    expect(jwtHeaderAlg(jwt({ alg: "RS256" }, {}))).toBe("RS256");
  });

  it("returns undefined for a malformed token", () => {
    expect(jwtHeaderAlg("garbage")).toBeUndefined();
  });

  it("returns undefined when alg is missing or not a string", () => {
    expect(jwtHeaderAlg(jwt({}, {}))).toBeUndefined();
    expect(jwtHeaderAlg(jwt({ alg: 123 }, {}))).toBeUndefined();
  });
});

describe("hasCorsWildcardWithCredentials", () => {
  it("returns true for a wildcard origin paired with credentials allowed", () => {
    expect(
      hasCorsWildcardWithCredentials([
        { name: "Access-Control-Allow-Origin", value: "*" },
        { name: "Access-Control-Allow-Credentials", value: "true" },
      ]),
    ).toBe(true);
  });

  it("is case-insensitive on both header name and the credentials value", () => {
    expect(
      hasCorsWildcardWithCredentials([
        { name: "access-control-allow-origin", value: "*" },
        { name: "Access-Control-Allow-Credentials", value: "True" },
      ]),
    ).toBe(true);
  });

  it("returns false when origin is a specific host, not a wildcard", () => {
    expect(
      hasCorsWildcardWithCredentials([
        { name: "Access-Control-Allow-Origin", value: "https://example.com" },
        { name: "Access-Control-Allow-Credentials", value: "true" },
      ]),
    ).toBe(false);
  });

  it("returns false when credentials aren't allowed", () => {
    expect(
      hasCorsWildcardWithCredentials([{ name: "Access-Control-Allow-Origin", value: "*" }]),
    ).toBe(false);
  });

  it("returns false when headers are undefined", () => {
    expect(hasCorsWildcardWithCredentials(undefined)).toBe(false);
  });
});
