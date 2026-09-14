import { describe, expect, it } from "vitest";
import { isInjectedCaptureMessage } from "./messaging.js";

function payload(overrides: Record<string, unknown> = {}) {
  return {
    ts: 0,
    method: "GET",
    url: "https://api.example.com/users/1",
    host: "api.example.com",
    path: "/users/1",
    source: "fetch",
    ...overrides,
  };
}

describe("isInjectedCaptureMessage", () => {
  it("accepts a message with the expected token and a well-shaped payload", () => {
    const message = { source: "apidiscovery", token: "abc", payload: payload() };
    expect(isInjectedCaptureMessage(message, "abc")).toBe(true);
  });

  it("rejects a message with the wrong token -- a forging page won't know the real one", () => {
    const message = { source: "apidiscovery", token: "wrong", payload: payload() };
    expect(isInjectedCaptureMessage(message, "abc")).toBe(false);
  });

  it("rejects a message with no token at all", () => {
    const message = { source: "apidiscovery", payload: payload() };
    expect(isInjectedCaptureMessage(message, "abc")).toBe(false);
  });

  it("rejects when the expected token itself is empty (never validated against nothing)", () => {
    const message = { source: "apidiscovery", token: "", payload: payload() };
    expect(isInjectedCaptureMessage(message, "")).toBe(false);
  });

  it("rejects the wrong source string even with a correct token", () => {
    const message = { source: "not-apidiscovery", token: "abc", payload: payload() };
    expect(isInjectedCaptureMessage(message, "abc")).toBe(false);
  });

  it("rejects a payload missing required string fields", () => {
    const message = { source: "apidiscovery", token: "abc", payload: payload({ url: 123 }) };
    expect(isInjectedCaptureMessage(message, "abc")).toBe(false);
  });

  it("rejects a payload that isn't an object", () => {
    const message = { source: "apidiscovery", token: "abc", payload: "not an object" };
    expect(isInjectedCaptureMessage(message, "abc")).toBe(false);
  });

  it("rejects non-object data entirely", () => {
    expect(isInjectedCaptureMessage("just a string", "abc")).toBe(false);
    expect(isInjectedCaptureMessage(null, "abc")).toBe(false);
    expect(isInjectedCaptureMessage(undefined, "abc")).toBe(false);
  });
});
