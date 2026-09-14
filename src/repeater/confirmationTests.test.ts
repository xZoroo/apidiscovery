import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CapturedRequest } from "../capture/types.js";
import {
  runCorsReflectionTest,
  runIdorSubstitutionTest,
  runJwtAlgNoneTest,
  runMassAssignmentTest,
  runMethodTamperingTest,
  runOpenRedirectTest,
  runUnauthenticatedReplayTest,
} from "./confirmationTests.js";
import { sendRepeaterRequest } from "./sendRequest.js";

vi.mock("./sendRequest.js", () => ({ sendRepeaterRequest: vi.fn() }));

const mockSend = vi.mocked(sendRepeaterRequest);

beforeEach(() => {
  mockSend.mockReset();
});

function sample(overrides: Partial<CapturedRequest> = {}): CapturedRequest {
  return {
    id: "r1",
    ts: 0,
    tabId: 7,
    method: "GET",
    url: "https://api.example.com/users/1",
    host: "api.example.com",
    path: "/users/1",
    requestHeaders: [
      { name: "Authorization", value: "Bearer abc" },
      { name: "Cookie", value: "session=xyz" },
    ],
    responseStatus: 200,
    responseBody: '{"id":1,"name":"alice"}',
    source: "fetch",
    ...overrides,
  };
}

function ok(overrides: Partial<Awaited<ReturnType<typeof sendRepeaterRequest>>> = {}) {
  return {
    status: 200,
    statusText: "OK",
    headers: [],
    body: "{}",
    timedMs: 1,
    finalUrl: "https://api.example.com/users/2",
    redirected: false,
    ...overrides,
  };
}

describe("runIdorSubstitutionTest", () => {
  it("is not applicable without a sample", async () => {
    const result = await runIdorSubstitutionTest(undefined);
    expect(result.notApplicable).toBe(true);
  });

  it("is not applicable with no numeric ID segment", async () => {
    const result = await runIdorSubstitutionTest(sample({ url: "https://api.example.com/health" }));
    expect(result.notApplicable).toBe(true);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it("flags a different successful body for the substituted ID", async () => {
    mockSend.mockResolvedValue(ok({ status: 200, body: '{"id":2,"name":"bob"}' }));
    const result = await runIdorSubstitutionTest(sample());
    expect(result.concern).toBe(true);
    expect(mockSend).toHaveBeenCalledWith(
      expect.objectContaining({ url: "https://api.example.com/users/2" }),
      7,
    );
  });

  it("does not flag when the substituted ID is rejected", async () => {
    mockSend.mockResolvedValue(ok({ status: 403, body: "" }));
    const result = await runIdorSubstitutionTest(sample());
    expect(result.concern).toBe(false);
  });

  it("reports the request error instead of a verdict when the send fails", async () => {
    mockSend.mockResolvedValue({ error: "network down" });
    const result = await runIdorSubstitutionTest(sample());
    expect(result.concern).toBe(false);
    expect(result.verdict).toContain("network down");
  });
});

describe("runUnauthenticatedReplayTest", () => {
  it("is not applicable without a sample", async () => {
    expect((await runUnauthenticatedReplayTest(undefined)).notApplicable).toBe(true);
  });

  it("strips credential headers and omits credentials", async () => {
    mockSend.mockResolvedValue(ok({ status: 403 }));
    await runUnauthenticatedReplayTest(sample());
    expect(mockSend).toHaveBeenCalledWith(
      expect.objectContaining({ headers: [], includeCredentials: false }),
      7,
    );
  });

  it("flags a success status returned without credentials", async () => {
    mockSend.mockResolvedValue(ok({ status: 200 }));
    const result = await runUnauthenticatedReplayTest(sample());
    expect(result.concern).toBe(true);
  });
});

describe("runCorsReflectionTest", () => {
  it("is not applicable with no sample and no example URL", async () => {
    expect((await runCorsReflectionTest(undefined, undefined)).notApplicable).toBe(true);
  });

  it("always sends from the extension context (tabId null), never the tab", async () => {
    mockSend.mockResolvedValue(ok({ headers: [] }));
    await runCorsReflectionTest(sample(), undefined);
    expect(mockSend).toHaveBeenCalledWith(expect.anything(), null);
  });

  it("flags a reflected, credentialed Origin", async () => {
    mockSend.mockResolvedValue(
      ok({
        headers: [
          { name: "access-control-allow-origin", value: "chrome-extension://abc" },
          { name: "access-control-allow-credentials", value: "true" },
        ],
      }),
    );
    const result = await runCorsReflectionTest(sample(), undefined);
    expect(result.concern).toBe(true);
  });

  it("does not flag a response with no CORS headers", async () => {
    mockSend.mockResolvedValue(ok({ headers: [] }));
    const result = await runCorsReflectionTest(sample(), undefined);
    expect(result.concern).toBe(false);
  });
});

describe("runJwtAlgNoneTest", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig";

  it("is not applicable without a sample", async () => {
    expect((await runJwtAlgNoneTest(undefined)).notApplicable).toBe(true);
  });

  it("is not applicable when no JWT is present", async () => {
    const result = await runJwtAlgNoneTest(sample({ requestHeaders: [] }));
    expect(result.notApplicable).toBe(true);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it("forges an alg=none token and substitutes it into the header", async () => {
    mockSend.mockResolvedValue(ok({ status: 401 }));
    await runJwtAlgNoneTest(
      sample({ requestHeaders: [{ name: "Authorization", value: `Bearer ${jwt}` }] }),
    );
    const sentHeaders = mockSend.mock.calls[0]?.[0].headers ?? [];
    const authHeader = sentHeaders.find((h) => h.name === "Authorization");
    expect(authHeader?.value).not.toContain(jwt);
    expect(authHeader?.value.endsWith(".")).toBe(true);
  });

  it("flags a non-error status for the unsigned token", async () => {
    mockSend.mockResolvedValue(ok({ status: 200 }));
    const result = await runJwtAlgNoneTest(
      sample({ requestHeaders: [{ name: "Authorization", value: `Bearer ${jwt}` }] }),
    );
    expect(result.concern).toBe(true);
  });
});

describe("runMethodTamperingTest", () => {
  it("is not applicable without a sample", async () => {
    expect((await runMethodTamperingTest(undefined)).notApplicable).toBe(true);
  });

  it("tries every alternate method exactly once", async () => {
    mockSend.mockResolvedValue(ok({ status: 403 }));
    await runMethodTamperingTest(sample({ method: "GET" }));
    const methodsTried = mockSend.mock.calls.map((call) => call[0].method);
    expect(methodsTried.sort()).toEqual(["DELETE", "POST", "PUT"]);
  });

  it("flags when an alternate method is not rejected", async () => {
    mockSend
      .mockResolvedValueOnce(ok({ status: 403 }))
      .mockResolvedValueOnce(ok({ status: 200 }))
      .mockResolvedValueOnce(ok({ status: 403 }));
    const result = await runMethodTamperingTest(sample({ method: "GET" }));
    expect(result.concern).toBe(true);
  });

  it("does not flag when every alternate method is rejected", async () => {
    mockSend.mockResolvedValue(ok({ status: 405 }));
    const result = await runMethodTamperingTest(sample({ method: "GET" }));
    expect(result.concern).toBe(false);
  });
});

describe("runOpenRedirectTest", () => {
  it("is not applicable without a redirect-shaped parameter", async () => {
    const result = await runOpenRedirectTest(sample({ url: "https://api.example.com/users/1" }));
    expect(result.notApplicable).toBe(true);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it("flags when the browser follows the injected external target", async () => {
    mockSend.mockResolvedValue(ok({ finalUrl: "https://attacker-test.invalid/" }));
    const result = await runOpenRedirectTest(
      sample({ url: "https://api.example.com/login?next=/dashboard" }),
    );
    expect(result.concern).toBe(true);
  });

  it("does not flag when the redirect target is not followed", async () => {
    mockSend.mockResolvedValue(ok({ finalUrl: "https://api.example.com/login?next=%2Fdashboard" }));
    const result = await runOpenRedirectTest(
      sample({ url: "https://api.example.com/login?next=/dashboard" }),
    );
    expect(result.concern).toBe(false);
  });
});

describe("runMassAssignmentTest", () => {
  it("is not applicable without a sample", async () => {
    expect((await runMassAssignmentTest(undefined)).notApplicable).toBe(true);
  });

  it("is not applicable for GET requests", async () => {
    const result = await runMassAssignmentTest(sample({ method: "GET" }));
    expect(result.notApplicable).toBe(true);
  });

  it("is not applicable for a non-JSON body", async () => {
    const result = await runMassAssignmentTest(sample({ method: "POST", requestBody: "not json" }));
    expect(result.notApplicable).toBe(true);
  });

  it("is not applicable when every candidate field is already present", async () => {
    const result = await runMassAssignmentTest(
      sample({
        method: "POST",
        requestBody: JSON.stringify({ role: "user", isAdmin: false, verified: true }),
      }),
    );
    expect(result.notApplicable).toBe(true);
    expect(mockSend).not.toHaveBeenCalled();
  });

  it("injects missing candidate fields and always flags the result as a real write", async () => {
    mockSend.mockResolvedValue(ok({ body: '{"ok":true}' }));
    const result = await runMassAssignmentTest(
      sample({ method: "POST", requestBody: JSON.stringify({ name: "alice" }) }),
    );
    expect(result.concern).toBe(true);
    const sentBody = JSON.parse(mockSend.mock.calls[0]?.[0].body ?? "{}");
    expect(sentBody).toMatchObject({ name: "alice", role: "admin", isAdmin: true, verified: true });
  });

  it("notes when the injected field is reflected in the response", async () => {
    mockSend.mockResolvedValue(ok({ body: '{"role":"admin"}' }));
    const result = await runMassAssignmentTest(
      sample({ method: "POST", requestBody: JSON.stringify({ name: "alice" }) }),
    );
    expect(result.verdict).toContain("reflects the injected field");
  });
});
