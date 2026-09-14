/**
 * One-click, single-endpoint confirmation tests: each fires a small, bounded number of requests
 * (never a loop, never a sweep across endpoints) to turn a passive finding into a proven result --
 * "does this numeric ID actually leak another user's data" instead of "this ID looks sequential".
 *
 * These are deliberately narrow. There is no "run everything" button and no automated fuzzing --
 * each test is a single, explicit, user-triggered action on the one endpoint currently open, which
 * keeps this tool's threat model where it already was: capable of what a tester deliberately
 * clicks, incapable of running anything on its own.
 */

import { isNumericIdSegment } from "../capture/normalizer.js";
import type { CapturedRequest, HeaderEntry } from "../capture/types.js";
import { decodeJwtParts, findJwtCandidates } from "../score/rules.js";
import { sendRepeaterRequest, type RepeaterError, type RepeaterResponse } from "./sendRequest.js";

export interface ConfirmationOutcome {
  verdict: string;
  /** True when the result is worth a closer manual look (styled as a warning, not an error). */
  concern: boolean;
  /** True when the test couldn't run at all (no id segment, no JWT, no JSON body, ...) -- no request was sent. */
  notApplicable?: boolean;
  rows: { label: string; value: string }[];
  response?: RepeaterResponse | RepeaterError | undefined;
}

function notApplicable(reason: string): ConfirmationOutcome {
  return { verdict: reason, concern: false, notApplicable: true, rows: [] };
}

function requestFailed(response: RepeaterError): ConfirmationOutcome {
  return { verdict: `Request failed: ${response.error}`, concern: false, rows: [], response };
}

const CREDENTIAL_HEADER_NAMES = new Set(["authorization", "cookie", "x-api-key"]);

function base64UrlEncode(text: string): string {
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Substitutes the last numeric ID segment in the path with an adjacent value and compares responses. */
export async function runIdorSubstitutionTest(
  sample: CapturedRequest | undefined,
): Promise<ConfirmationOutcome> {
  if (sample === undefined) return notApplicable("No captured request to test.");
  const url = new URL(sample.url);
  const segments = url.pathname.split("/");
  const index = segments.findLastIndex((s) => isNumericIdSegment(s));
  if (index === -1) return notApplicable("No numeric ID segment found in this URL's path.");
  const original = Number(segments[index]);
  const substituted = original + 1;
  segments[index] = String(substituted);
  url.pathname = segments.join("/");

  const response = await sendRepeaterRequest(
    {
      method: sample.method,
      url: url.toString(),
      headers: sample.requestHeaders ?? [],
      body: sample.requestBody ?? "",
      includeCredentials: true,
    },
    sample.tabId,
  );
  if ("error" in response) return requestFailed(response);

  const originalStatus = sample.responseStatus;
  const succeeded = response.status < 300;
  const bodyDiffers = sample.responseBody !== undefined && response.body !== sample.responseBody;
  const concern = succeeded && bodyDiffers;
  const verdict =
    originalStatus === undefined
      ? "No original response was captured to compare against -- review the result manually."
      : concern
        ? "Returned a different, successful response for a different ID -- review whether this is another user's data (IDOR)."
        : succeeded
          ? "Returned a successful response, but the body matches the original -- inconclusive."
          : "Rejected the substituted ID -- looks authorization-checked.";

  return {
    verdict,
    concern,
    rows: [
      { label: "Original ID", value: String(original) },
      { label: "Substituted ID", value: String(substituted) },
      {
        label: "Original status",
        value: originalStatus === undefined ? "(not captured)" : String(originalStatus),
      },
    ],
    response,
  };
}

/** Resends the request with credential headers stripped, checking for broken access control. */
export async function runUnauthenticatedReplayTest(
  sample: CapturedRequest | undefined,
): Promise<ConfirmationOutcome> {
  if (sample === undefined) return notApplicable("No captured request to test.");
  const headers = (sample.requestHeaders ?? []).filter(
    (h) => !CREDENTIAL_HEADER_NAMES.has(h.name.toLowerCase()),
  );
  const response = await sendRepeaterRequest(
    {
      method: sample.method,
      url: sample.url,
      headers,
      body: sample.requestBody ?? "",
      includeCredentials: false,
    },
    sample.tabId,
  );
  if ("error" in response) return requestFailed(response);

  const concern = response.status < 300;
  return {
    verdict: concern
      ? "Returned a success status with no credentials -- check for broken access control."
      : "Rejected the request without credentials.",
    concern,
    rows: [{ label: "Status without credentials", value: String(response.status) }],
    response,
  };
}

/**
 * Sends from the extension's own context (never the tab), so the browser attaches a genuinely
 * arbitrary Origin header (this extension's own origin) that the target could never have
 * allow-listed in advance -- a spoofed Origin can't be set via `fetch()` headers, so this is the
 * only way to see how the server treats a truly unexpected origin.
 */
export async function runCorsReflectionTest(
  sample: CapturedRequest | undefined,
  exampleUrl: string | undefined,
): Promise<ConfirmationOutcome> {
  const url = sample?.url ?? exampleUrl;
  if (url === undefined) return notApplicable("No URL available to test.");
  const response = await sendRepeaterRequest(
    {
      method: "GET",
      url,
      headers: sample?.requestHeaders ?? [],
      body: "",
      includeCredentials: true,
    },
    null,
  );
  if ("error" in response) return requestFailed(response);

  const allowOrigin = response.headers.find(
    (h) => h.name.toLowerCase() === "access-control-allow-origin",
  )?.value;
  const allowCredentials = response.headers.find(
    (h) => h.name.toLowerCase() === "access-control-allow-credentials",
  )?.value;
  const concern = allowOrigin !== undefined && allowCredentials?.toLowerCase() === "true";
  return {
    verdict: concern
      ? `Reflected an arbitrary Origin ("${allowOrigin}") with Allow-Credentials: true -- likely exploitable CORS misconfiguration.`
      : "Did not grant a credentialed cross-origin response to an arbitrary Origin.",
    concern,
    rows: [
      { label: "Access-Control-Allow-Origin", value: allowOrigin ?? "(not present)" },
      { label: "Access-Control-Allow-Credentials", value: allowCredentials ?? "(not present)" },
    ],
    response,
  };
}

/** Re-signs an observed JWT with alg=none and an empty signature, and resends it. */
export async function runJwtAlgNoneTest(
  sample: CapturedRequest | undefined,
): Promise<ConfirmationOutcome> {
  if (sample === undefined) return notApplicable("No captured request to test.");
  const haystacks = [
    ...(sample.requestHeaders ?? []).map((h) => h.value),
    sample.requestBody,
  ].filter((v): v is string => v !== undefined);
  const token = haystacks.flatMap((h) => findJwtCandidates(h)).at(0);
  if (token === undefined) return notApplicable("No JWT found in this request.");

  const decoded = decodeJwtParts(token);
  if (decoded === null || typeof decoded.header !== "object" || decoded.header === null) {
    return notApplicable("Found a JWT but could not decode its header.");
  }
  const noneHeader = { ...(decoded.header as Record<string, unknown>), alg: "none" };
  const payloadSegment = token.split(".").at(1) ?? "";
  const forgedToken = `${base64UrlEncode(JSON.stringify(noneHeader))}.${payloadSegment}.`;

  const headers: HeaderEntry[] = (sample.requestHeaders ?? []).map((h) =>
    h.value.includes(token) ? { name: h.name, value: h.value.replaceAll(token, forgedToken) } : h,
  );
  const body = sample.requestBody?.includes(token)
    ? sample.requestBody.replaceAll(token, forgedToken)
    : (sample.requestBody ?? "");

  const response = await sendRepeaterRequest(
    { method: sample.method, url: sample.url, headers, body, includeCredentials: true },
    sample.tabId,
  );
  if ("error" in response) return requestFailed(response);

  const concern = response.status < 400;
  return {
    verdict: concern
      ? "Server returned a non-error status for the unsigned (alg=none) token -- check whether authentication was actually bypassed."
      : "Server rejected the unsigned token.",
    concern,
    rows: [{ label: "Forged token", value: forgedToken }],
    response,
  };
}

const TAMPER_CANDIDATE_METHODS = ["GET", "POST", "PUT", "DELETE"];

/** Resends the same URL/headers/body with each alternate method, flagging any that isn't rejected. */
export async function runMethodTamperingTest(
  sample: CapturedRequest | undefined,
): Promise<ConfirmationOutcome> {
  if (sample === undefined) return notApplicable("No captured request to test.");
  const original = sample.method.toUpperCase();
  const candidates = TAMPER_CANDIDATE_METHODS.filter((m) => m !== original);

  const rows: { label: string; value: string }[] = [];
  let concern = false;
  let lastResponse: RepeaterResponse | RepeaterError | undefined;
  for (const method of candidates) {
    const response = await sendRepeaterRequest(
      {
        method,
        url: sample.url,
        headers: sample.requestHeaders ?? [],
        body: sample.requestBody ?? "",
        includeCredentials: true,
      },
      sample.tabId,
    );
    lastResponse = response;
    if ("error" in response) {
      rows.push({ label: method, value: `error: ${response.error}` });
      continue;
    }
    rows.push({
      label: method,
      value: `${String(response.status)} (${String(response.body.length)} bytes)`,
    });
    if (response.status < 400) concern = true;
  }

  return {
    verdict: concern
      ? "At least one unexpected method returned a non-error status -- check whether it performs the same action."
      : "All alternate methods were rejected.",
    concern,
    rows,
    response: lastResponse,
  };
}

const REDIRECT_PARAM_RE = /redirect|return_?to|next|continue|dest|redir/i;
const OPEN_REDIRECT_TEST_TARGET = "https://attacker-test.invalid/";

function findRedirectParam(url: URL): string | undefined {
  for (const key of url.searchParams.keys()) {
    if (REDIRECT_PARAM_RE.test(key)) return key;
  }
  return undefined;
}

/** Substitutes a redirect-shaped query parameter with an external test URL and checks whether the browser follows it there. */
export async function runOpenRedirectTest(
  sample: CapturedRequest | undefined,
): Promise<ConfirmationOutcome> {
  if (sample === undefined) return notApplicable("No captured request to test.");
  const url = new URL(sample.url);
  const param = findRedirectParam(url);
  if (param === undefined) {
    return notApplicable(
      "No redirect-shaped query parameter (redirect, next, return_to, ...) found.",
    );
  }
  url.searchParams.set(param, OPEN_REDIRECT_TEST_TARGET);

  const response = await sendRepeaterRequest(
    {
      method: "GET",
      url: url.toString(),
      headers: sample.requestHeaders ?? [],
      body: "",
      includeCredentials: true,
    },
    sample.tabId,
  );
  if ("error" in response) return requestFailed(response);

  const concern = response.finalUrl.startsWith(OPEN_REDIRECT_TEST_TARGET);
  return {
    verdict: concern
      ? "The browser followed the injected redirect to the external test URL -- open redirect confirmed."
      : "Did not redirect to the injected external target.",
    concern,
    rows: [
      { label: "Injected parameter", value: param },
      { label: "Final URL reached", value: response.finalUrl },
    ],
    response,
  };
}

const MASS_ASSIGNMENT_CANDIDATES: Record<string, unknown> = {
  role: "admin",
  isAdmin: true,
  verified: true,
};

/** Adds attacker-chosen privileged fields to a JSON body and resends it -- performs a real write. */
export async function runMassAssignmentTest(
  sample: CapturedRequest | undefined,
): Promise<ConfirmationOutcome> {
  if (sample === undefined) return notApplicable("No captured request to test.");
  const method = sample.method.toUpperCase();
  if (method === "GET" || method === "HEAD") {
    return notApplicable("This test only applies to state-changing requests (POST/PUT/PATCH).");
  }
  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(sample.requestBody ?? "");
  } catch {
    return notApplicable("This endpoint's request body is not JSON.");
  }
  if (typeof parsedBody !== "object" || parsedBody === null || Array.isArray(parsedBody)) {
    return notApplicable("This endpoint's request body is not a JSON object.");
  }

  const existingKeys = new Set(Object.keys(parsedBody).map((k) => k.toLowerCase()));
  const injected: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(MASS_ASSIGNMENT_CANDIDATES)) {
    if (!existingKeys.has(key.toLowerCase())) injected[key] = value;
  }
  if (Object.keys(injected).length === 0) {
    return notApplicable("All candidate fields are already present in the body.");
  }

  const body = JSON.stringify({ ...parsedBody, ...injected });
  const response = await sendRepeaterRequest(
    {
      method: sample.method,
      url: sample.url,
      headers: sample.requestHeaders ?? [],
      body,
      includeCredentials: true,
    },
    sample.tabId,
  );
  if ("error" in response) return requestFailed(response);

  const reflected = Object.entries(injected).some(
    ([key, value]) => response.body.includes(`"${key}"`) && response.body.includes(String(value)),
  );
  return {
    verdict: reflected
      ? "The response reflects the injected field(s) -- verify whether they were actually applied to stored data."
      : "Injected field(s) not visible in the response -- this sent a real write; check manually whether it was silently applied.",
    concern: true,
    rows: Object.entries(injected).map(([key, value]) => ({ label: key, value: String(value) })),
    response,
  };
}
