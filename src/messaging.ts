/**
 * Shared message-type constants and payload shapes used across entrypoints (injected page
 * script -> content script -> background service worker -> dashboard/devtools panel).
 *
 * Kept in one file, per the plan's module layout, because every messaging participant needs the
 * exact same string literals and payload shapes to agree.
 */

import type { CapturedRequest } from "./capture/types.js";

/** Message posted from `injected.ts` (MAIN world) via `window.postMessage`. */
export const INJECTED_MESSAGE_SOURCE = "apidiscovery" as const;

export interface InjectedCaptureMessage {
  source: typeof INJECTED_MESSAGE_SOURCE;
  /**
   * Proves this message came from `injected.content.ts`, not from the page itself. Both scripts
   * run in the same MAIN-world `window`, so `event.source === window` alone can't tell an
   * injected-script message apart from the page calling `window.postMessage` directly -- without
   * this, any site could plant fabricated capture entries in the dashboard. `content.ts` mints a
   * fresh token per page load and only `injected.content.ts` ever gets to read it; see the
   * handshake comments in both files.
   */
  token: string;
  payload: Omit<CapturedRequest, "id" | "tabId">;
}

/**
 * Message types exchanged over `browser.runtime.sendMessage` / `onMessage`.
 *
 * The opt-in doc-path probe is deliberately NOT a message here: `prober.ts` and `store.ts` need
 * no `browser.*` APIs, so the dashboard calls them directly rather than routing through the
 * background service worker -- one less indirection, and it keeps "the only module that ever
 * probes" (`src/probe/`) entirely out of the background/content-script message surface.
 */
export type RuntimeMessage =
  | { type: "capture"; payload: Omit<CapturedRequest, "id" | "tabId"> }
  | {
      type: "page-scripts";
      pageUrl: string;
      html: string;
      scriptUrls: string[];
      inlineScripts: string[];
    }
  | { type: "endpoint-updated"; key: string }
  | { type: "secrets-updated" };

function isCapturePayloadShape(value: unknown): value is Omit<CapturedRequest, "id" | "tabId"> {
  if (typeof value !== "object" || value === null) return false;
  const p = value as Record<string, unknown>;
  return (
    typeof p["ts"] === "number" &&
    typeof p["method"] === "string" &&
    typeof p["url"] === "string" &&
    typeof p["host"] === "string" &&
    typeof p["path"] === "string" &&
    typeof p["source"] === "string"
  );
}

/** Validates both the anti-forgery token and the payload's shape before it's ever trusted. */
export function isInjectedCaptureMessage(
  data: unknown,
  expectedToken: string,
): data is InjectedCaptureMessage {
  if (typeof data !== "object" || data === null) return false;
  const candidate = data as Record<string, unknown>;
  return (
    candidate["source"] === INJECTED_MESSAGE_SOURCE &&
    expectedToken.length > 0 &&
    candidate["token"] === expectedToken &&
    isCapturePayloadShape(candidate["payload"])
  );
}
