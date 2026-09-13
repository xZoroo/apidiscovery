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

export function isInjectedCaptureMessage(data: unknown): data is InjectedCaptureMessage {
  return (
    typeof data === "object" &&
    data !== null &&
    "source" in data &&
    (data as { source: unknown }).source === INJECTED_MESSAGE_SOURCE
  );
}
