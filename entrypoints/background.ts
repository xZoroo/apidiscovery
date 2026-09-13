/**
 * Background service worker: relays captures into the store, mines page HTML/scripts on
 * navigation, watches network traffic as a metadata-only fallback, and opens the dashboard from
 * the toolbar icon. See plan doc's "Capture pipeline" (steps 4-5) and permissions rationale.
 */

import { splitUrl } from "../src/capture/normalizer.js";
import { upsertCapture, upsertSecret } from "../src/capture/store.js";
import type { CapturedRequest, HeaderEntry } from "../src/capture/types.js";
import { fetchScriptWithSourceMap } from "../src/mine/fetcher.js";
import { mineBlobs, type ScriptBlob } from "../src/mine/miner.js";
import type { RuntimeMessage } from "../src/messaging.js";

function broadcast(message: RuntimeMessage): void {
  browser.runtime.sendMessage(message).catch(() => {
    // No listener is currently open (dashboard/devtools panel closed) -- nothing to notify.
  });
}

async function handleCapture(
  payload: Omit<CapturedRequest, "id" | "tabId">,
  tabId: number | null,
): Promise<void> {
  const request: CapturedRequest = { id: crypto.randomUUID(), tabId, ...payload };
  const key = await upsertCapture(request);
  broadcast({ type: "endpoint-updated", key });
}

function inlineScriptBlobs(pageUrl: string, inlineScripts: string[]): ScriptBlob[] {
  return inlineScripts.map((text, index) => ({ sourceUrl: `${pageUrl}#inline-${index}`, text }));
}

async function mineEndpoint(url: string): Promise<void> {
  const { host, path } = splitUrl(url);
  const key = await upsertCapture({
    id: crypto.randomUUID(),
    ts: Date.now(),
    tabId: null,
    method: "GET",
    url,
    host,
    path,
    source: "js-mined",
  });
  broadcast({ type: "endpoint-updated", key });
}

async function handlePageScripts(
  message: Extract<RuntimeMessage, { type: "page-scripts" }>,
): Promise<void> {
  const externalBlobsByScript = await Promise.all(
    message.scriptUrls.map((url) => fetchScriptWithSourceMap(url)),
  );
  const blobs: ScriptBlob[] = [
    { sourceUrl: message.pageUrl, text: message.html },
    ...externalBlobsByScript.flat(),
    ...inlineScriptBlobs(message.pageUrl, message.inlineScripts),
  ];

  const { endpoints, secrets } = mineBlobs(blobs);
  await Promise.all(endpoints.map((endpoint) => mineEndpoint(endpoint.url)));
  await Promise.all(
    secrets.map((secret) =>
      upsertSecret({
        label: secret.label,
        match: secret.match,
        sourceFile: secret.sourceFile,
        ts: Date.now(),
      }),
    ),
  );
  if (secrets.length > 0) broadcast({ type: "secrets-updated" });
}

function registerMessageListener(): void {
  browser.runtime.onMessage.addListener((message: RuntimeMessage, sender) => {
    if (message.type === "capture") {
      return handleCapture(message.payload, sender.tab?.id ?? null);
    }
    if (message.type === "page-scripts") {
      return handlePageScripts(message);
    }
    return undefined;
  });
}

/**
 * Secondary, metadata-only capture path for API calls the MAIN-world patch might miss (e.g. a
 * page whose CSP blocked the injection). No bodies are available here -- see plan doc's MV3
 * capture constraints. Scoped to `xmlhttprequest` (covers both `fetch` and `XHR`) and
 * `websocket` resource types to avoid flooding the catalog with every image/font/script load.
 */
function registerWebRequestFallback(): void {
  browser.webRequest.onCompleted.addListener(
    (details) => {
      const { host, path } = splitUrl(details.url);
      const responseHeaders: HeaderEntry[] = (details.responseHeaders ?? []).map((header) => ({
        name: header.name,
        value: header.value ?? "",
      }));
      void handleCapture(
        {
          ts: Date.now(),
          method: details.method,
          url: details.url,
          host,
          path,
          responseStatus: details.statusCode,
          responseHeaders,
          source: "webRequest",
        },
        details.tabId >= 0 ? details.tabId : null,
      );
    },
    { urls: ["<all_urls>"], types: ["xmlhttprequest", "websocket"] },
    ["responseHeaders"],
  );
}

function registerActionClick(): void {
  browser.action.onClicked.addListener((tab) => {
    const origin = tab.url !== undefined ? new URL(tab.url).origin : undefined;
    const url =
      origin === undefined
        ? browser.runtime.getURL("/dashboard.html")
        : browser.runtime.getURL(`/dashboard.html?origin=${encodeURIComponent(origin)}`);
    void browser.tabs.create({ url });
  });
}

export default defineBackground(() => {
  registerMessageListener();
  registerWebRequestFallback();
  registerActionClick();
});
