/**
 * Isolated-world content script: relays `injected.ts`'s captures to the background service
 * worker, and (on each top-level navigation) sends the page's own already-rendered HTML plus
 * its script tags for the miner to scan -- see plan doc's capture pipeline steps 3 and 6.
 */

import { isInjectedCaptureMessage, type RuntimeMessage } from "../src/messaging.js";

/**
 * Mints a per-page-load anti-forgery token and hands it to `injected.content.ts` via a DOM
 * attribute, which that MAIN-world script reads once and immediately deletes -- see the matching
 * comment there. This isolated-world content script is registered before the MAIN-world one in
 * the manifest (verify in the built output if either file is ever renamed), so the attribute is
 * always set before `injected.content.ts` runs; if that ordering were ever broken, captures would
 * simply stop (the token wouldn't match) rather than silently falling back to the unauthenticated
 * behavior this replaces.
 */
function relayCaptures(): void {
  const token = crypto.randomUUID();
  document.documentElement.dataset["apidiscoveryToken"] = token;

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (!isInjectedCaptureMessage(event.data, token)) return;
    const message: RuntimeMessage = { type: "capture", payload: event.data.payload };
    browser.runtime.sendMessage(message).catch(() => {
      // The background service worker may be mid-restart; the next capture will succeed once
      // it's back up. One dropped capture must not crash the content script.
    });
  });
}

function collectPageScripts(): { scriptUrls: string[]; inlineScripts: string[] } {
  const scripts = [...document.querySelectorAll("script")];
  const scriptUrls = scripts.map((el) => el.src).filter((src): src is string => src.length > 0);
  const inlineScripts = scripts
    .filter((el) => el.src.length === 0)
    .map((el) => el.textContent ?? "")
    .filter((text) => text.length > 0);
  return { scriptUrls, inlineScripts };
}

function sendPageScriptsOnLoad(): void {
  const send = (): void => {
    const { scriptUrls, inlineScripts } = collectPageScripts();
    const message: RuntimeMessage = {
      type: "page-scripts",
      pageUrl: window.location.href,
      html: document.documentElement.outerHTML,
      scriptUrls,
      inlineScripts,
    };
    browser.runtime.sendMessage(message).catch(() => {
      // Same rationale as relayCaptures: a dropped message here just means this page's JS
      // won't be mined this load; it isn't worth surfacing to the user.
    });
  };

  if (document.readyState === "complete") {
    send();
  } else {
    window.addEventListener("load", send, { once: true });
  }
}

export default defineContentScript({
  matches: ["<all_urls>"],
  allFrames: true,
  runAt: "document_start",
  main() {
    relayCaptures();
    sendPageScriptsOnLoad();
  },
});
