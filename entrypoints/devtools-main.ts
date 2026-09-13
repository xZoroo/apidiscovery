/**
 * Registers the "API Discovery" DevTools panel. Uses `chrome.devtools.panels` directly (not
 * `browser.*`) since devtools APIs are accessed the same way in both Chrome and Firefox and
 * this file only ever runs inside the devtools_page context.
 *
 * Wrapped in try/catch (not just `.catch()`) because WXT's fake-browser -- used to introspect
 * entrypoints during `wxt prepare`/`wxt dev` -- throws `create()` synchronously rather than
 * rejecting a promise; real Chrome/Firefox devtools pages return a promise normally.
 */
export default defineUnlistedScript(() => {
  try {
    chrome.devtools.panels.create("API Discovery", "", "/devtools-panel.html").catch(() => {
      // Nothing sensible to do if panel registration fails; DevTools itself will have logged why.
    });
  } catch {
    // See comment above -- expected in WXT's analysis environment, harmless.
  }
});
