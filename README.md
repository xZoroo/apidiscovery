# API Discovery

A Chrome and Firefox extension that passively catalogs the backend API calls a website makes,
mines its JavaScript for endpoints that were never actually called, and flags which endpoints are
worth manually testing in Burp Suite (or similar) — an aid for the recon/enumeration stage of an
authorized security assessment.

This is a recon aid, not a scanner. It never fuzzes, swaps IDs, or attempts auth bypass on its
own. The only request it ever makes beyond what a page itself loads is a manual, opt-in check of
a fixed list of well-known API documentation paths against the current tab's origin.

See `/Users/cory.watson/.claude/plans/do-some-thorough-research-stateful-hearth.md` for the full
design rationale, prior-art survey, and rule table this was built from.

## What it does

- **Passive network capture.** A MAIN-world script patches `fetch`, `XMLHttpRequest`, and
  `WebSocket` in the page's own JS context, capturing full request/response headers and bodies
  with no DevTools dependency and no `chrome.debugger` banner. A `webRequest`-based fallback
  catches metadata for anything the page-world patch might miss.
- **JavaScript mining.** On every page load, external scripts (plus their sourcemaps, when
  available) and inline scripts are scanned for endpoint-shaped URLs and a small set of
  high-signal secret patterns (AWS keys, JWTs, Google API keys, Slack tokens, generic labeled
  secrets) — catching endpoints the page never actually called this session.
- **Deduplicated catalog.** Requests are grouped into one record per `METHOD host/templated/path`
  (e.g. `/users/1` and `/users/2` collapse into `/users/{id}`).
- **Security triage.** A fixed, reviewable rule table flags endpoints worth testing: numeric/UUID/
  ObjectId path segments (IDOR candidates), admin/internal/debug paths, auth-bearing calls,
  state-changing writes on an object ID (BOLA/BFLA), sensitive body fields (mass assignment),
  GraphQL endpoints, JWT-shaped tokens, and unversioned APIs with versioned siblings. Every flag
  shows the concrete rationale that fired it.
- **Dashboard tab + DevTools panel.** A full dashboard tab (opened from the toolbar icon) shows
  the whole catalog with search/filter and exports; a thin DevTools panel shows the same data
  scoped to the inspected tab.
- **Exports.** HAR (importable into Burp's HAR Importer, Burp Pro, or ZAP) and a plain endpoint
  list with reconstructed `curl` commands.
- **Opt-in doc-path probe.** A manual button in the dashboard checks ~15 well-known API-doc paths
  (`/swagger.json`, `/openapi.json`, GraphQL introspection, etc.) against the current tab's
  origin only.

## Build

```sh
npm install
npm run build           # .output/chrome-mv3
npm run build:firefox   # .output/firefox-mv3
```

For live-reload during development: `npm run dev` (Chrome) or `npm run dev:firefox`.

## Load unpacked

- **Chrome:** `chrome://extensions` → enable Developer mode → Load unpacked → select
  `.output/chrome-mv3`.
- **Firefox:** `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → select
  `.output/firefox-mv3/manifest.json`.

## Verify

```sh
npm run typecheck
npm run lint
npm run format:check
npm test
```

Then browse an authorized target (or a local vulnerable demo app such as crAPI or OWASP Juice
Shop) with the extension loaded, and confirm: the dashboard fills in with real captured requests;
an endpoint referenced only in a JS bundle shows up tagged `js-mined`; hitting `/users/1` then
`/users/2` collapses into one `/users/{id}` row; a numeric/UUID-id endpoint shows an IDOR finding;
the DevTools panel shows only the inspected tab's endpoints; the HAR export imports cleanly into
Burp; and capture survives a service-worker restart mid-session.
