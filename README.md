# API Discovery

A Chrome and Firefox extension for security researchers and penetration testers. It passively
catalogs the backend API calls a website makes, mines its JavaScript for endpoints that were never
actually called, flags which endpoints are worth manual testing, and gives you one-click tools to
confirm a finding without leaving the browser or setting up a proxy.

> **Authorized use only.** Only run this against systems you own or have explicit written
> authorization to test. Several features (the opt-in doc-path probe, the Repeater, and the
> Confirmation tests) send real requests to whatever site is currently open, and one of the
> Confirmation tests performs a genuine write. See [Security testing features](#security-testing-features)
> before using anything beyond passive capture.

## What it does

**Passive recon**

- **Network capture.** A MAIN-world script patches `fetch`, `XMLHttpRequest`, and `WebSocket` in
  the page's own JS context, capturing full request/response headers and bodies with no DevTools
  dependency and no `chrome.debugger` banner. A `webRequest`-based fallback catches metadata for
  anything the page-world patch might miss.
- **JavaScript mining.** On every page load, external scripts (plus their sourcemaps, when
  available) and inline scripts are scanned for endpoint-shaped URLs and a small set of
  high-signal secret patterns (AWS keys, JWTs, Google API keys, Slack tokens, generic labeled
  secrets) — catching endpoints the page never actually called this session.
- **Deduplicated catalog.** Requests are grouped into one record per `METHOD host/templated/path`
  (e.g. `/users/1` and `/users/2` collapse into `/users/{id}`), with method/host/path/risk/seen/
  source columns, full-text search, and OWASP-category and severity filters.

**Security triage**

- A fixed, reviewable rule table flags endpoints worth testing, each tagged with an OWASP API
  Security Top 10 (2023) category: numeric/UUID/ObjectId path segments (BOLA/IDOR candidates),
  admin/internal/debug paths, auth-bearing calls, state-changing writes on an object ID (BOLA/
  BFLA), sensitive body fields (mass assignment / BOPLA), GraphQL endpoints, JWT-shaped tokens
  (with inline decoding and an `alg: "none"` warning), CORS misconfiguration (`Access-Control-
Allow-Origin: *` paired with credentials), inconsistent auth across sibling endpoints, and
  unversioned APIs with versioned siblings.
- Every flag shows the exact literal text that triggered it, highlighted in place in the path,
  URL, and rationale — never just a description of the rule.
- Clicking a row (or one of its flag chips) expands the full request/response, the finding list,
  and a decoded-JWT panel when a token was observed.

**Security testing features**

- **Repeater.** Edit a captured request's method, URL, headers, and body, then send it and inspect
  the raw response inline — a single-request Burp Repeater equivalent, with no proxy or CA
  certificate needed. Sends prefer the original tab's own page context (reusing its real cookies/
  session) and fall back to the extension's own context when that tab is gone.
- **Confirmation tests.** Seven one-click, single-endpoint tests that turn a passive finding into
  a proven result: IDOR ID-substitution with response diffing, unauthenticated replay, CORS
  reflection, JWT `alg=none` forging, HTTP method tampering, open-redirect parameter injection,
  and a mass-assignment field probe. Each fires a small, bounded number of requests on click —
  none of them loop, retry, or run on their own.

**Everything else**

- **Dashboard tab + DevTools panel.** A full dashboard tab (opened from the toolbar icon) shows
  the whole catalog with search/filter/sort and exports; a thin DevTools panel shows the same data
  scoped to the inspected tab.
- **Exports.** HAR (importable into Burp's HAR Importer, Burp Pro, or ZAP) and a plain endpoint
  list with reconstructed `curl` commands.
- **Opt-in doc-path probe.** A manual button in the dashboard checks ~15 well-known API-doc paths
  (`/swagger.json`, `/openapi.json`, GraphQL introspection, etc.) against the current tab's origin
  only.
- **Light/dark mode**, toggled from the dashboard header and persisted across sessions.

## How to use

1. [Build](#build) the extension and [load it unpacked](#load-unpacked) in Chrome or Firefox.
2. Browse the target application normally. The extension captures traffic passively in the
   background — no need to open DevTools or the dashboard while you browse.
3. Click the toolbar icon to open the dashboard. Use search, the method/severity/OWASP-category
   filters, or the sortable column headers to find what's worth reviewing; the Flags column is
   sorted by severity by default.
4. Click a row to expand it. Read the finding rationale, check the decoded JWT if one is present,
   and use the Repeater to try a variation of the request by hand, or click a Confirmation test
   button to get an automatic verdict on a specific issue.
5. When you're ready to move into Burp (or another proxy) for deeper testing, use **Export HAR**
   or **Export endpoint list / curl** to carry the catalog over.
6. Only if you have authorization to do so, use the **Active probe** section to check for exposed
   API documentation on the current origin.

## Permissions

| Permission                         | Why                                                                                                                                                                                                                          |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `storage`                          | Small preferences (e.g. theme choice). Bulk data lives in IndexedDB, which needs no permission.                                                                                                                              |
| `webRequest`                       | Non-blocking metadata fallback for requests the page-world patch might miss.                                                                                                                                                 |
| `scripting`                        | Runs the MAIN-world capture patch, and the Repeater's tab-context send path.                                                                                                                                                 |
| `tabs`                             | Reads the active tab's origin for the DevTools filter, the probe's "current origin" lock, and opening the dashboard from the toolbar icon.                                                                                   |
| `host_permissions: ["<all_urls>"]` | Needed for injection, the `webRequest` fallback, JS-mining fetches, and the Repeater/Confirmation tests to work against whatever site is under test. This is the one broad permission this class of tool structurally needs. |

Deliberately **not** requested: `debugger` (would show Chrome's "this browser is being debugged"
banner and conflicts with continuous background capture alongside a real, open DevTools panel).

All data stays local in the browser's IndexedDB. Nothing is ever transmitted off the device.

## Known limitations

- **JavaScript mining fetches run on every site you visit while the extension is enabled**, not
  only ones you're actively testing. It fetches whatever URLs appear in that page's own `<script
src>` tags from the privileged background context (deliberately bypassing the page's CORS and
  CSP, the same way any script-mining tool must) so it can scan them for endpoints/secrets. A page
  that points a script tag at an internal or unexpected address will cause that fetch to happen.
  If you want mining scoped only to targets you've opted into, disable the extension between
  engagements rather than leaving it on for general browsing.
- **The Repeater and Confirmation tests, when sent through a live tab's own page context, run
  inside that page's real JavaScript realm.** A target that has instrumented or overridden its own
  `fetch`/`XMLHttpRequest` could tamper with what these features send or see, which would falsify
  a test's verdict. This is an inherent trade-off of a proxy-less, certificate-less repeater; a
  traditional MITM proxy like Burp doesn't have this limitation because it sits outside the page
  entirely.
- **The passive capture bridge (page → extension) is authenticated with a per-page-load token**,
  so a hostile page can no longer forge fake capture entries into your dashboard. It cannot,
  however, prevent a page from simply not calling the endpoints it references, or from lying in
  its own responses -- this tool reports what a server actually said, not whether that server told
  the truth.

## Build

```sh
npm install
npm run build           # output/chrome-mv3
npm run build:firefox   # output/firefox-mv3
```

For live-reload during development: `npm run dev` (Chrome) or `npm run dev:firefox`.

## Load unpacked

- **Chrome:** `chrome://extensions` → enable Developer mode → Load unpacked → select
  `output/chrome-mv3`.
- **Firefox:** `about:debugging#/runtime/this-firefox` → Load Temporary Add-on → select
  `output/firefox-mv3/manifest.json`.

## Development

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

## Security

See [SECURITY.md](SECURITY.md) for how to report a vulnerability in this extension itself.
