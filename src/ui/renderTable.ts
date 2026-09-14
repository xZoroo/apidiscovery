/**
 * Shared render logic for the dashboard and devtools panel (the plan's "two real consumers" that
 * earn a shared module). Every captured value (URL, header, body) is attacker-controlled -- it
 * comes straight from the site under test -- so this file only ever sets `textContent`, never
 * `innerHTML`, on anything derived from captured data.
 *
 * Styling uses Tailwind utility classes on top of the custom color tokens in
 * assets/tailwind.css; this file owns the DOM structure and severity/method color mapping so the
 * dashboard and devtools panel render identically without duplicating markup. Most surface/text
 * colors below (bg-surface, text-ink, border-line, ...) need no separate `dark:` variant --
 * those tokens are redefined under `.dark` in the stylesheet instead.
 */

import { buildConfirmationTestsSection } from "./confirmationTestsView.js";
import {
  formatHeaderLines,
  parseHeaderLines,
  sendRepeaterRequest,
  type RepeaterError,
  type RepeaterRequest,
  type RepeaterResponse,
} from "../repeater/sendRequest.js";
import { decodeJwtParts, findJwtCandidates } from "../score/rules.js";
import { maxSeverity } from "../score/scorer.js";
import type {
  CapturedRequest,
  EndpointRecord,
  Finding,
  HeaderEntry,
  Severity,
  StoredSecret,
} from "../capture/types.js";

// ---------------------------------------------------------------------------
// Color mapping -- severity is the one place this UI spends bold, saturated
// color (solid badge fills); HTTP methods are quiet colored text with no
// background, so they never compete with the severity signal for attention.
// ---------------------------------------------------------------------------

export const SEVERITY_STYLES: Record<Severity, { badge: string; callout: string; icon: string }> = {
  high: {
    badge: "bg-risk-high text-white",
    callout: "border-risk-high bg-risk-high/8",
    icon: "text-risk-high",
  },
  medium: {
    badge: "bg-risk-medium text-white",
    callout: "border-risk-medium bg-risk-medium/8",
    icon: "text-risk-medium",
  },
  low: {
    badge: "bg-risk-low text-white",
    callout: "border-risk-low bg-risk-low/8",
    icon: "text-risk-low",
  },
};

const METHOD_TEXT_STYLES: Record<string, string> = {
  POST: "text-method-post",
  PUT: "text-method-put",
  PATCH: "text-method-put",
  DELETE: "text-method-delete",
};
const DEFAULT_METHOD_TEXT_STYLE = "text-ink-muted";

function severityIconPath(severity: Severity): string {
  if (severity === "high") {
    // Triangle exclamation
    return "M12 2 1 21h22L12 2Zm0 6v6m0 3h.01";
  }
  if (severity === "medium") {
    // Exclamation circle
    return "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Zm0-14v5m0 3h.01";
  }
  // Info circle (low)
  return "M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20Zm0-11v6m0-9h.01";
}

function severityIcon(severity: Severity): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  // Explicit width/height (not just a Tailwind size class) so the icon has a fixed intrinsic
  // size no matter what: an SVG with only a viewBox is a flex item with no constrained size, and
  // the browser's default `align-items: stretch` would otherwise blow it up to the row's height.
  svg.setAttribute("width", "16");
  svg.setAttribute("height", "16");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("class", `mt-0.5 shrink-0 ${SEVERITY_STYLES[severity].icon}`);
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", severityIconPath(severity));
  svg.appendChild(path);
  return svg;
}

export function badge(text: string, className: string): HTMLSpanElement {
  const span = document.createElement("span");
  span.className = `inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${className}`;
  span.textContent = text;
  return span;
}

/** Quiet outline-style tag for secondary metadata (OWASP category, capture source). */
function tag(text: string): HTMLSpanElement {
  return badge(text, "border border-line text-ink-muted");
}

export function methodLabel(method: string): HTMLSpanElement {
  const span = document.createElement("span");
  span.className = `font-mono text-sm font-semibold ${METHOD_TEXT_STYLES[method] ?? DEFAULT_METHOD_TEXT_STYLE}`;
  span.textContent = method;
  return span;
}

// ---------------------------------------------------------------------------
// Highlighting -- wraps the exact literal text a rule flagged (Finding.matchedValue)
// wherever it appears in displayed text, so the reviewer sees precisely what was
// flagged in context, not just a description of it.
// ---------------------------------------------------------------------------

export interface HighlightSegment {
  text: string;
  highlighted: boolean;
}

/**
 * Wraps `term` in word-boundary assertions on whichever sides start/end on a word character.
 * Without this, a short numeric ID like "1" (a very common {@link Finding.matchedValue}) would
 * match as a plain substring inside "2026", "v1", or any other unrelated number/word, painting
 * huge swaths of unrelated text yellow on a real, high-volume capture.
 */
function boundaryPattern(term: string): string {
  const escaped = escapeRegExp(term);
  const startsWithWordChar = /^\w/.test(term);
  const endsWithWordChar = /\w$/.test(term);
  return `${startsWithWordChar ? "\\b" : ""}${escaped}${endsWithWordChar ? "\\b" : ""}`;
}

/**
 * Splits `text` into segments, marking which ones exactly match a term in `terms` (word-boundary
 * aware -- see {@link boundaryPattern}). Pure and DOM-free so the matching behavior itself is
 * directly unit-testable without a browser.
 */
export function splitHighlightSegments(text: string, terms: string[]): HighlightSegment[] {
  const uniqueTerms = [...new Set(terms)].filter((t) => t.length > 0);
  if (uniqueTerms.length === 0) return [{ text, highlighted: false }];
  const pattern = new RegExp(`(${uniqueTerms.map(boundaryPattern).join("|")})`, "g");
  return text
    .split(pattern)
    .filter((part) => part.length > 0)
    .map((part) => ({ text: part, highlighted: uniqueTerms.includes(part) }));
}

function appendHighlighted(container: HTMLElement, text: string, terms: string[]): void {
  for (const segment of splitHighlightSegments(text, terms)) {
    if (segment.highlighted) {
      const mark = document.createElement("mark");
      mark.className = "rounded bg-mark px-0.5 font-semibold text-mark-ink";
      mark.textContent = segment.text;
      container.appendChild(mark);
    } else {
      container.appendChild(document.createTextNode(segment.text));
    }
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function matchedValues(findings: Finding[]): string[] {
  return findings.map((f) => f.matchedValue).filter((v): v is string => v !== undefined);
}

// ---------------------------------------------------------------------------
// Endpoint table rows
// ---------------------------------------------------------------------------

/** Called when a row (or one of its flag chips) is clicked. `focusRuleId` is set only for a chip click. */
export type SelectHandler = (endpoint: EndpointRecord, focusRuleId?: string) => void;

function cell(className = ""): HTMLTableCellElement {
  const td = document.createElement("td");
  td.className = `px-3 py-2.5 align-top text-sm ${className}`;
  return td;
}

/** Distinct rules present in `findings` (by ruleId), most severe first -- what the row's chips show. */
function distinctRuleChips(
  findings: Finding[],
): { ruleId: string; label: string; severity: Severity }[] {
  const order: Severity[] = ["high", "medium", "low"];
  const seen = new Map<string, { ruleId: string; label: string; severity: Severity }>();
  for (const finding of findings) {
    if (!seen.has(finding.ruleId)) {
      seen.set(finding.ruleId, {
        ruleId: finding.ruleId,
        label: finding.label,
        severity: finding.severity,
      });
    }
  }
  return [...seen.values()].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

function buildFlagsCell(endpoint: EndpointRecord, onSelect: SelectHandler): HTMLTableCellElement {
  const td = cell();
  const findings = endpoint.findings;
  if (findings.length === 0) {
    const span = document.createElement("span");
    span.className = "text-xs text-ink-muted";
    span.textContent = "—";
    td.appendChild(span);
    return td;
  }
  const wrap = document.createElement("div");
  wrap.className = "flex flex-wrap gap-1";
  const chips = distinctRuleChips(findings);
  const MAX_VISIBLE = 3;
  for (const chip of chips.slice(0, MAX_VISIBLE)) {
    const chipEl = badge(chip.label, `cursor-pointer ${SEVERITY_STYLES[chip.severity].badge}`);
    chipEl.title = "Click to jump to this finding";
    chipEl.addEventListener("click", (event) => {
      event.stopPropagation();
      onSelect(endpoint, chip.ruleId);
    });
    wrap.appendChild(chipEl);
  }
  if (chips.length > MAX_VISIBLE) {
    wrap.appendChild(
      badge(
        `+${String(chips.length - MAX_VISIBLE)}`,
        SEVERITY_STYLES[chips[0]?.severity ?? "low"].badge,
      ),
    );
  }
  td.appendChild(wrap);
  return td;
}

function buildPathCell(endpoint: EndpointRecord): HTMLTableCellElement {
  // truncate (not wrap) so a long real-world path can't force this fixed-width column to
  // steal space from Flags/Seen/Source -- the full value is still available via the title
  // attribute (hover tooltip) and, more importantly, by clicking the row to open the detail view.
  const td = cell("truncate font-mono text-ink");
  td.title = endpoint.templatedPath;
  appendHighlighted(td, endpoint.templatedPath, matchedValues(endpoint.findings));
  return td;
}

function buildEndpointRow(endpoint: EndpointRecord, onSelect: SelectHandler): HTMLTableRowElement {
  const row = document.createElement("tr");
  row.className = "cursor-pointer border-b border-line last:border-0 hover:bg-page";

  const methodCell = cell();
  methodCell.appendChild(methodLabel(endpoint.method));

  const hostCell = cell("truncate font-mono text-ink-muted");
  hostCell.title = endpoint.host;
  hostCell.textContent = endpoint.host;

  const seenCell = cell("text-ink-muted tabular-nums");
  seenCell.textContent = String(endpoint.seenCount);

  const sourceCell = cell();
  const sourceWrap = document.createElement("div");
  sourceWrap.className = "flex flex-wrap gap-1";
  for (const source of endpoint.sources) {
    sourceWrap.appendChild(tag(source));
  }
  sourceCell.appendChild(sourceWrap);

  row.append(
    methodCell,
    hostCell,
    buildPathCell(endpoint),
    buildFlagsCell(endpoint, onSelect),
    seenCell,
    sourceCell,
  );
  row.addEventListener("click", () => {
    onSelect(endpoint);
  });
  return row;
}

/** Renders one row per endpoint into `tbody`, replacing any existing rows. */
export function renderEndpointRows(
  tbody: HTMLTableSectionElement,
  endpoints: EndpointRecord[],
  onSelect: SelectHandler,
): void {
  if (endpoints.length === 0) {
    const row = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 6;
    td.className = "px-3 py-10 text-center text-sm text-ink-muted";
    td.textContent =
      "No endpoints match the current filters. Browse the target site, or clear filters, to see more.";
    row.appendChild(td);
    tbody.replaceChildren(row);
    return;
  }
  tbody.replaceChildren(...endpoints.map((endpoint) => buildEndpointRow(endpoint, onSelect)));
}

// ---------------------------------------------------------------------------
// Detail view -- security findings as callout cards, then request/response.
// ---------------------------------------------------------------------------

function buildFindingCallout(finding: Finding, focused: boolean): HTMLElement {
  const box = document.createElement("div");
  box.dataset["ruleId"] = finding.ruleId;
  const focusRing = focused ? " ring-2 ring-brand ring-offset-1 ring-offset-surface" : "";
  box.className = `flex items-start gap-2 rounded-md border-l-4 p-3 ${SEVERITY_STYLES[finding.severity].callout}${focusRing}`;

  box.appendChild(severityIcon(finding.severity));

  const body = document.createElement("div");
  body.className = "min-w-0 flex-1";

  const heading = document.createElement("div");
  heading.className = "flex flex-wrap items-center gap-2";
  const label = document.createElement("span");
  label.className = "text-sm font-semibold text-ink";
  label.textContent = finding.label;
  heading.append(label, badge(finding.severity, SEVERITY_STYLES[finding.severity].badge));
  if (finding.owaspCategory !== undefined) heading.appendChild(tag(finding.owaspCategory));

  const rationale = document.createElement("p");
  rationale.className = "mt-1 text-sm text-ink-muted";
  appendHighlighted(
    rationale,
    finding.rationale,
    finding.matchedValue !== undefined ? [finding.matchedValue] : [],
  );

  body.append(heading, rationale);
  box.appendChild(body);
  return box;
}

function buildFindingsSection(
  findings: Finding[],
  focusRuleId: string | undefined,
): HTMLElement | null {
  if (findings.length === 0) return null;
  const section = document.createElement("div");
  section.className = "space-y-2";
  const heading = document.createElement("h3");
  heading.className = "text-xs font-semibold uppercase tracking-wide text-ink-muted";
  heading.textContent = `Security findings (${String(findings.length)})`;
  section.appendChild(heading);
  for (const finding of findings) {
    section.appendChild(buildFindingCallout(finding, finding.ruleId === focusRuleId));
  }
  return section;
}

function buildHeadersList(headers: HeaderEntry[] | undefined): HTMLElement {
  const wrap = document.createElement("dl");
  wrap.className = "divide-y divide-line text-xs";
  for (const header of headers ?? []) {
    const row = document.createElement("div");
    row.className = "flex gap-2 py-1";
    const dt = document.createElement("dt");
    dt.className = "w-40 shrink-0 font-mono text-ink-muted";
    dt.textContent = header.name;
    const dd = document.createElement("dd");
    dd.className = "min-w-0 flex-1 break-all font-mono text-ink";
    dd.textContent = header.value;
    row.append(dt, dd);
    wrap.appendChild(row);
  }
  if ((headers ?? []).length === 0) {
    const empty = document.createElement("p");
    empty.className = "text-xs text-ink-muted";
    empty.textContent = "No headers captured.";
    wrap.appendChild(empty);
  }
  return wrap;
}

/** Pretty-prints a body as JSON when it parses as such, otherwise shows the raw text. */
function buildBodyPre(body: string | undefined): HTMLPreElement {
  const pre = document.createElement("pre");
  pre.className = "mt-2 max-h-60 overflow-auto rounded-md bg-ink p-3 text-xs text-page";
  if (body === undefined) {
    pre.textContent = "(no body)";
    pre.className += " italic opacity-60";
    return pre;
  }
  try {
    pre.textContent = JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    pre.textContent = body;
  }
  return pre;
}

function buildExchangeBlock(
  title: string,
  headers: HeaderEntry[] | undefined,
  body: string | undefined,
): HTMLElement {
  const section = document.createElement("div");
  const heading = document.createElement("h4");
  heading.className = "text-xs font-semibold uppercase tracking-wide text-ink-muted";
  heading.textContent = title;
  section.append(heading, buildHeadersList(headers), buildBodyPre(body));
  return section;
}

/**
 * Shown instead of a request/response block when the endpoint has no stored sample -- e.g. it
 * was only ever found by mining JavaScript, and the page itself never actually called it. Without
 * this, clicking such a row looked exactly like clicking did nothing.
 */
function buildNoSampleNotice(endpoint: EndpointRecord): HTMLElement {
  const box = document.createElement("div");
  box.className = "rounded-md border border-dashed border-line p-3 text-xs text-ink-muted";
  const onlyMined = endpoint.sources.every((s) => s === "js-mined");
  box.textContent = onlyMined
    ? "No captured request/response yet -- this endpoint was found by scanning JavaScript, not by observing real traffic. Browse the site so it actually calls this endpoint, then reopen this row."
    : "No request/response body was captured for this endpoint (metadata-only capture can't see bodies). Browse the site again with this endpoint active to capture a full example.";
  return box;
}

function buildRequestResponseBlock(request: CapturedRequest): HTMLElement {
  const wrapper = document.createElement("div");
  wrapper.className = "space-y-2";

  const heading = document.createElement("h3");
  heading.className = "text-xs font-semibold uppercase tracking-wide text-ink-muted";
  heading.textContent = "Request & response";
  wrapper.appendChild(heading);

  const grid = document.createElement("div");
  grid.className = "grid grid-cols-1 gap-4 sm:grid-cols-2";
  grid.append(
    buildExchangeBlock("Request", request.requestHeaders, request.requestBody),
    buildExchangeBlock(
      request.responseStatus === undefined
        ? "Response"
        : `Response — ${String(request.responseStatus)}`,
      request.responseHeaders,
      request.responseBody,
    ),
  );
  wrapper.appendChild(grid);
  return wrapper;
}

// ---------------------------------------------------------------------------
// JWT decode -- a manual-testing helper: find the first JWT in the sample
// requests and decode it locally (no signature verification -- this is a
// recon aid, not a validator).
// ---------------------------------------------------------------------------

function extractFirstJwt(requests: CapturedRequest[]): string | undefined {
  for (const request of requests) {
    const texts = [
      ...(request.requestHeaders ?? []).map((h) => h.value),
      ...(request.responseHeaders ?? []).map((h) => h.value),
      request.requestBody,
      request.responseBody,
    ];
    for (const text of texts) {
      if (text === undefined) continue;
      const [first] = findJwtCandidates(text);
      if (first !== undefined) return first;
    }
  }
  return undefined;
}

function jwtAlg(header: unknown): string | undefined {
  if (typeof header !== "object" || header === null) return undefined;
  const alg = (header as Record<string, unknown>)["alg"];
  return typeof alg === "string" ? alg : undefined;
}

function buildJwtSection(sampleRequests: CapturedRequest[]): HTMLElement | null {
  const token = extractFirstJwt(sampleRequests);
  if (token === undefined) return null;

  const section = document.createElement("div");
  const heading = document.createElement("h3");
  heading.className = "text-xs font-semibold uppercase tracking-wide text-ink-muted";
  heading.textContent = "Decoded JWT";
  section.appendChild(heading);

  const decoded = decodeJwtParts(token);
  if (decoded === null) {
    const p = document.createElement("p");
    p.className = "mt-1 text-xs text-ink-muted";
    p.textContent = "Found a JWT-shaped token but could not decode it.";
    section.appendChild(p);
    return section;
  }

  const alg = jwtAlg(decoded.header);
  if (alg?.toLowerCase() === "none") {
    const warning = document.createElement("p");
    warning.className = "mt-1 text-xs font-semibold text-risk-high";
    warning.textContent = 'alg is "none" -- test whether the server accepts an unsigned token.';
    section.appendChild(warning);
  }

  const pre = document.createElement("pre");
  pre.className = "mt-2 max-h-40 overflow-auto rounded-md bg-ink p-3 text-xs text-page";
  pre.textContent = JSON.stringify({ header: decoded.header, payload: decoded.payload }, null, 2);
  section.appendChild(pre);
  return section;
}

// ---------------------------------------------------------------------------
// Repeater -- edit and resend a captured request. Visually flagged like the dashboard's opt-in
// probe section (same risk-medium border) because, unlike the rest of this tool, clicking Send
// here does send a real request to the target.
// ---------------------------------------------------------------------------

function buildRepeaterResponseView(result: RepeaterResponse | RepeaterError): HTMLElement {
  if ("error" in result) {
    const box = document.createElement("div");
    box.className =
      "rounded-md border border-risk-high/40 bg-risk-high/8 p-3 text-xs text-risk-high";
    box.textContent = `Request failed: ${result.error}`;
    return box;
  }
  const wrapper = document.createElement("div");
  wrapper.className = "space-y-2";
  const status = document.createElement("p");
  status.className = "font-mono text-sm font-semibold text-ink";
  status.textContent = `${String(result.status)} ${result.statusText} — ${String(result.timedMs)}ms`;
  wrapper.append(status, buildHeadersList(result.headers), buildBodyPre(result.body));
  return wrapper;
}

function buildRepeaterSection(
  endpoint: EndpointRecord,
  sample: CapturedRequest | undefined,
): HTMLElement {
  const section = document.createElement("div");
  section.className = "space-y-3 rounded-lg border border-risk-medium/40 bg-risk-medium/10 p-4";

  const heading = document.createElement("h3");
  heading.className = "text-sm font-semibold text-risk-medium";
  heading.textContent = "Repeater";
  const warning = document.createElement("p");
  warning.className = "text-xs text-ink-muted";
  warning.textContent =
    "Sends a real, editable request straight from your browser -- no proxy or certificate needed. " +
    "Browser-managed headers (Host, Cookie, Content-Length, ...) can't be overridden here. Only use " +
    "this against systems you are authorized to test.";
  section.append(heading, warning);

  const inputClass =
    "rounded-md border border-line bg-surface px-2 py-1 font-mono text-sm text-ink focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand";

  const row = document.createElement("div");
  row.className = "flex gap-2";
  const methodInput = document.createElement("input");
  methodInput.type = "text";
  methodInput.spellcheck = false;
  methodInput.value = sample?.method ?? endpoint.method;
  methodInput.className = `w-24 uppercase ${inputClass}`;
  const urlInput = document.createElement("input");
  urlInput.type = "text";
  urlInput.spellcheck = false;
  urlInput.value =
    sample?.url ?? endpoint.exampleUrls[0] ?? `https://${endpoint.host}${endpoint.templatedPath}`;
  urlInput.className = `min-w-0 flex-1 ${inputClass}`;
  row.append(methodInput, urlInput);

  const textareaClass =
    "w-full rounded-md border border-line bg-surface p-2 font-mono text-xs text-ink focus:border-brand focus:outline-none focus:ring-1 focus:ring-brand";
  const headersTextarea = document.createElement("textarea");
  headersTextarea.rows = 4;
  headersTextarea.spellcheck = false;
  headersTextarea.placeholder = "Header-Name: value (one per line)";
  headersTextarea.value = formatHeaderLines(sample?.requestHeaders ?? []);
  headersTextarea.className = textareaClass;

  const bodyTextarea = document.createElement("textarea");
  bodyTextarea.rows = 4;
  bodyTextarea.spellcheck = false;
  bodyTextarea.placeholder = "Request body";
  bodyTextarea.value = sample?.requestBody ?? "";
  bodyTextarea.className = textareaClass;

  const credentialsLabel = document.createElement("label");
  credentialsLabel.className = "flex items-center gap-2 text-xs text-ink-muted";
  const credentialsCheckbox = document.createElement("input");
  credentialsCheckbox.type = "checkbox";
  credentialsCheckbox.checked = true;
  credentialsLabel.append(
    credentialsCheckbox,
    document.createTextNode("Include cookies/credentials"),
  );

  const sendButton = document.createElement("button");
  sendButton.type = "button";
  sendButton.textContent = "Send";
  sendButton.className =
    "rounded-md bg-risk-medium px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50";

  const controlsRow = document.createElement("div");
  controlsRow.className = "flex items-center gap-3";
  controlsRow.append(sendButton, credentialsLabel);

  const responseContainer = document.createElement("div");

  sendButton.addEventListener("click", () => {
    sendButton.disabled = true;
    sendButton.textContent = "Sending…";
    const request: RepeaterRequest = {
      method: methodInput.value,
      url: urlInput.value,
      headers: parseHeaderLines(headersTextarea.value),
      body: bodyTextarea.value,
      includeCredentials: credentialsCheckbox.checked,
    };
    void sendRepeaterRequest(request, sample?.tabId ?? null).then((result) => {
      sendButton.disabled = false;
      sendButton.textContent = "Send";
      responseContainer.replaceChildren(buildRepeaterResponseView(result));
    });
  });

  section.append(row, headersTextarea, bodyTextarea, controlsRow, responseContainer);
  return section;
}

/**
 * Renders the expanded detail view for one endpoint: example URLs, its findings as callout
 * cards (the one matching `focusRuleId` gets a highlight ring and is scrolled into view), a
 * decoded-JWT helper when a token was observed, and one representative request/response.
 */
export function renderDetail(
  container: HTMLElement,
  endpoint: EndpointRecord,
  sampleRequests: CapturedRequest[],
  focusRuleId?: string,
): void {
  container.replaceChildren();
  container.className = "space-y-4 rounded-lg border border-line bg-surface p-4";

  const heading = document.createElement("div");
  heading.className = "flex flex-wrap items-center gap-2";
  heading.appendChild(methodLabel(endpoint.method));
  const pathHeading = document.createElement("span");
  pathHeading.className = "font-mono text-sm text-ink";
  appendHighlighted(
    pathHeading,
    `${endpoint.host}${endpoint.templatedPath}`,
    matchedValues(endpoint.findings),
  );
  heading.appendChild(pathHeading);
  container.appendChild(heading);

  const urlList = document.createElement("ul");
  urlList.className = "space-y-0.5 font-mono text-xs text-ink-muted";
  for (const url of endpoint.exampleUrls) {
    const li = document.createElement("li");
    li.className = "truncate";
    appendHighlighted(li, url, matchedValues(endpoint.findings));
    urlList.appendChild(li);
  }
  container.appendChild(urlList);

  const findingsSection = buildFindingsSection(endpoint.findings, focusRuleId);
  if (findingsSection !== null) container.appendChild(findingsSection);

  const jwtSection = buildJwtSection(sampleRequests);
  if (jwtSection !== null) container.appendChild(jwtSection);

  const sample = sampleRequests.at(-1);
  container.appendChild(
    sample !== undefined ? buildRequestResponseBlock(sample) : buildNoSampleNotice(endpoint),
  );
  container.appendChild(buildRepeaterSection(endpoint, sample));
  container.appendChild(buildConfirmationTestsSection(endpoint, sample));

  // Always bring the detail panel into view on selection, not just when a specific finding is
  // focused -- otherwise, on a long endpoint list, clicking a row can silently update a detail
  // panel that's off the bottom of the screen, which looks exactly like "nothing happened".
  if (focusRuleId !== undefined) {
    const focused = container.querySelector(`[data-rule-id="${focusRuleId}"]`);
    focused?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  } else {
    container.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }
}

// ---------------------------------------------------------------------------
// Secrets table
// ---------------------------------------------------------------------------

/** Renders one row per found secret into `tbody`, replacing any existing rows. */
export function renderSecretRows(tbody: HTMLTableSectionElement, secrets: StoredSecret[]): void {
  if (secrets.length === 0) {
    const row = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 3;
    td.className = "px-3 py-6 text-center text-sm text-ink-muted";
    td.textContent = "No secrets found in scanned JavaScript.";
    row.appendChild(td);
    tbody.replaceChildren(row);
    return;
  }
  tbody.replaceChildren(
    ...secrets.map((secret) => {
      const row = document.createElement("tr");
      row.className = "border-b border-line last:border-0";

      const labelCell = cell();
      labelCell.appendChild(badge(secret.label, SEVERITY_STYLES.high.badge));

      const matchCell = cell("font-mono text-ink");
      matchCell.textContent = secret.match;

      const sourceCell = cell("font-mono text-ink-muted");
      sourceCell.textContent = secret.sourceFile;

      row.append(labelCell, matchCell, sourceCell);
      return row;
    }),
  );
}

// ---------------------------------------------------------------------------
// Summary stat cards (dashboard only)
// ---------------------------------------------------------------------------

export interface CatalogSummary {
  total: number;
  high: number;
  medium: number;
  low: number;
  secrets: number;
}

export function summarize(endpoints: EndpointRecord[], secrets: StoredSecret[]): CatalogSummary {
  let high = 0;
  let medium = 0;
  let low = 0;
  for (const endpoint of endpoints) {
    const severity = maxSeverity(endpoint.findings);
    if (severity === "high") high += 1;
    else if (severity === "medium") medium += 1;
    else if (severity === "low") low += 1;
  }
  return { total: endpoints.length, high, medium, low, secrets: secrets.length };
}

function buildStatCard(label: string, value: number, accentClass: string): HTMLElement {
  const card = document.createElement("div");
  card.className = "rounded-lg border border-line bg-surface p-4";
  const valueEl = document.createElement("p");
  valueEl.className = `text-2xl font-semibold tabular-nums ${accentClass}`;
  valueEl.textContent = String(value);
  const labelEl = document.createElement("p");
  labelEl.className = "mt-1 text-xs font-medium uppercase tracking-wide text-ink-muted";
  labelEl.textContent = label;
  card.append(valueEl, labelEl);
  return card;
}

/** Renders the KPI summary cards row into `container`, replacing any existing content. */
export function renderSummary(container: HTMLElement, summary: CatalogSummary): void {
  container.replaceChildren(
    buildStatCard("Endpoints", summary.total, "text-brand"),
    buildStatCard("High severity", summary.high, "text-risk-high"),
    buildStatCard("Medium severity", summary.medium, "text-risk-medium"),
    buildStatCard("Low severity", summary.low, "text-risk-low"),
    buildStatCard("Secrets found", summary.secrets, "text-risk-high"),
  );
}
