/**
 * Shared render logic for the dashboard and devtools panel (the plan's "two real consumers" that
 * earn a shared module). Every captured value (URL, header, body) is attacker-controlled -- it
 * comes straight from the site under test -- so this file only ever sets `textContent`, never
 * `innerHTML`, on anything derived from captured data.
 *
 * Styling uses Tailwind utility classes on top of the custom color tokens in
 * assets/tailwind.css; this file owns the DOM structure and severity/method color mapping so the
 * dashboard and devtools panel render identically without duplicating markup.
 */

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
// Color mapping -- severity and HTTP method deliberately live in different hue
// families (see assets/tailwind.css) so a red DELETE badge is never mistaken
// for a high-severity flag.
// ---------------------------------------------------------------------------

const SEVERITY_STYLES: Record<Severity, { badge: string; callout: string; icon: string }> = {
  high: {
    badge:
      "bg-risk-high/10 text-risk-high ring-1 ring-inset ring-risk-high/25 dark:bg-risk-high/20",
    callout: "border-risk-high bg-risk-high/5 dark:bg-risk-high/10",
    icon: "text-risk-high",
  },
  medium: {
    badge:
      "bg-risk-medium/10 text-risk-medium ring-1 ring-inset ring-risk-medium/25 dark:bg-risk-medium/20",
    callout: "border-risk-medium bg-risk-medium/5 dark:bg-risk-medium/10",
    icon: "text-risk-medium",
  },
  low: {
    badge: "bg-risk-low/10 text-risk-low ring-1 ring-inset ring-risk-low/20 dark:bg-risk-low/20",
    callout: "border-risk-low bg-risk-low/5 dark:bg-risk-low/10",
    icon: "text-risk-low",
  },
};

const METHOD_STYLES: Record<string, string> = {
  GET: "bg-method-get/10 text-method-get ring-1 ring-inset ring-method-get/25 dark:bg-method-get/20",
  POST: "bg-method-post/10 text-method-post ring-1 ring-inset ring-method-post/25 dark:bg-method-post/20",
  PUT: "bg-method-put/10 text-method-put ring-1 ring-inset ring-method-put/25 dark:bg-method-put/20",
  PATCH:
    "bg-method-put/10 text-method-put ring-1 ring-inset ring-method-put/25 dark:bg-method-put/20",
  DELETE:
    "bg-method-delete/10 text-method-delete ring-1 ring-inset ring-method-delete/25 dark:bg-method-delete/20",
};
const DEFAULT_METHOD_STYLE =
  "bg-slate-100 text-slate-600 ring-1 ring-inset ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-400/20";

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

function badge(text: string, className: string): HTMLSpanElement {
  const span = document.createElement("span");
  span.className = `inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium ${className}`;
  span.textContent = text;
  return span;
}

function methodBadge(method: string): HTMLSpanElement {
  return badge(method, `font-mono ${METHOD_STYLES[method] ?? DEFAULT_METHOD_STYLE}`);
}

// ---------------------------------------------------------------------------
// Highlighting -- wraps the exact literal text a rule flagged (Finding.matchedValue)
// wherever it appears in displayed text, so the reviewer sees precisely what was
// flagged in context, not just a description of it.
// ---------------------------------------------------------------------------

/** Renders `text` into `container`, wrapping any occurrence of a term in `terms` in a `<mark>`. */
function appendHighlighted(container: HTMLElement, text: string, terms: string[]): void {
  const uniqueTerms = [...new Set(terms)].filter((t) => t.length > 0);
  if (uniqueTerms.length === 0) {
    container.appendChild(document.createTextNode(text));
    return;
  }
  const pattern = new RegExp(`(${uniqueTerms.map(escapeRegExp).join("|")})`, "g");
  const parts = text.split(pattern);
  for (const part of parts) {
    if (uniqueTerms.includes(part)) {
      const mark = document.createElement("mark");
      mark.className = "rounded bg-mark px-0.5 font-semibold text-mark-ink";
      mark.textContent = part;
      container.appendChild(mark);
    } else if (part.length > 0) {
      container.appendChild(document.createTextNode(part));
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
    span.className = "text-xs text-slate-400 dark:text-slate-500";
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
  const td = cell("font-mono text-slate-700 dark:text-slate-300");
  appendHighlighted(td, endpoint.templatedPath, matchedValues(endpoint.findings));
  return td;
}

function buildEndpointRow(endpoint: EndpointRecord, onSelect: SelectHandler): HTMLTableRowElement {
  const row = document.createElement("tr");
  row.className =
    "cursor-pointer border-b border-slate-100 last:border-0 hover:bg-slate-50 dark:border-slate-800 dark:hover:bg-slate-800/60";

  const methodCell = cell();
  methodCell.appendChild(methodBadge(endpoint.method));

  const hostCell = cell("font-mono text-slate-500 dark:text-slate-400");
  hostCell.textContent = endpoint.host;

  const seenCell = cell("text-slate-500 dark:text-slate-400 tabular-nums");
  seenCell.textContent = String(endpoint.seenCount);

  const sourceCell = cell();
  const sourceWrap = document.createElement("div");
  sourceWrap.className = "flex flex-wrap gap-1";
  for (const source of endpoint.sources) {
    sourceWrap.appendChild(
      badge(source, "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"),
    );
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
    td.className = "px-3 py-10 text-center text-sm text-slate-400 dark:text-slate-500";
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

function buildOwaspTag(category: string | undefined): HTMLElement | null {
  if (category === undefined) return null;
  return badge(category, "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400");
}

function buildFindingCallout(finding: Finding, focused: boolean): HTMLElement {
  const box = document.createElement("div");
  box.dataset["ruleId"] = finding.ruleId;
  const focusRing = focused
    ? " ring-2 ring-brand-500 ring-offset-1 dark:ring-offset-slate-900"
    : "";
  box.className = `flex items-start gap-2 rounded-md border-l-4 p-3 ${SEVERITY_STYLES[finding.severity].callout}${focusRing}`;

  box.appendChild(severityIcon(finding.severity));

  const body = document.createElement("div");
  body.className = "min-w-0 flex-1";

  const heading = document.createElement("div");
  heading.className = "flex flex-wrap items-center gap-2";
  const label = document.createElement("span");
  label.className = "text-sm font-semibold text-slate-900 dark:text-slate-100";
  label.textContent = finding.label;
  heading.append(label, badge(finding.severity, SEVERITY_STYLES[finding.severity].badge));
  const owaspTag = buildOwaspTag(finding.owaspCategory);
  if (owaspTag !== null) heading.appendChild(owaspTag);

  const rationale = document.createElement("p");
  rationale.className = "mt-1 text-sm text-slate-600 dark:text-slate-300";
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
  heading.className =
    "text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400";
  heading.textContent = `Security findings (${String(findings.length)})`;
  section.appendChild(heading);
  for (const finding of findings) {
    section.appendChild(buildFindingCallout(finding, finding.ruleId === focusRuleId));
  }
  return section;
}

function buildHeadersList(headers: HeaderEntry[] | undefined): HTMLElement {
  const wrap = document.createElement("dl");
  wrap.className = "divide-y divide-slate-100 text-xs dark:divide-slate-800";
  for (const header of headers ?? []) {
    const row = document.createElement("div");
    row.className = "flex gap-2 py-1";
    const dt = document.createElement("dt");
    dt.className = "w-40 shrink-0 font-mono text-slate-500 dark:text-slate-400";
    dt.textContent = header.name;
    const dd = document.createElement("dd");
    dd.className = "min-w-0 flex-1 break-all font-mono text-slate-700 dark:text-slate-300";
    dd.textContent = header.value;
    row.append(dt, dd);
    wrap.appendChild(row);
  }
  if ((headers ?? []).length === 0) {
    const empty = document.createElement("p");
    empty.className = "text-xs text-slate-400 dark:text-slate-500";
    empty.textContent = "No headers captured.";
    wrap.appendChild(empty);
  }
  return wrap;
}

/** Pretty-prints a body as JSON when it parses as such, otherwise shows the raw text. */
function buildBodyPre(body: string | undefined): HTMLPreElement {
  const pre = document.createElement("pre");
  pre.className =
    "mt-2 max-h-60 overflow-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100 dark:bg-black";
  if (body === undefined) {
    pre.textContent = "(no body)";
    pre.className += " italic text-slate-500";
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
  heading.className =
    "text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400";
  heading.textContent = title;
  section.append(heading, buildHeadersList(headers), buildBodyPre(body));
  return section;
}

function buildRequestResponseBlock(request: CapturedRequest): HTMLElement {
  const wrapper = document.createElement("div");
  wrapper.className = "space-y-2";

  const heading = document.createElement("h3");
  heading.className =
    "text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400";
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
  heading.className =
    "text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400";
  heading.textContent = "Decoded JWT";
  section.appendChild(heading);

  const decoded = decodeJwtParts(token);
  if (decoded === null) {
    const p = document.createElement("p");
    p.className = "mt-1 text-xs text-slate-400 dark:text-slate-500";
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
  pre.className =
    "mt-2 max-h-40 overflow-auto rounded-md bg-slate-900 p-3 text-xs text-slate-100 dark:bg-black";
  pre.textContent = JSON.stringify({ header: decoded.header, payload: decoded.payload }, null, 2);
  section.appendChild(pre);
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
  container.className =
    "space-y-4 rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900";

  const heading = document.createElement("div");
  heading.className = "flex flex-wrap items-center gap-2";
  heading.appendChild(methodBadge(endpoint.method));
  const pathHeading = document.createElement("span");
  pathHeading.className = "font-mono text-sm text-slate-800 dark:text-slate-200";
  appendHighlighted(
    pathHeading,
    `${endpoint.host}${endpoint.templatedPath}`,
    matchedValues(endpoint.findings),
  );
  heading.appendChild(pathHeading);
  container.appendChild(heading);

  const urlList = document.createElement("ul");
  urlList.className = "space-y-0.5 font-mono text-xs text-slate-500 dark:text-slate-400";
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
  if (sample !== undefined) container.appendChild(buildRequestResponseBlock(sample));

  if (focusRuleId !== undefined) {
    const focused = container.querySelector(`[data-rule-id="${focusRuleId}"]`);
    focused?.scrollIntoView({ block: "nearest", behavior: "smooth" });
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
    td.className = "px-3 py-6 text-center text-sm text-slate-400 dark:text-slate-500";
    td.textContent = "No secrets found in scanned JavaScript.";
    row.appendChild(td);
    tbody.replaceChildren(row);
    return;
  }
  tbody.replaceChildren(
    ...secrets.map((secret) => {
      const row = document.createElement("tr");
      row.className = "border-b border-slate-100 last:border-0 dark:border-slate-800";

      const labelCell = cell();
      labelCell.appendChild(badge(secret.label, SEVERITY_STYLES.high.badge));

      const matchCell = cell("font-mono text-slate-700 dark:text-slate-300");
      matchCell.textContent = secret.match;

      const sourceCell = cell("font-mono text-slate-500 dark:text-slate-400");
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
  card.className =
    "rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900";
  const valueEl = document.createElement("p");
  valueEl.className = `text-2xl font-semibold tabular-nums ${accentClass}`;
  valueEl.textContent = String(value);
  const labelEl = document.createElement("p");
  labelEl.className =
    "mt-1 text-xs font-medium uppercase tracking-wide text-slate-500 dark:text-slate-400";
  labelEl.textContent = label;
  card.append(valueEl, labelEl);
  return card;
}

/** Renders the KPI summary cards row into `container`, replacing any existing content. */
export function renderSummary(container: HTMLElement, summary: CatalogSummary): void {
  container.replaceChildren(
    buildStatCard("Endpoints", summary.total, "text-brand-600 dark:text-brand-400"),
    buildStatCard("High severity", summary.high, "text-risk-high"),
    buildStatCard("Medium severity", summary.medium, "text-risk-medium"),
    buildStatCard("Low severity", summary.low, "text-risk-low"),
    buildStatCard("Secrets found", summary.secrets, "text-risk-high"),
  );
}
