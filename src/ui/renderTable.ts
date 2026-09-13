/**
 * Shared render logic for the dashboard and devtools panel (the plan's "two real consumers" that
 * earn a shared module). Every captured value (URL, header, body) is attacker-controlled -- it
 * comes straight from the site under test -- so this file only ever sets `textContent`, never
 * `innerHTML`, on anything derived from captured data.
 */

import { maxSeverity } from "../score/scorer.js";
import type {
  CapturedRequest,
  EndpointRecord,
  Finding,
  HeaderEntry,
  StoredSecret,
} from "../capture/types.js";

function cell(text: string): HTMLTableCellElement {
  const td = document.createElement("td");
  td.textContent = text;
  return td;
}

function buildFlagsCell(findings: Finding[]): HTMLTableCellElement {
  const td = document.createElement("td");
  const severity = maxSeverity(findings);
  if (severity !== null) {
    const badge = document.createElement("span");
    badge.className = `badge ${severity}`;
    badge.textContent = `${findings.length} flag${findings.length === 1 ? "" : "s"}`;
    td.appendChild(badge);
  }
  return td;
}

function buildEndpointRow(
  endpoint: EndpointRecord,
  onSelect: (endpoint: EndpointRecord) => void,
): HTMLTableRowElement {
  const row = document.createElement("tr");
  row.className = "endpoint-row";
  row.append(
    cell(endpoint.method),
    cell(endpoint.host),
    cell(endpoint.templatedPath),
    buildFlagsCell(endpoint.findings),
    cell(String(endpoint.seenCount)),
    cell(endpoint.sources.join(", ")),
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
  onSelect: (endpoint: EndpointRecord) => void,
): void {
  tbody.replaceChildren(...endpoints.map((endpoint) => buildEndpointRow(endpoint, onSelect)));
}

function buildHeadersList(headers: HeaderEntry[] | undefined): HTMLUListElement {
  const ul = document.createElement("ul");
  for (const header of headers ?? []) {
    const li = document.createElement("li");
    li.textContent = `${header.name}: ${header.value}`;
    ul.appendChild(li);
  }
  return ul;
}

/** Pretty-prints a body as JSON when it parses as such, otherwise shows the raw text. */
function buildBodyPre(body: string | undefined): HTMLPreElement {
  const pre = document.createElement("pre");
  if (body === undefined) {
    pre.textContent = "(no body)";
    return pre;
  }
  try {
    pre.textContent = JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    pre.textContent = body;
  }
  return pre;
}

function buildRequestResponseBlock(request: CapturedRequest): DocumentFragment {
  const fragment = document.createDocumentFragment();

  const reqHeading = document.createElement("h4");
  reqHeading.textContent = "Request";
  fragment.append(
    reqHeading,
    buildHeadersList(request.requestHeaders),
    buildBodyPre(request.requestBody),
  );

  const resHeading = document.createElement("h4");
  resHeading.textContent =
    request.responseStatus === undefined ? "Response" : `Response (${request.responseStatus})`;
  fragment.append(
    resHeading,
    buildHeadersList(request.responseHeaders),
    buildBodyPre(request.responseBody),
  );

  return fragment;
}

function buildFindingsList(findings: Finding[]): HTMLElement | null {
  if (findings.length === 0) return null;
  const heading = document.createElement("h4");
  heading.textContent = "Findings";
  const list = document.createElement("ul");
  for (const finding of findings) {
    const li = document.createElement("li");
    li.textContent = `[${finding.severity}] ${finding.rationale}`;
    list.appendChild(li);
  }
  const container = document.createElement("div");
  container.append(heading, list);
  return container;
}

/**
 * Renders the expanded detail view for one endpoint: example URLs, its findings with rationale,
 * and one representative request/response (the most recently captured sample, if any).
 */
export function renderDetail(
  container: HTMLElement,
  endpoint: EndpointRecord,
  sampleRequests: CapturedRequest[],
): void {
  container.replaceChildren();

  const heading = document.createElement("h3");
  heading.textContent = `${endpoint.method} ${endpoint.host}${endpoint.templatedPath}`;
  container.appendChild(heading);

  const urlList = document.createElement("ul");
  for (const url of endpoint.exampleUrls) {
    const li = document.createElement("li");
    li.textContent = url;
    urlList.appendChild(li);
  }
  container.appendChild(urlList);

  const findingsBlock = buildFindingsList(endpoint.findings);
  if (findingsBlock !== null) container.appendChild(findingsBlock);

  const sample = sampleRequests.at(-1);
  if (sample !== undefined) container.appendChild(buildRequestResponseBlock(sample));
}

/** Renders one row per found secret into `tbody`, replacing any existing rows. */
export function renderSecretRows(tbody: HTMLTableSectionElement, secrets: StoredSecret[]): void {
  tbody.replaceChildren(
    ...secrets.map((secret) => {
      const row = document.createElement("tr");
      row.append(cell(secret.label), cell(secret.match), cell(secret.sourceFile));
      return row;
    }),
  );
}
