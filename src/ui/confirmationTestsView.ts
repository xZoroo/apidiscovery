/**
 * UI for the one-click confirmation tests in src/repeater/confirmationTests.ts. Each test gets
 * its own button and its own persistent result panel (not one shared slot), so a tester can run
 * several and compare them side by side instead of overwriting the previous result.
 */

import type { ConfirmationOutcome } from "../repeater/confirmationTests.js";
import {
  runCorsReflectionTest,
  runIdorSubstitutionTest,
  runJwtAlgNoneTest,
  runMassAssignmentTest,
  runMethodTamperingTest,
  runOpenRedirectTest,
  runUnauthenticatedReplayTest,
} from "../repeater/confirmationTests.js";
import type { CapturedRequest, EndpointRecord } from "../capture/types.js";

function buildOutcomeView(outcome: ConfirmationOutcome): HTMLElement {
  const toneClass = outcome.notApplicable
    ? "border-line bg-page text-ink-muted"
    : outcome.concern
      ? "border-risk-high/40 bg-risk-high/8 text-risk-high"
      : "border-risk-low/40 bg-risk-low/8 text-ink-muted";
  const box = document.createElement("div");
  box.className = `space-y-2 rounded-md border p-3 text-xs ${toneClass}`;

  const verdict = document.createElement("p");
  verdict.className = "font-semibold";
  verdict.textContent = outcome.verdict;
  box.appendChild(verdict);

  if (outcome.rows.length > 0) {
    const dl = document.createElement("dl");
    dl.className = "space-y-1 font-mono text-ink";
    for (const row of outcome.rows) {
      const line = document.createElement("div");
      line.className = "flex gap-2";
      const dt = document.createElement("dt");
      dt.className = "w-40 shrink-0 text-ink-muted";
      dt.textContent = row.label;
      const dd = document.createElement("dd");
      dd.className = "min-w-0 flex-1 break-all";
      dd.textContent = row.value;
      line.append(dt, dd);
      dl.appendChild(line);
    }
    box.appendChild(dl);
  }

  return box;
}

function buildTestButton(label: string, runner: () => Promise<ConfirmationOutcome>): HTMLElement {
  const wrapper = document.createElement("div");
  wrapper.className = "border-t border-line/60 pt-3 first:border-t-0 first:pt-0";

  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.className =
    "rounded-md border border-risk-medium/50 bg-surface px-3 py-1.5 text-sm font-medium text-risk-medium hover:bg-risk-medium/10 disabled:cursor-not-allowed disabled:opacity-50";

  const resultContainer = document.createElement("div");
  resultContainer.className = "mt-2 empty:mt-0";

  button.addEventListener("click", () => {
    button.disabled = true;
    button.textContent = "Running…";
    void runner().then((outcome) => {
      button.disabled = false;
      button.textContent = label;
      resultContainer.replaceChildren(buildOutcomeView(outcome));
    });
  });

  wrapper.append(button, resultContainer);
  return wrapper;
}

/**
 * A block of one-click confirmation tests for the currently open endpoint. Each button fires a
 * small, bounded number of requests (never a loop, never a sweep across endpoints) -- turning a
 * passive finding into a proven result instead of automating an attack.
 */
export function buildConfirmationTestsSection(
  endpoint: EndpointRecord,
  sample: CapturedRequest | undefined,
): HTMLElement {
  const section = document.createElement("div");
  section.className = "space-y-3 rounded-lg border border-risk-medium/40 bg-risk-medium/10 p-4";

  const heading = document.createElement("h3");
  heading.className = "text-sm font-semibold text-risk-medium";
  heading.textContent = "Confirmation tests";
  const warning = document.createElement("p");
  warning.className = "text-xs text-ink-muted";
  warning.textContent =
    "Each button below sends a small, bounded number of real requests to confirm (or rule out) " +
    "one specific issue on this endpoint. None of these loop or run automatically. Only use " +
    "them against systems you are authorized to test -- the mass assignment test performs a " +
    "real write.";
  section.append(heading, warning);

  section.append(
    buildTestButton("Test IDOR (substitute ID)", () => runIdorSubstitutionTest(sample)),
    buildTestButton("Test unauthenticated replay", () => runUnauthenticatedReplayTest(sample)),
    buildTestButton("Test CORS reflection", () =>
      runCorsReflectionTest(sample, endpoint.exampleUrls[0]),
    ),
    buildTestButton("Test JWT alg=none", () => runJwtAlgNoneTest(sample)),
    buildTestButton("Test method tampering", () => runMethodTamperingTest(sample)),
    buildTestButton("Test open redirect", () => runOpenRedirectTest(sample)),
    buildTestButton("Test mass assignment (real write)", () => runMassAssignmentTest(sample)),
  );

  return section;
}
