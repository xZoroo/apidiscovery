/**
 * A deliberately small, documented set of regex patterns for the JS/HTML static-analysis miner.
 *
 * Per the plan: "start with a focused proven set and note where to extend" rather than porting
 * hundreds of rules from any one tool. Each pattern is tagged with the prior-art category it was
 * adapted from.
 */

export interface EndpointPattern {
  id: string;
  /** Must have exactly one capturing group: the matched URL/path text. */
  regex: RegExp;
  note: string;
}

export interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
}

/**
 * Endpoint-shaped string literals in JS/HTML source. Adapted from the "quoted URL literal" and
 * "API-prefixed path literal" categories used by ReconLens, JSpider, EndPointer, and de-secretor.
 * Deliberately conservative (absolute URLs, or paths that look API-ish) to keep noise down; a
 * generic multi-segment path literal is intentionally NOT included here as it produced too many
 * false positives on prior-art tools that shipped it (e.g. matching CSS/asset paths).
 */
export const ENDPOINT_PATTERNS: EndpointPattern[] = [
  {
    id: "absolute-url",
    regex: /["'`](https?:\/\/[a-zA-Z0-9.-]+(?:\/[^\s"'`]*)?)["'`]/g,
    note: "Absolute http(s) URL literal in quotes/backticks.",
  },
  {
    id: "api-prefixed-path",
    regex: /["'`](\/(?:api|v\d+|graphql)(?:\/[^\s"'`?]*)?)["'`]/gi,
    note: "Path literal starting with /api, /vN, or /graphql -- the common API-route prefixes.",
  },
];

/**
 * High-signal secret shapes only, adapted from the Gitleaks/Mantra-derived categories used by
 * de-secretor and JS-Recon-Extractor-Extension. Extend this list (not the matching logic) if a
 * target uses a provider not covered here.
 */
export const SECRET_PATTERNS: SecretPattern[] = [
  { id: "aws-access-key-id", label: "AWS Access Key ID", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  {
    id: "jwt",
    label: "JWT",
    regex: /\bey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  { id: "google-api-key", label: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "slack-token", label: "Slack token", regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  {
    id: "generic-labeled-secret",
    label: "Generic labeled secret",
    regex: /\b(?:api[_-]?key|secret|token)\b\s*[:=]\s*["'`]([A-Za-z0-9_\-./+]{12,})["'`]/gi,
  },
];
