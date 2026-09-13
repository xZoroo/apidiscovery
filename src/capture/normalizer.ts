/**
 * Turns a raw URL into the (host, templatedPath) pair used to key an {@link EndpointRecord}, and
 * detects "id-shaped" path segments (numeric, UUID, Mongo ObjectId, hex hash) so that
 * `/users/1` and `/users/2` collapse into one `/users/{id}` record.
 *
 * The id-segment detectors are exported (not just used internally) because the scorer reuses the
 * exact same shape checks for its IDOR-family rules -- one definition of "looks like an id",
 * not two that could drift apart.
 */

/** Caps how much of a request/response body is ever stored, per {@link CapturedRequest}. */
export const MAX_BODY_BYTES = 256 * 1024;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const OBJECT_ID_OR_HASH_RE = /^[0-9a-f]{24}$|^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
const NUMERIC_RE = /^\d+$/;

export function isNumericIdSegment(segment: string): boolean {
  return NUMERIC_RE.test(segment);
}

export function isUuidSegment(segment: string): boolean {
  return UUID_RE.test(segment);
}

export function isObjectIdOrHashSegment(segment: string): boolean {
  return OBJECT_ID_OR_HASH_RE.test(segment);
}

/** True if the segment looks like any kind of object identifier (numeric, UUID, ObjectId/hash). */
export function isIdSegment(segment: string): boolean {
  return isNumericIdSegment(segment) || isUuidSegment(segment) || isObjectIdOrHashSegment(segment);
}

/** Truncates a body string to {@link MAX_BODY_BYTES} (measured in UTF-16 code units, not bytes). */
export function truncateBody(body: string | undefined): string | undefined {
  if (body === undefined || body.length <= MAX_BODY_BYTES) return body;
  return body.slice(0, MAX_BODY_BYTES);
}

/** Splits a URL into `host` and `path` (query string and fragment dropped from `path`). */
export function splitUrl(url: string): { host: string; path: string } {
  const parsed = new URL(url);
  return { host: parsed.host, path: parsed.pathname || "/" };
}

/** Replaces every id-shaped path segment with `{id}` (e.g. `/users/1/orders/2` -> `/users/{id}/orders/{id}`). */
export function templatePath(path: string): string {
  return path
    .split("/")
    .map((segment) => (segment.length > 0 && isIdSegment(segment) ? "{id}" : segment))
    .join("/");
}

/** Builds the dedup key an {@link EndpointRecord} is stored/merged under. */
export function endpointKey(method: string, host: string, templatedPath: string): string {
  return `${method.toUpperCase()} ${host}${templatedPath}`;
}
