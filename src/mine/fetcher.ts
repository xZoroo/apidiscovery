/**
 * Fetches external script bodies and, when available, their sourcemap's `sourcesContent` so the
 * miner can regex-scan original (unminified) source instead of just the minified bundle.
 *
 * Background-context fetches aren't subject to the page's own CORS/CSP, per the plan's capture
 * pipeline step 6 -- this is why mining happens in `background.ts`, not the content script.
 */

const SOURCE_MAP_COMMENT_RE = /\/\/# sourceMappingURL=([^\s]+)/;

export interface ScriptBlob {
  /** The URL this text was fetched from (script URL, or the resolved sourcemap URL). */
  sourceUrl: string;
  text: string;
}

/** Resolves a (possibly relative) sourcemap URL against the script's own URL. */
function resolveSourceMapUrl(scriptUrl: string, mapRef: string): string | undefined {
  try {
    return new URL(mapRef, scriptUrl).toString();
  } catch {
    return undefined;
  }
}

/**
 * Fetches one external script and, if it references a sourcemap with `sourcesContent`, also
 * returns those original-source blobs. Returns an empty array (rather than throwing) if the
 * script itself can't be fetched -- one unreachable script must not abort the whole scan.
 */
export async function fetchScriptWithSourceMap(scriptUrl: string): Promise<ScriptBlob[]> {
  let scriptText: string;
  try {
    const response = await fetch(scriptUrl);
    if (!response.ok) return [];
    scriptText = await response.text();
  } catch {
    return [];
  }

  const blobs: ScriptBlob[] = [{ sourceUrl: scriptUrl, text: scriptText }];

  const mapRef = SOURCE_MAP_COMMENT_RE.exec(scriptText)?.[1];
  if (mapRef === undefined) return blobs;
  const mapUrl = resolveSourceMapUrl(scriptUrl, mapRef);
  if (mapUrl === undefined) return blobs;

  try {
    const mapResponse = await fetch(mapUrl);
    if (!mapResponse.ok) return blobs;
    const map = (await mapResponse.json()) as { sourcesContent?: unknown; sources?: unknown };
    if (!Array.isArray(map.sourcesContent)) return blobs;
    const sources = Array.isArray(map.sources) ? map.sources : [];
    map.sourcesContent.forEach((content: unknown, index: number) => {
      if (typeof content === "string" && content.length > 0) {
        const sourceName = typeof sources[index] === "string" ? sources[index] : `source-${index}`;
        blobs.push({ sourceUrl: `${mapUrl}#${sourceName}`, text: content });
      }
    });
  } catch {
    // No sourcemap available, or it wasn't parseable JSON -- fall back to just the script text.
  }

  return blobs;
}
