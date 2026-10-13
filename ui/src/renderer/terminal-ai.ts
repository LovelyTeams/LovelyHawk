import type { AiAssistContent } from "./AiAssistPanel";

const encoder = new TextEncoder();

/**
 * What the operator selected in a terminal, as one AI request may carry it.
 *
 * Whole lines from the top until the next would pass the bound, so what is
 * sent reads as it was selected; the rest is counted, and the panel says how
 * many lines stay behind. xterm joins a wrapped line back into one, so a
 * single line can be longer than the bound on its own: then its start is sent.
 */
export function terminalSelectionContent(selected: string, maximumBytes: number): AiAssistContent {
  const lines = selected.replace(/\r\n?/gu, "\n").replace(/[ \t]+$/gmu, "").replace(/\n+$/u, "").split("\n");
  const kept: string[] = [];
  let bytes = 0;
  for (const line of lines) {
    const size = encoder.encode(line).byteLength + (kept.length === 0 ? 0 : 1);
    if (bytes + size > maximumBytes) break;
    kept.push(line);
    bytes += size;
  }
  if (kept.length === 0 && lines.length > 0) {
    let start = "";
    let used = 0;
    for (const character of lines[0]!) {
      const size = encoder.encode(character).byteLength;
      if (used + size > maximumBytes) break;
      start += character;
      used += size;
    }
    return { text: start, omitted: lines.length - 1 };
  }
  return { text: kept.join("\n"), omitted: lines.length - kept.length };
}

/** Lines in a selection, as the panel names it ("选中的 12 行"). */
export function terminalSelectionLines(selected: string): number {
  const trimmed = selected.replace(/\r\n?/gu, "\n").replace(/\n+$/u, "");
  return trimmed === "" ? 0 : trimmed.split("\n").length;
}
