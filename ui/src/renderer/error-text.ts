/**
 * Host errors keep a trailing `(code)` that page logic matches on. The
 * operator reads the sentence, not the code. A message with no Chinese at all
 * is a request the page's own checks refused ("Invalid … request."), written
 * for developers; the caller's sentence says it better.
 */
const TRAILING_CODE = /\s*\([a-z][a-z0-9]*(?:-[a-z0-9]+)+\)\s*$/u;
const CHINESE = /[一-鿿]/u;

export function errorText(reason: unknown, fallback: string): string {
  if (!(reason instanceof Error)) return fallback;
  const text = reason.message.replace(TRAILING_CODE, "").trim();
  return CHINESE.test(text) ? text : fallback;
}
