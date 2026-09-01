import path from "node:path";

export const RENDERER_SCHEME = "lovelyres";
export const RENDERER_HOST = "app";

export function isTrustedRendererUrl(rawUrl: string): boolean {
  try {
    const url = new URL(rawUrl);
    return url.protocol === `${RENDERER_SCHEME}:` && url.host === RENDERER_HOST;
  } catch {
    return false;
  }
}

/**
 * The windows that share the terminal preload, and therefore the target the
 * main process resolved for them.
 *
 * A closed set, spelled out: the file editor joined it so a file can be opened
 * at a readable size and written back, and it reaches the same SFTP handlers
 * the browser does. Anything not on this list is not one of these windows and
 * gets none of them.
 */
export const TERMINAL_FAMILY_WINDOWS = ["terminal", "file-editor"] as const;
export type TerminalFamilyWindow = (typeof TERMINAL_FAMILY_WINDOWS)[number];

export function isTerminalRendererUrl(rawUrl: string): boolean {
  return terminalRendererWindow(rawUrl) !== null;
}

/** Which of the family a URL is, or null when it is not one of them. */
export function terminalRendererWindow(rawUrl: string): TerminalFamilyWindow | null {
  try {
    const url = new URL(rawUrl);
    if (
      url.protocol !== `${RENDERER_SCHEME}:` ||
      url.host !== RENDERER_HOST ||
      url.pathname !== "/" ||
      url.hash !== "" ||
      url.searchParams.size !== 1
    ) {
      return null;
    }
    const kind = url.searchParams.get("window");
    return (TERMINAL_FAMILY_WINDOWS as readonly string[]).includes(kind ?? "")
      ? kind as TerminalFamilyWindow
      : null;
  } catch {
    return null;
  }
}

export function resolveRendererAsset(rawUrl: string, rendererRoot: string): string | null {
  const originPrefix = `${RENDERER_SCHEME}://${RENDERER_HOST}`;
  if (!rawUrl.startsWith(originPrefix)) return null;
  const undecodedPath = rawUrl.slice(originPrefix.length).split(/[?#]/, 1)[0] ?? "";
  let decodedRawPath: string;
  try {
    decodedRawPath = decodeURIComponent(undecodedPath);
  } catch {
    return null;
  }
  if (
    decodedRawPath.includes("\0") ||
    decodedRawPath.includes("\\") ||
    decodedRawPath.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (!isTrustedRendererUrl(rawUrl)) return null;

  let pathname: string;
  try {
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return null;
  }
  if (pathname.includes("\0") || pathname.includes("\\")) return null;
  let relative: string;
  if (pathname === "/") {
    if (url.search === "" && url.hash === "") relative = "index.html";
    else if (isTerminalRendererUrl(rawUrl)) relative = "terminal.html";
    else return null;
  } else {
    if (url.search !== "" || url.hash !== "") return null;
    relative = pathname.replace(/^\/+/, "");
  }
  const normalizedRoot = path.resolve(rendererRoot);
  const candidate = path.resolve(normalizedRoot, relative);
  if (candidate !== normalizedRoot && !candidate.startsWith(`${normalizedRoot}${path.sep}`)) {
    return null;
  }
  return candidate;
}
