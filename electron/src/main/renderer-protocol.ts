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

export function isTerminalRendererUrl(rawUrl: string): boolean {
  try {
    const url = new URL(rawUrl);
    return (
      url.protocol === `${RENDERER_SCHEME}:` &&
      url.host === RENDERER_HOST &&
      url.pathname === "/" &&
      url.search === "?window=terminal" &&
      url.hash === "" &&
      url.searchParams.size === 1 &&
      url.searchParams.get("window") === "terminal"
    );
  } catch {
    return false;
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
