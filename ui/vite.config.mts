import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

/** Where `pnpm desktop:hot` serves the pages. The debug host accepts only loopback. */
export const DEV_SERVER_HOST = "127.0.0.1";
export const DEV_SERVER_PORT = 5173;

/**
 * `pnpm desktop:hot` only: what the dev server needs that the pages' CSP refuses.
 *
 * The built pages, which the desktop embeds and the source gate checks, are
 * untouched (`apply: "serve"`). The served ones get exactly three additions:
 * the hash of each inline script Vite and React Fast Refresh inject, inline
 * <style> tags (Vite delivers CSS as injected styles), and the dev server's
 * own origin and WebSocket for module and update requests.
 */
function developmentCsp(): Plugin {
  const origin = `${DEV_SERVER_HOST}:${DEV_SERVER_PORT}`;
  return {
    name: "lovelyhawk-development-csp",
    apply: "serve",
    transformIndexHtml: {
      // After every other hook, so the injected preamble scripts are present.
      order: "post",
      handler(html) {
        const hashes = [...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)]
          .map((match) => `'sha256-${createHash("sha256").update(match[1] ?? "").digest("base64")}'`);
        const meta = /(<meta\s+http-equiv="Content-Security-Policy"\s+content=")([^"]*)(")/i;
        if (!meta.test(html)) throw new Error("page has no Content-Security-Policy meta tag");
        return html.replace(meta, (_, open: string, policy: string, close: string) => {
          const directives = policy.split(";").map((directive) => directive.trim()).filter(Boolean)
            .map((directive) => {
              const [name, ...sources] = directive.split(/\s+/);
              const add = (...extra: string[]) =>
                [name, ...sources, ...extra.filter((source) => !sources.includes(source))].join(" ");
              switch (name) {
                case "script-src": return add(...hashes);
                case "style-src": return add("'unsafe-inline'");
                case "connect-src": return add("'self'", `ws://${origin}`);
                default: return directive;
              }
            });
          return `${open}${directives.join("; ")}${close}`;
        });
      },
    },
  };
}

export default defineConfig({
  base: "./",
  plugins: [react(), developmentCsp()],
  publicDir: path.resolve(projectRoot, "assets"),
  // Everything ships inside the desktop executable; nothing is fetched at runtime.
  optimizeDeps: {
    exclude: ["@xterm/xterm"],
  },
  server: {
    host: DEV_SERVER_HOST,
    port: DEV_SERVER_PORT,
    strictPort: true,
  },
  build: {
    emptyOutDir: true,
    outDir: path.resolve(projectRoot, "dist"),
    // WebView2 is evergreen Chromium on every supported Windows build.
    target: "es2022",
    rollupOptions: {
      input: {
        app: path.resolve(projectRoot, "index.html"),
        terminal: path.resolve(projectRoot, "terminal.html"),
      },
    },
  },
});
