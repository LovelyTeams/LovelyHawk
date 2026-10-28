import path from "node:path";
import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
const projectRoot = path.dirname(fileURLToPath(import.meta.url));
export default defineConfig({
    base: "./",
    plugins: [react()],
    publicDir: path.resolve(projectRoot, "assets"),
    // Everything ships inside the desktop executable; nothing is fetched at runtime.
    optimizeDeps: {
        exclude: ["@xterm/xterm"],
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
