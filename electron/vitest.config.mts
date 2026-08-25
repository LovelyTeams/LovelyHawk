import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["dist-electron/**", "dist-renderer/**", "node_modules/**"],
  },
});
