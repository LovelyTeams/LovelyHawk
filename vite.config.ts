import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;
// @ts-expect-error process is a nodejs global
const isProd = process.env.NODE_ENV === 'production' || process.env.TAURI_ENV_DEBUG !== 'true';
// @ts-expect-error process is a nodejs global
const isDebugBuild = process.env.TAURI_ENV_DEBUG === 'true' || process.env.VITE_DEBUG_SOURCEMAP === 'true';

// https://vite.dev/config/
export default defineConfig(async () => ({
  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 5174,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 5175,
        }
      : undefined,
    watch: {
      // 3. tell vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
  esbuild: isProd
    ? {
        drop: ['console', 'debugger'],
      }
    : undefined,
  // 配置多页面应用
  build: {
    sourcemap: isDebugBuild,
    minify: 'esbuild' as const, // 使用 esbuild 进行基本压缩（更快，不混淆）
    chunkSizeWarningLimit: 3500,
    rollupOptions: {
      treeshake: isProd
        ? {
            manualPureFunctions: [
              'console.debug',
              'console.error',
              'console.info',
              'console.log',
              'console.warn',
            ],
          }
        : undefined,
      // 单入口：SSH / 容器终端窗口改为加载 index.html?window=xxx，
      // 由 src/main.ts 分流到各自入口模块，不再需要独立的 .html 文件。
      input: {
        main: 'index.html',
      },
      onwarn(warning: any, warn: any) {
        // 忽略source map相关警告
        if (warning.code === 'SOURCEMAP_ERROR') return;
        if (warning.message && warning.message.includes('source map')) return;
        warn(warning);
      },
      output: {
        // 标准文件名格式
        entryFileNames: 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
        // 代码分块优化：按重型库单独拆分 chunk, 降低首屏体积
        manualChunks(id: string) {
          if (id.indexOf('node_modules') === -1) return undefined;
          if (/[\\/]node_modules[\\/](xterm|xterm-addon-)/.test(id)) return 'xterm';
          if (/[\\/]node_modules[\\/]@tauri-apps[\\/]/.test(id)) return 'tauri';
          if (/[\\/]node_modules[\\/]@icon-park[\\/]/.test(id)) return 'icons';
          if (/[\\/]node_modules[\\/]monaco-editor[\\/]/.test(id)) return 'monaco';
          if (/[\\/]node_modules[\\/](vue|@vue|pinia)[\\/]/.test(id)) return 'vue';
          return 'vendor';
        },
      },
    },
  },

  plugins: [vue()],
}));
