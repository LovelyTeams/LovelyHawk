/**
 * 本地化第三方前端资源(离线可用)
 *
 * 赛场为断网环境,所有静态资源必须随包打进本地,禁止依赖任何 CDN。
 * 本模块替代原先在 index.html 中通过 CDN / Google Fonts 引入的资源:
 *   - highlight.js:语法高亮,挂到 window.hljs 供 fileViewerModal 使用
 *   - Inter 字体:与原 index.html 请求的 300/400/500/600/700 字重保持一致
 *
 * 以副作用方式 import,在 main.ts 最早期加载即可。
 */

// Inter 字体(本地 woff2,替代 fonts.googleapis.com)
// 仅取 latin 子集:UI 为中英文,中文走系统 CJK 字体,Inter 只负责拉丁字符,
// 无需 cyrillic/greek/vietnamese 等子集(可将字体产物从 70 个 woff2 降到 5 个)。
import '@fontsource/inter/latin-300.css';
import '@fontsource/inter/latin-400.css';
import '@fontsource/inter/latin-500.css';
import '@fontsource/inter/latin-600.css';
import '@fontsource/inter/latin-700.css';

// highlight.js:common 构建(约 40 种常见语言,体积小于 full,已覆盖 bash/python/php/java/sql/nginx 等)
// 深色主题样式替代原 CDN 的 github-dark.min.css
import hljs from 'highlight.js/lib/common';
import 'highlight.js/styles/github-dark.css';

// fileViewerModal.ts 通过 (window as any).hljs 使用,保持原有全局约定不变
(window as any).hljs = hljs;

export {};
