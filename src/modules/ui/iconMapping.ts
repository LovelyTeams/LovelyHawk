/**
 * IconPark 图标体系 —— emoji → SVG 统一替换
 *
 * 说明：@icon-park/svg 的每个图标是返回 SVG 字符串的具名函数，签名如
 *   Whale({ theme:'outline', size:24, fill:'currentColor' }) => '<svg ...>'
 * 为保证 tree-shaking（避免把全部 2600+ 图标打进包），这里**具名导入**用到的
 * 图标构成本地注册表 ICON_REGISTRY，再按名字索引渲染。
 *
 * 新增功能时若要用未收录的图标名，请先在此 import 并加入 ICON_REGISTRY。
 */

import {
  Folder, FolderOpen, FolderClose, FileText, FileCode, FileCodeOne, CodeBrackets,
  Terminal, Code, Bug, Shield, Protection, Alarm, SettingTwo, SettingConfig, Config, Tool,
  Refresh, Plus, Delete, Edit, EditName, Search, Lock, LockOne, Home, KeyOne, KeyTwo,
  Info, Attention, Caution, CloseOne, CheckOne, Check, Close, RadioOne,
  Peoples, Computer, LaptopComputer, Whale, Rocket, Fire, FireTwo,
  ChartHistogramOne, ChartLine, TrendTwo, DashboardOne,
  Save, Upload, Download, Clipboard, DocDetail, Log,
  NetworkTree, LinkOne, LinkCloud, ConnectionPoint, Api,
  Data, DataSheet, DataAll, Server, HardDisk, MemoryOne, FileCabinet,
  Picture, Pic, ImageFiles, Zip, FileZip, Box,
  SunOne, Moon, Cherry, DarkMode, Water, Magic, Robot, ColorCard,
  Recycling, Lightning, Components, Experiment, Microscope, Analysis, Right, Pill, Injection,
} from '@icon-park/svg';

type IconFn = (props: Record<string, unknown>) => string;

/** 用到的图标注册表（新增请同步 import） */
const ICON_REGISTRY: Record<string, IconFn> = {
  Folder, FolderOpen, FolderClose, FileText, FileCode, FileCodeOne, CodeBrackets,
  Terminal, Code, Bug, Shield, Protection, Alarm, SettingTwo, SettingConfig, Config, Tool,
  Refresh, Plus, Delete, Edit, EditName, Search, Lock, LockOne, Home, KeyOne, KeyTwo,
  Info, Attention, Caution, CloseOne, CheckOne, Check, Close, RadioOne,
  Peoples, Computer, LaptopComputer, Whale, Rocket, Fire, FireTwo,
  ChartHistogramOne, ChartLine, TrendTwo, DashboardOne,
  Save, Upload, Download, Clipboard, DocDetail, Log,
  NetworkTree, LinkOne, LinkCloud, ConnectionPoint, Api,
  Data, DataSheet, DataAll, Server, HardDisk, MemoryOne, FileCabinet,
  Picture, Pic, ImageFiles, Zip, FileZip, Box,
  SunOne, Moon, Cherry, DarkMode, Water, Magic, Robot, ColorCard,
  Recycling, Lightning, Components, Experiment, Microscope, Analysis, Right, Pill, Injection,
} as unknown as Record<string, IconFn>;

const FALLBACK_ICON = 'Info';

// emoji → IconPark 名称
export const EMOJI_TO_ICONPARK_MAP: Record<string, string> = {
  // 导航 / 菜单
  '📊': 'ChartHistogramOne', '📈': 'TrendTwo', '📉': 'ChartLine', '🖥️': 'Computer',
  '🔧': 'Tool', '🔨': 'Tool', '🐳': 'Whale', '🚨': 'Alarm', '⚙️': 'SettingTwo',
  '🎛️': 'SettingConfig', '📡': 'NetworkTree', '🧭': 'DashboardOne',
  // 连接 / 状态
  '🔗': 'LinkOne', '🟢': 'CheckOne', '🔴': 'CloseOne', '🟡': 'Attention', '🟠': 'Attention',
  '🟣': 'RadioOne', '⚪': 'RadioOne', '⚫': 'RadioOne', '🌐': 'LinkCloud', '🔌': 'Api',
  // 文件 / 数据
  '📁': 'Folder', '📂': 'FolderOpen', '🗂️': 'FolderClose', '📦': 'Box', '💾': 'Save',
  '📤': 'Upload', '📥': 'Download', '📋': 'Clipboard', '📄': 'FileText', '📃': 'FileText',
  '📜': 'FileCode', '🗄️': 'FileCabinet', '🖼️': 'Pic', '🗜️': 'FileZip',
  // 系统 / 进程
  '💻': 'LaptopComputer', '🐚': 'Terminal', '👥': 'Peoples', '🚀': 'Rocket',
  '🧵': 'Components', '🧠': 'MemoryOne', '💽': 'HardDisk', '🗃️': 'DataSheet',
  // 操作 / 控制
  '🔄': 'Refresh', '♻️': 'Recycling', '➕': 'Plus', '🗑️': 'Delete', '✏️': 'Edit',
  '📝': 'EditName', '🔎': 'Search', '🔍': 'Search', '🔐': 'Lock', '🔒': 'Lock',
  '🔓': 'LockOne', '🏠': 'Home',
  // 认证 / 安全
  '🔑': 'KeyTwo', '🗝️': 'KeyOne', '🛡️': 'Shield', '🦠': 'Bug',
  // 状态 / 信息
  'ℹ️': 'Info', '💡': 'Info', '⚡': 'Lightning', '🚧': 'Config', '⚠️': 'Attention',
  '✅': 'CheckOne', '❌': 'CloseOne', '✔️': 'Check', '✓': 'Check', '✗': 'Close',
  '☑️': 'CheckOne', '🔥': 'Fire', '🤖': 'Robot', '🎨': 'ColorCard',
  // 主题
  '☀️': 'SunOne', '🌙': 'Moon', '🌸': 'Cherry', '🔮': 'DarkMode', '🌊': 'Water',
  // 编程语言 / 类型
  '🐧': 'Terminal', '🐍': 'FileCode', '💎': 'FileCode', '🐪': 'FileCode',
  // 诊断
  '🔬': 'Microscope', '🧪': 'Experiment', '💊': 'Pill', '💉': 'Injection',
};

// 状态图标语义色
export const ICON_COLOR_MAP: Record<string, string> = {
  '🟢': '#22c55e', '🔴': '#ef4444', '🟡': '#f59e0b', '⚪': '#9ca3af', '⚫': '#374151',
  '✅': '#22c55e', '❌': '#ef4444', '⚠️': '#f59e0b', 'ℹ️': '#6db3ff',
  'default': 'currentColor',
  'primary': 'var(--primary-color)',
  'secondary': 'var(--text-secondary)',
  'success': 'var(--success-color)',
  'warning': 'var(--warning-color)',
  'error': 'var(--error-color)',
};

export const ICON_SIZES = {
  small: 14, medium: 16, large: 20, xlarge: 24, xxlarge: 32, huge: 48,
} as const;

export type IconSize = keyof typeof ICON_SIZES;
export type IconTheme = 'outline' | 'filled' | 'two-tone' | 'multi-color';

export interface IconOptions {
  size?: IconSize | number;
  color?: string;
  theme?: IconTheme;
  strokeWidth?: number;
  className?: string;
}

export function getIconFromEmoji(emoji: string): string {
  return EMOJI_TO_ICONPARK_MAP[emoji] || FALLBACK_ICON;
}

export function getIconColor(emoji: string, customColor?: string): string {
  if (customColor) return customColor;
  return ICON_COLOR_MAP[emoji] || ICON_COLOR_MAP.default;
}

export function getIconSize(size: IconSize | number): number {
  return typeof size === 'number' ? size : ICON_SIZES[size];
}

/**
 * 按 IconPark 名称渲染真实 SVG 字符串。名称不在注册表时回退到中性图标。
 */
export function icon(name: string, opts: IconOptions = {}): string {
  const fn = ICON_REGISTRY[name] || ICON_REGISTRY[FALLBACK_ICON];
  const size = getIconSize(opts.size ?? 'medium');
  const fill = opts.color ?? 'currentColor';
  const theme = opts.theme ?? 'outline';
  const strokeWidth = opts.strokeWidth ?? 3;
  try {
    return fn({ theme, size, fill, strokeWidth });
  } catch {
    return '';
  }
}

/** 内联包裹：让 SVG 与文本基线对齐 */
function wrap(svg: string, size: number, className?: string): string {
  const cls = className ? ` ${className}` : '';
  return `<span class="ip-icon${cls}" style="display:inline-flex;align-items:center;justify-content:center;width:${size}px;height:${size}px;vertical-align:-0.15em;line-height:0;">${svg}</span>`;
}

/**
 * 由 emoji 或 IconPark 名称生成内联图标 HTML（供模板字符串使用）。
 * 传 emoji 时经映射表解析；传名称时直接渲染。
 */
export function createIconHTML(emojiOrName: string, options: IconOptions = {}): string {
  const name = EMOJI_TO_ICONPARK_MAP[emojiOrName]
    || (ICON_REGISTRY[emojiOrName] ? emojiOrName : FALLBACK_ICON);
  const size = getIconSize(options.size ?? 'medium');
  const color = getIconColor(emojiOrName, options.color);
  const svg = icon(name, { ...options, size, color });
  return wrap(svg, size, options.className);
}

/** 状态徽章图标（success/warning/error/info）带语义色 */
export function statusIcon(
  level: 'success' | 'warning' | 'error' | 'info',
  opts: IconOptions = {},
): string {
  const map = {
    success: { name: 'CheckOne', color: 'var(--success-color, #22c55e)' },
    warning: { name: 'Attention', color: 'var(--warning-color, #f59e0b)' },
    error: { name: 'CloseOne', color: 'var(--error-color, #ef4444)' },
    info: { name: 'Info', color: 'var(--info-color, #6db3ff)' },
  } as const;
  const m = map[level];
  const size = getIconSize(opts.size ?? 'small');
  return wrap(icon(m.name, { ...opts, size, color: opts.color ?? m.color }), size, opts.className);
}

/** 文件类型图标：目录/软链/按扩展名 */
export function iconForFile(name: string, isDir = false, isSymlink = false, opts: IconOptions = {}): string {
  const size = getIconSize(opts.size ?? 'medium');
  const render = (n: string, color?: string) => wrap(icon(n, { ...opts, size, color: opts.color ?? color }), size, opts.className);
  if (isDir) return render('Folder', 'var(--primary-color)');
  if (isSymlink) return render('LinkOne');
  const lower = name.toLowerCase();
  const ext = (m: string[]) => m.some(e => lower.endsWith(e));
  if (ext(['.sh', '.bash', '.zsh'])) return render('Terminal');
  if (ext(['.py', '.rb', '.pl', '.pm', '.php', '.jsp', '.js', '.ts', '.go', '.rs', '.c', '.cpp', '.java'])) return render('FileCode');
  if (ext(['.json', '.xml', '.yaml', '.yml', '.toml', '.ini'])) return render('FileCodeOne');
  if (ext(['.conf', '.cfg', '.cnf'])) return render('Config');
  if (ext(['.log'])) return render('Log');
  if (ext(['.txt', '.md', '.rst'])) return render('FileText');
  if (ext(['.zip', '.tar', '.gz', '.tgz', '.bz2', '.xz', '.7z', '.rar'])) return render('FileZip');
  if (ext(['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico'])) return render('Pic');
  if (ext(['.so', '.ko', '.o', '.a', '.dll'])) return render('Tool');
  if (ext(['.pem', '.key', '.crt', '.cer', '.pub'])) return render('KeyTwo');
  if (ext(['.db', '.sqlite', '.sql'])) return render('DataSheet');
  return render('FileText');
}

export function getIconProps(emoji: string, options: IconOptions = {}) {
  const { size = 'medium', color, theme = 'outline', strokeWidth = 3 } = options;
  return {
    name: getIconFromEmoji(emoji),
    size: getIconSize(size),
    fill: getIconColor(emoji, color),
    theme,
    strokeWidth,
  };
}

/** 批量把模板字符串里的 emoji 换成内联 SVG */
export function replaceEmojisInTemplate(template: string, defaultOptions: IconOptions = {}): string {
  let result = template;
  Object.keys(EMOJI_TO_ICONPARK_MAP).forEach(emoji => {
    const regex = new RegExp(emoji.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g');
    result = result.replace(regex, createIconHTML(emoji, defaultOptions));
  });
  return result;
}
