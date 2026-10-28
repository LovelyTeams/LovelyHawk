import type { ReactElement } from "react";

const ICON_PROPS = {
  viewBox: "0 0 16 16",
  width: 16,
  height: 16,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.4,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

/**
 * One drawn icon per page, in the same stroke style as the title bar. The
 * page registry's text glyph is kept as the fallback for a page the shell does
 * not know yet, so a new page never renders without an icon.
 */
const ICONS: Record<string, () => ReactElement> = {
  "system-info": () => (
    <svg {...ICON_PROPS}>
      <rect x="1.8" y="2.4" width="12.4" height="8.6" rx="1.6" />
      <path d="M5.5 13.6h5M8 11v2.6M4.6 8.2l1.8-2 1.6 1.4 2.2-2.6 1.4 1.4" />
    </svg>
  ),
  docker: () => (
    <svg {...ICON_PROPS}>
      <rect x="1.8" y="6.8" width="3.4" height="3" rx=".5" />
      <rect x="6.3" y="6.8" width="3.4" height="3" rx=".5" />
      <rect x="10.8" y="6.8" width="3.4" height="3" rx=".5" />
      <rect x="6.3" y="2.8" width="3.4" height="3" rx=".5" />
      <path d="M1.2 12.6c2.2 1.3 4.4 1.6 6.8 1.6 3 0 5.2-.8 6.8-2.6" />
    </svg>
  ),
  kubernetes: () => (
    <svg {...ICON_PROPS}>
      <path d="M8 1.6 13.6 4.4l1 6.1L10.7 14H5.3L1.4 10.5l1-6.1Z" />
      <circle cx="8" cy="8.2" r="1.7" />
      <path d="M8 3.8v2.7M8 9.9v2.4M3.9 6.8l2.6.8M9.5 8.6l2.6.9M4.6 11.4l2.1-1.9M9.3 6.9l2-1.9" />
    </svg>
  ),
  "emergency-commands": () => (
    <svg {...ICON_PROPS}>
      <rect x="1.8" y="2.6" width="12.4" height="10.8" rx="1.8" />
      <path d="m4.6 6.2 2 1.8-2 1.8M8.4 10.4h3" />
    </svg>
  ),
  "windows-incident": () => (
    <svg {...ICON_PROPS}>
      <rect x="2.2" y="2.2" width="5.2" height="5.2" rx=".8" />
      <rect x="8.6" y="2.2" width="5.2" height="5.2" rx=".8" />
      <rect x="2.2" y="8.6" width="5.2" height="5.2" rx=".8" />
      <rect x="8.6" y="8.6" width="5.2" height="5.2" rx=".8" />
    </svg>
  ),
  "log-analysis": () => (
    <svg {...ICON_PROPS}>
      <path d="M2.2 3.4h9M2.2 6.4h6.4M2.2 9.4h3.8M2.2 12.4h3" />
      <circle cx="10.8" cy="10.2" r="2.6" />
      <path d="m12.7 12.1 1.7 1.7" />
    </svg>
  ),
  "packet-capture": () => (
    <svg {...ICON_PROPS}>
      <path d="M1.4 8.6h2.8l1.7-4.6 3.4 8.4 1.9-3.8h3.4" />
    </svg>
  ),
  "check-audit": () => (
    <svg {...ICON_PROPS}>
      <rect x="3" y="2.6" width="10" height="11.6" rx="1.6" />
      <path d="M6 2.6V1.8h4v.8" />
      <path d="m5.6 8.6 1.7 1.7 3.2-3.4" />
    </svg>
  ),
  integrity: () => (
    <svg {...ICON_PROPS}>
      <path d="M8 1.8 13 3.8v3.9c0 3-2.1 5.2-5 6.5-2.9-1.3-5-3.5-5-6.5V3.8Z" />
      <path d="m5.8 8.2 1.6 1.6 2.9-3.1" />
    </svg>
  ),
  notes: () => (
    <svg {...ICON_PROPS}>
      <path d="M3.2 2.2h6.2l3.4 3.4v8a.8.8 0 0 1-.8.8H4a.8.8 0 0 1-.8-.8Z" />
      <path d="M9.2 2.2v3.6h3.6M5.6 9h4.8M5.6 11.6h3" />
    </svg>
  ),
  database: () => (
    <svg {...ICON_PROPS}>
      <ellipse cx="8" cy="3.8" rx="5.2" ry="1.8" />
      <path d="M2.8 3.8v8.4c0 1 2.3 1.8 5.2 1.8s5.2-.8 5.2-1.8V3.8" />
      <path d="M2.8 8c0 1 2.3 1.8 5.2 1.8s5.2-.8 5.2-1.8" />
    </svg>
  ),
  "java-hot-update": () => (
    <svg {...ICON_PROPS}>
      <path d="M2.6 6.4h8.6v3.4a3.2 3.2 0 0 1-3.2 3.2H5.8a3.2 3.2 0 0 1-3.2-3.2Z" />
      <path d="M11.2 7.4h.9a1.6 1.6 0 0 1 0 3.2h-.9M5.4 1.8v2.4M8.2 1.8v2.4" />
    </svg>
  ),
  "config-generator": () => (
    <svg {...ICON_PROPS}>
      <path d="M3.4 1.8h5.8l3.4 3.4v8.6a.6.6 0 0 1-.6.6H3.4a.6.6 0 0 1-.6-.6V2.4a.6.6 0 0 1 .6-.6Z" />
      <circle cx="7.8" cy="9.6" r="1.7" />
      <path d="M7.8 6.6v1.3M7.8 11.3v1.3M4.8 9.6h1.3M9.5 9.6h1.3" />
    </svg>
  ),
  "security-reference": () => (
    <svg {...ICON_PROPS}>
      <path d="M2.4 2.8h4.2A1.4 1.4 0 0 1 8 4.2a1.4 1.4 0 0 1 1.4-1.4h4.2v9.8H9.4A1.4 1.4 0 0 0 8 14a1.4 1.4 0 0 0-1.4-1.4H2.4Z" />
      <path d="M8 4.2V14" />
    </svg>
  ),
  "ai-history": () => (
    <svg {...ICON_PROPS}>
      <path d="M7.4 1.8 8.6 5.6l3.8 1.2-3.8 1.2-1.2 3.8L6.2 8 2.4 6.8l3.8-1.2Z" />
      <path d="M12.4 10.4v3.2M10.8 12h3.2" />
    </svg>
  ),
};

export function NavIcon({ pageId, glyph }: { pageId: string; glyph: string }) {
  const Icon = ICONS[pageId];
  return Icon === undefined ? <span className="nav-glyph" aria-hidden="true">{glyph}</span> : <Icon />;
}

export function hasNavIcon(pageId: string): boolean {
  return Object.hasOwn(ICONS, pageId);
}
