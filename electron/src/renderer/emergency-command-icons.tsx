import type { ReactElement } from "react";

import type { EmergencyCommandCategory } from "../shared/emergency-command-contract";

const ICON_PROPS = {
  viewBox: "0 0 16 16",
  width: 17,
  height: 17,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

const PATHS: Record<EmergencyCommandCategory, ReactElement> = {
  permissions: (
    <>
      <path d="M8 1.9 13 3.6v4.1c0 3-2 5.1-5 6.4-3-1.3-5-3.4-5-6.4V3.6Z" />
      <path d="m5.9 7.9 1.4 1.4 2.8-2.8" />
    </>
  ),
  accounts: (
    <>
      <circle cx="8" cy="5.4" r="2.6" />
      <path d="M2.9 13.6a5.1 5.1 0 0 1 10.2 0" />
    </>
  ),
  network: (
    <>
      <circle cx="8" cy="8" r="5.9" />
      <path d="M2.1 8h11.8" />
      <path d="M8 2.1a9.6 9.6 0 0 1 0 11.8 9.6 9.6 0 0 1 0-11.8Z" />
    </>
  ),
  processes: (
    <>
      <rect x="4.4" y="4.4" width="7.2" height="7.2" rx="1.4" />
      <path d="M6.6 1.9v2.5M9.4 1.9v2.5M6.6 11.6v2.5M9.4 11.6v2.5" />
      <path d="M1.9 6.6h2.5M1.9 9.4h2.5M11.6 6.6h2.5M11.6 9.4h2.5" />
    </>
  ),
  persistence: (
    <>
      <path d="M2.4 8a5.6 5.6 0 0 1 9.6-3.9l1.6 1.5" />
      <path d="M13.6 8a5.6 5.6 0 0 1-9.6 3.9L2.4 10.4" />
      <path d="M13.6 2.4v3.2h-3.2M2.4 13.6v-3.2h3.2" />
    </>
  ),
  logs: (
    <>
      <path d="M3 3.4h10M3 6.6h10M3 9.8h7M3 13h5" />
    </>
  ),
  files: (
    <>
      <path d="M9.1 1.9H4.6a1.3 1.3 0 0 0-1.3 1.3v9.6a1.3 1.3 0 0 0 1.3 1.3h6.8a1.3 1.3 0 0 0 1.3-1.3V5.3Z" />
      <path d="M9.1 1.9v3.4h3.6" />
    </>
  ),
  containers: (
    <>
      <path d="M8 1.9 13.4 5v6L8 14.1 2.6 11V5Z" />
      <path d="M2.6 5 8 8.1 13.4 5M8 8.1v6" />
    </>
  ),
  system: (
    <>
      <rect x="2.1" y="2.6" width="11.8" height="4.4" rx="1.3" />
      <rect x="2.1" y="9" width="11.8" height="4.4" rx="1.3" />
      <path d="M4.6 4.8h.01M4.6 11.2h.01" />
    </>
  ),
};

/** Tone class that colors the tile; mapped to semantic theme tokens in CSS. */
const TONES: Record<EmergencyCommandCategory, string> = {
  permissions: "accent",
  accounts: "warning",
  network: "info",
  processes: "success",
  persistence: "danger",
  logs: "accent",
  files: "info",
  containers: "success",
  system: "neutral",
};

export function emergencyCommandTone(category: EmergencyCommandCategory): string {
  return TONES[category] ?? "neutral";
}

export function EmergencyCommandIcon({ category }: { category: EmergencyCommandCategory }) {
  return (
    <span className={`emergency-command-icon is-${emergencyCommandTone(category)}`} aria-hidden="true">
      <svg {...ICON_PROPS}>{PATHS[category]}</svg>
    </span>
  );
}

export function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg {...ICON_PROPS} width={13} height={13} className={open ? "is-open" : ""}>
      <path d="m5.6 3.4 5 4.6-5 4.6" />
    </svg>
  );
}

export function PlayIcon() {
  return (
    <svg {...ICON_PROPS} width={14} height={14}>
      <path d="M5.4 3.4 12 8l-6.6 4.6Z" />
    </svg>
  );
}

export function RefreshIcon() {
  return (
    <svg {...ICON_PROPS} width={14} height={14}>
      <path d="M13.4 8a5.4 5.4 0 1 1-1.6-3.8" />
      <path d="M13.4 2.6v3.2h-3.2" />
    </svg>
  );
}

export function SearchIcon() {
  return (
    <svg {...ICON_PROPS} width={14} height={14}>
      <circle cx="7.2" cy="7.2" r="4.4" />
      <path d="m10.5 10.5 2.6 2.6" />
    </svg>
  );
}

export function CheckIcon() {
  return (
    <svg {...ICON_PROPS} width={15} height={15}>
      <circle cx="8" cy="8" r="6.1" />
      <path d="m5.4 8.2 1.8 1.8 3.4-3.6" />
    </svg>
  );
}

export function ClockIcon() {
  return (
    <svg {...ICON_PROPS} width={13} height={13}>
      <circle cx="8" cy="8" r="5.9" />
      <path d="M8 4.7V8l2.2 1.3" />
    </svg>
  );
}

export function TagIcon() {
  return (
    <svg {...ICON_PROPS} width={13} height={13}>
      <path d="M2.6 3.9a1.3 1.3 0 0 1 1.3-1.3h3.3l6.2 6.2-4.6 4.6-6.2-6.2Z" />
      <path d="M5.3 5.3h.01" />
    </svg>
  );
}

export function LockIcon() {
  return (
    <svg {...ICON_PROPS} width={13} height={13}>
      <rect x="3.4" y="7" width="9.2" height="6.2" rx="1.4" />
      <path d="M5.6 7V5.2a2.4 2.4 0 0 1 4.8 0V7" />
    </svg>
  );
}
