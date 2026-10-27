import type { WindowsIncidentTab } from "./win-ir-model";

const paths: Record<WindowsIncidentTab, string> = {
  overview: "M3 4h18v12H3z M8 21h8 M12 16v5 M7 12l3-3 3 2 4-5",
  playbooks: "M4 3h16v18H4z M8 7h8 M8 12h3 M8 17h3 M14 12l2 2 3-4 M14 18h3",
  baseline: "M12 3l8 3v6c0 4-4 7-8 9-4-2-8-5-8-9V6z M8 12l3 3 5-6",
  timeline: "M6 3v18 M6 6h13 M6 12h10 M6 18h13 M3 6h6 M3 12h6 M3 18h6",
  processes: "M8 3h8v5H8z M3 16h7v5H3z M14 16h7v5h-7z M12 8v4 M6 16v-4h12v4",
  network: "M9 3h6v6H9z M3 16h6v5H3z M15 16h6v5h-6z M12 9v4 M6 16v-3h12v3",
  startup: "M14 3c4 0 7 0 7 0s0 3-1 7l-7 7-6-6z M8 8H4l-2 6h5 M16 16v4l-6 2v-5 M5 18l-2 3 M15 7h2",
  services: "M3 4h18v6H3z M3 14h18v6H3z M6 7h1 M6 17h1 M11 7h7 M11 17h7",
  drivers: "M6 6h12v12H6z M9 9h6v6H9z M9 2v4 M15 2v4 M9 18v4 M15 18v4 M2 9h4 M2 15h4 M18 9h4 M18 15h4",
  tasks: "M4 4h16v17H4z M8 2v4 M16 2v4 M4 8h16 M8 14l3 3 5-6",
  accounts: "M16 8a4 4 0 1 1-8 0 4 4 0 0 1 8 0z M4 21v-2c0-4 4-5 8-5s8 1 8 5v2",
  logs: "M5 3h11l3 3v15H5z M15 3v5h4 M9 12h6 M9 16h6",
  files: "M3 6h7l2 3h9v11H3z M3 6V4h7l2 2h7v3",
  registry: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  desktop: "M3 3h18v14H3z M8 21h8 M12 17v4",
  console: "M3 4h18v16H3z M7 9l3 3-3 3 M13 15h4",
};

export function WinIrIcon({ name, size = 20 }: { name: WindowsIncidentTab; size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d={paths[name]} />
    </svg>
  );
}
