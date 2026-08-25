import type { LogSourceKind } from "../shared/log-analysis-read-contract";

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

/**
 * A file log and a journal unit are read differently, so they are drawn
 * differently: a page for the one that lives on disk, a service dial for the
 * one that comes out of systemd.
 */
export function LogSourceIcon({ kind }: { kind: LogSourceKind }) {
  return (
    <span className={`log-analysis-icon is-${kind}`} aria-hidden="true">
      <svg {...ICON_PROPS}>
        {kind === "journal" ? (
          <>
            <circle cx="8" cy="8" r="5.9" />
            <path d="M8 4.6V8l2.4 1.6" />
          </>
        ) : (
          <>
            <path d="M9.1 1.9H4.4a1 1 0 0 0-1 1v10.2a1 1 0 0 0 1 1h7.2a1 1 0 0 0 1-1V5.4Z" />
            <path d="M9.1 1.9v3.5h3.5" />
            <path d="M5.8 8.6h4.4M5.8 11h3" />
          </>
        )}
      </svg>
    </span>
  );
}
