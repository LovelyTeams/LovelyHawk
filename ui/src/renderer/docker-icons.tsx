import type { ReactElement } from "react";

/**
 * Line icons for the Docker pane.
 *
 * Drawn rather than typed. The summary cards and row buttons started out as
 * Unicode glyphs, and glyphs are at the mercy of whichever font the machine
 * happens to have: on a plain Windows Server install several of them fell back
 * to a different face and came out at the wrong size and weight, in a row where
 * six of them sit side by side. These are one shape, one stroke width, always.
 */
const ICON_PROPS = {
  viewBox: "0 0 16 16",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

const PATHS = {
  /** A box: a container. */
  container: (
    <>
      <path d="M2.4 4.7 8 1.9l5.6 2.8v6.6L8 14.1l-5.6-2.8Z" />
      <path d="M2.4 4.7 8 7.5l5.6-2.8M8 7.5v6.6" />
    </>
  ),
  /** Play: running. */
  running: <path d="M5.6 3.4 12 8l-6.4 4.6Z" />,
  /** Square: stopped. */
  stopped: <rect x="4.2" y="4.2" width="7.6" height="7.6" rx="1.4" />,
  /** Stacked plates: images. */
  images: (
    <>
      <path d="M8 1.9 14 5 8 8.1 2 5Z" />
      <path d="m2 8.4 6 3.1 6-3.1M2 11.5l6 3.1 6-3.1" />
    </>
  ),
  /** A hub with three spokes: networks. */
  networks: (
    <>
      <circle cx="8" cy="8" r="2.1" />
      <path d="M8 1.9v3.9M3.1 12.4l3.2-2.3M12.9 12.4l-3.2-2.3" />
      <circle cx="8" cy="1.9" r="0.9" />
      <circle cx="2.6" cy="13" r="0.9" />
      <circle cx="13.4" cy="13" r="0.9" />
    </>
  ),
  /** A drum: volumes. */
  volumes: (
    <>
      <ellipse cx="8" cy="4" rx="5.2" ry="2.1" />
      <path d="M2.8 4v8c0 1.2 2.3 2.1 5.2 2.1s5.2-.9 5.2-2.1V4" />
      <path d="M2.8 8c0 1.2 2.3 2.1 5.2 2.1s5.2-.9 5.2-2.1" />
    </>
  ),
  /** A prompt: opens a terminal inside a container. */
  terminal: (
    <>
      <rect x="1.9" y="3" width="12.2" height="10" rx="1.8" />
      <path d="m4.9 6.6 2 1.7-2 1.7M8.6 10.4h2.8" />
    </>
  ),
  start: <path d="M5.6 3.4 12 8l-6.4 4.6Z" />,
  stop: <rect x="4.2" y="4.2" width="7.6" height="7.6" rx="1.4" />,
  restart: (
    <>
      <path d="M13.2 8a5.2 5.2 0 1 1-1.6-3.7" />
      <path d="M13.4 2.4v3h-3" />
    </>
  ),
  pause: <path d="M6.2 3.6v8.8M9.8 3.6v8.8" />,
  unpause: <path d="M5.6 3.4 12 8l-6.4 4.6Z" />,
  kill: <path d="m4.2 4.2 7.6 7.6M11.8 4.2 4.2 11.8" />,
  remove: (
    <>
      <path d="M2.9 4.4h10.2M6.4 4.4V2.9h3.2v1.5" />
      <path d="M4.4 4.4l.7 8.2c0 .5.5.9 1 .9h3.8c.5 0 1-.4 1-.9l.7-8.2" />
    </>
  ),
  more: (
    <>
      <circle cx="3.6" cy="8" r="1" />
      <circle cx="8" cy="8" r="1" />
      <circle cx="12.4" cy="8" r="1" />
    </>
  ),
  search: (
    <>
      <circle cx="7.1" cy="7.1" r="4.2" />
      <path d="m10.2 10.2 3 3" />
    </>
  ),
  close: <path d="m4.2 4.2 7.6 7.6M11.8 4.2 4.2 11.8" />,
} as const;

export type DockerIconName = keyof typeof PATHS;

export function DockerIcon({ name, size = 16 }: { name: DockerIconName; size?: number }): ReactElement {
  return (
    <svg {...ICON_PROPS} width={size} height={size} className="docker-icon">
      {PATHS[name]}
    </svg>
  );
}
