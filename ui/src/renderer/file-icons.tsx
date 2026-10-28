import type { ReactElement } from "react";

/**
 * One drawn set for the file panel, so a folder in the local pane and a folder
 * in the remote pane are the same mark. Every icon is a 16-unit grid, 1.5 wide
 * strokes, round joins, and takes its colour from the element around it.
 */
const STROKE = {
  viewBox: "0 0 16 16",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

function icon(paths: ReactElement, size = 14) {
  return <svg {...STROKE} width={size} height={size}>{paths}</svg>;
}

export function FolderIcon({ size }: { size?: number }) {
  return icon(
    <path d="M1.9 12.6V3.9a1 1 0 0 1 1-1h3l1.5 1.7h6.7a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H2.9a1 1 0 0 1-1-1Z" />,
    size,
  );
}

export function FileIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M9.3 1.7H4.5a1.2 1.2 0 0 0-1.2 1.2v10.2a1.2 1.2 0 0 0 1.2 1.2h7a1.2 1.2 0 0 0 1.2-1.2V5.1Z" />
      <path d="M9.3 1.7v3.4h3.4" />
    </>,
    size,
  );
}

export function SymlinkIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M6.9 9.1a3 3 0 0 0 4.5.3l1.7-1.7a3 3 0 0 0-4.2-4.2l-1 1" />
      <path d="M9.1 6.9a3 3 0 0 0-4.5-.3L2.9 8.3a3 3 0 0 0 4.2 4.2l1-1" />
    </>,
    size,
  );
}

export function UnknownEntryIcon({ size }: { size?: number }) {
  return icon(
    <>
      <circle cx="8" cy="8" r="5.9" />
      <path d="M8 11.2h.01M6.4 6.3a1.7 1.7 0 0 1 3.3.6c0 1.1-1.7 1.4-1.7 2.4" />
    </>,
    size,
  );
}

export function RefreshIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M13.4 8a5.4 5.4 0 1 1-1.6-3.8" />
      <path d="M13.4 2.6v3.2h-3.2" />
    </>,
    size,
  );
}

export function UploadIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M8 11.4V2.9" />
      <path d="m4.8 6.1 3.2-3.2 3.2 3.2" />
      <path d="M2.6 10.4v1.9a1.2 1.2 0 0 0 1.2 1.2h8.4a1.2 1.2 0 0 0 1.2-1.2v-1.9" />
    </>,
    size,
  );
}

export function DownloadIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M8 2.9v8.5" />
      <path d="m4.8 8.2 3.2 3.2 3.2-3.2" />
      <path d="M2.6 10.4v1.9a1.2 1.2 0 0 0 1.2 1.2h8.4a1.2 1.2 0 0 0 1.2-1.2v-1.9" />
    </>,
    size,
  );
}

export function TrashIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M2.8 4.4h10.4" />
      <path d="M6.2 4.4V3a1 1 0 0 1 1-1h1.6a1 1 0 0 1 1 1v1.4" />
      <path d="M4.2 4.4 4.8 13a1 1 0 0 0 1 .9h4.4a1 1 0 0 0 1-.9l.6-8.6" />
      <path d="M6.9 6.9v4.3M9.1 6.9v4.3" />
    </>,
    size,
  );
}

export function NewFolderIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M1.9 12.6V3.9a1 1 0 0 1 1-1h3l1.5 1.7h6.7a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H2.9a1 1 0 0 1-1-1Z" />
      <path d="M8 7.4v3.4M6.3 9.1h3.4" />
    </>,
    size,
  );
}

export function ArchiveIcon({ size }: { size?: number }) {
  return icon(
    <>
      <rect x="2" y="3.2" width="12" height="3" rx="1" />
      <path d="M3.1 6.2v6.1a1 1 0 0 0 1 1h7.8a1 1 0 0 0 1-1V6.2" />
      <path d="M6.6 9h2.8" />
    </>,
    size,
  );
}

export function PermissionIcon({ size }: { size?: number }) {
  return icon(
    <>
      <rect x="3.4" y="7" width="9.2" height="6.2" rx="1.3" />
      <path d="M5.6 7V5.2a2.4 2.4 0 0 1 4.8 0V7" />
      <path d="M8 9.4v1.6" />
    </>,
    size,
  );
}

export function InfoIcon({ size }: { size?: number }) {
  return icon(
    <>
      <circle cx="8" cy="8" r="6.1" />
      <path d="M8 7.2v4" />
      <path d="M8 4.8v.1" />
    </>,
    size,
  );
}

export function RenameIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M9.6 3.4l3 3-6.2 6.2-3.5.5.5-3.5Z" />
      <path d="M8.6 4.4l3 3" />
    </>,
    size,
  );
}

export function PreviewIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M1.6 8s2.4-4.2 6.4-4.2S14.4 8 14.4 8s-2.4 4.2-6.4 4.2S1.6 8 1.6 8Z" />
      <circle cx="8" cy="8" r="1.7" />
    </>,
    size,
  );
}

export function TerminalHereIcon({ size }: { size?: number }) {
  return icon(
    <>
      <rect x="1.8" y="2.8" width="12.4" height="10.4" rx="2" />
      <path d="m4.9 6.6 1.9 1.7-1.9 1.7" />
      <path d="M9.1 10.4h2.6" />
    </>,
    size,
  );
}

export function HomeIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M2.6 7 8 2.4 13.4 7" />
      <path d="M3.9 8.1v4.3a1 1 0 0 0 1 1h6.2a1 1 0 0 0 1-1V8.1" />
    </>,
    size,
  );
}

export function UpIcon({ size }: { size?: number }) {
  return icon(
    <>
      <path d="M8 13.1V3.4" />
      <path d="m4.2 7.2 3.8-3.8 3.8 3.8" />
    </>,
    size,
  );
}

export function SearchIcon({ size }: { size?: number }) {
  return icon(
    <>
      <circle cx="7.2" cy="7.2" r="4.4" />
      <path d="m10.5 10.5 2.6 2.6" />
    </>,
    size,
  );
}

export function CopyIcon({ size }: { size?: number }) {
  return icon(
    <>
      <rect x="5.4" y="5.4" width="8.2" height="8.2" rx="1.4" />
      <path d="M10.6 5.4V3.8a1.4 1.4 0 0 0-1.4-1.4H3.8a1.4 1.4 0 0 0-1.4 1.4v5.4a1.4 1.4 0 0 0 1.4 1.4h1.6" />
    </>,
    size,
  );
}

/** The mark for a directory entry, chosen by what the entry actually is. */
export function EntryKindIcon({ kind }: { kind: string }) {
  if (kind === "directory") return <FolderIcon />;
  if (kind === "file") return <FileIcon />;
  if (kind === "symlink") return <SymlinkIcon />;
  return <UnknownEntryIcon />;
}
