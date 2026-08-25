const GLYPH_PROPS = {
  viewBox: "0 0 16 16",
  width: 14,
  height: 14,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

export function RefreshGlyph() {
  return (
    <svg {...GLYPH_PROPS}>
      <path d="M13.4 8a5.4 5.4 0 1 1-1.6-3.8" />
      <path d="M13.4 2.6v3.2h-3.2" />
    </svg>
  );
}

export function UploadGlyph() {
  return (
    <svg {...GLYPH_PROPS}>
      <path d="M8 12.6V3.4" />
      <path d="m4.4 7 3.6-3.6L11.6 7" />
      <path d="M2.6 13.4h10.8" />
    </svg>
  );
}

export function DownloadGlyph() {
  return (
    <svg {...GLYPH_PROPS}>
      <path d="M8 3.4v9.2" />
      <path d="m4.4 9 3.6 3.6L11.6 9" />
      <path d="M2.6 13.4h10.8" />
    </svg>
  );
}

export function TrashGlyph() {
  return (
    <svg {...GLYPH_PROPS}>
      <path d="M2.8 4.4h10.4" />
      <path d="M6.2 4.4V3a1 1 0 0 1 1-1h1.6a1 1 0 0 1 1 1v1.4" />
      <path d="M4.2 4.4 4.8 13a1 1 0 0 0 1 .9h4.4a1 1 0 0 0 1-.9l.6-8.6" />
    </svg>
  );
}

export function FolderPlusGlyph() {
  return (
    <svg {...GLYPH_PROPS}>
      <path d="M2.4 12.6V4.2a1 1 0 0 1 1-1h2.8l1.4 1.6h5a1 1 0 0 1 1 1v6.8a1 1 0 0 1-1 1H3.4a1 1 0 0 1-1-1Z" />
      <path d="M8 7.4v3.4M6.3 9.1h3.4" />
    </svg>
  );
}
