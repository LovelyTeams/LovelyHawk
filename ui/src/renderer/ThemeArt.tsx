import type { ThemeDefinition } from "./theme/theme";

type Motif = "moon" | "crescent" | "blossom" | "grass" | "mountains" | "sprout" | "waves" | "pulse" | "spike" | "spectrum" | "star" | "cloud" | "beacon";

/** Each palette gets its own small picture, drawn only from its four swatches. */
const MOTIFS: Record<string, Motif> = {
  light: "moon",
  dark: "crescent",
  sakura: "blossom",
  pink: "blossom",
  tingwu: "grass",
  dongfang: "mountains",
  chunchen: "sprout",
  ruolan: "waves",
  linye: "pulse",
  shanhu: "spike",
  nihong: "spectrum",
  spark: "star",
  "incident-canvas": "beacon",
  shenhai: "cloud",
  wuye: "crescent",
  jiaotang: "moon",
  molv: "blossom",
};

function sparkle(cx: number, cy: number, r: number): string {
  const w = r * 0.28;
  return `M${cx} ${cy - r}Q${cx + w} ${cy - w} ${cx + r} ${cy}Q${cx + w} ${cy + w} ${cx} ${cy + r}Q${cx - w} ${cy + w} ${cx - r} ${cy}Q${cx - w} ${cy - w} ${cx} ${cy - r}Z`;
}

/**
 * The miniature colour poster shown on a theme card. Decorative only: the card
 * that holds it carries the theme's name.
 */
export function ThemeArt({ theme }: { theme: ThemeDefinition }) {
  const [ground, tint, mid, accent] = theme.swatches;
  const motif = MOTIFS[theme.id] ?? "moon";
  return (
    <svg className="theme-art" viewBox="0 0 64 44" aria-hidden="true" focusable="false">
      <rect width="64" height="44" fill={ground} />
      {motif === "moon" && (
        <g>
          <circle cx="24" cy="23" r="13" fill={tint} />
          <circle cx="29" cy="19" r="10" fill={ground} />
          <path d={sparkle(48, 15, 6)} fill={accent} />
          <circle cx="54" cy="30" r="2" fill={mid} />
        </g>
      )}
      {motif === "crescent" && (
        <g>
          <circle cx="23" cy="22" r="12" fill={accent} fillOpacity="0.9" />
          <circle cx="28.5" cy="17.5" r="10.5" fill={ground} />
          <circle cx="45" cy="12" r="1.8" fill={tint} />
          <path d={sparkle(50, 27, 6.5)} fill={accent} fillOpacity="0.75" />
          <circle cx="39" cy="34" r="1.4" fill={mid} />
        </g>
      )}
      {motif === "blossom" && (
        <g>
          <g fill={accent} fillOpacity="0.85">
            <circle cx="26" cy="12" r="7.5" />
            <circle cx="36" cy="19.5" r="7.5" />
            <circle cx="32" cy="31" r="7.5" />
            <circle cx="20" cy="31" r="7.5" />
            <circle cx="16" cy="19.5" r="7.5" />
          </g>
          <circle cx="26" cy="21.5" r="5" fill={tint} />
          <circle cx="26" cy="21.5" r="2" fill={mid} />
          <path d="M46 40C46 26 52 20 60 17" stroke={mid} strokeWidth="2" fill="none" strokeLinecap="round" />
          <circle cx="52" cy="14" r="5" fill={accent} fillOpacity="0.55" />
        </g>
      )}
      {motif === "grass" && (
        <g>
          <rect y="34" width="64" height="10" fill={tint} />
          <path d="M14 36C14 24 10 16 6 10c8 4 13 14 13 26Z" fill={mid} />
          <path d="M24 36c0-16 4-25 10-31-1 15-4 24-5 31Z" fill={accent} />
          <path d="M36 36c0-10 5-17 12-21-3 9-5 15-6 21Z" fill={mid} fillOpacity="0.8" />
          <circle cx="53" cy="13" r="4" fill={accent} fillOpacity="0.55" />
        </g>
      )}
      {motif === "mountains" && (
        <g>
          <circle cx="43" cy="16" r="9" fill={accent} fillOpacity="0.85" />
          <path d="M-2 44 18 18l18 26Z" fill={mid} />
          <path d="M24 44 44 22l22 22Z" fill={accent} fillOpacity="0.75" />
          <rect y="38" width="64" height="6" fill={tint} fillOpacity="0.75" />
          <path d="M6 12h16M10 7h16" stroke={tint} strokeWidth="2" strokeLinecap="round" />
        </g>
      )}
      {motif === "sprout" && (
        <g>
          <path d="M32 42V16" stroke={accent} strokeWidth="2.5" strokeLinecap="round" />
          <path d="M32 24c-10 0-15-5-16-12 10-1 15 4 16 12Z" fill={accent} />
          <path d="M32 30c10 0 15-5 16-12-10-1-15 4-16 12Z" fill={mid} />
          <circle cx="32" cy="12" r="4.5" fill={tint} />
          <circle cx="12" cy="34" r="2.5" fill={mid} fillOpacity="0.7" />
        </g>
      )}
      {motif === "waves" && (
        <g fill="none" strokeWidth="2.5" strokeLinecap="round">
          <path d="M-2 28q12-7 24 0t24 0 24 0" stroke={mid} />
          <path d="M-2 35q12-7 24 0t24 0 24 0" stroke={accent} />
          <path d="M-2 42q12-7 24 0t24 0 24 0" stroke={tint} />
          <path d="M32 4c4 7 7 10 7 13a7 7 0 0 1-14 0c0-3 3-6 7-13Z" fill={accent} stroke="none" />
        </g>
      )}
      {motif === "pulse" && (
        <g>
          <path d="M-2 44c10-14 16-10 24-18s16-2 26-10 14-2 18-6v34Z" fill={tint} />
          <path d="M-2 44c12-8 18-4 28-10s18-2 28-8 10-2 12-4v22Z" fill={mid} />
          <path d="M-2 20h16l4-8 4 15 5-10 4 3h35" stroke={accent} strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          <circle cx="18" cy="12" r="2.2" fill={accent} />
        </g>
      )}
      {motif === "spike" && (
        <g>
          <path d="m-2 44 12-8 8 3 10-19 6 13 10-5 8 6 14-4v14Z" fill={accent} />
          <path d="m22 44 6-38 6 38Z" fill={mid} />
          <path d="m44 44 4-26 4 26Z" fill={tint} />
          <circle cx="28" cy="6" r="2.6" fill={mid} />
        </g>
      )}
      {motif === "spectrum" && (
        <g>
          <g fill={tint}>
            <rect x="4" y="26" width="4" height="18" rx="2" />
            <rect x="11" y="20" width="4" height="24" rx="2" />
            <rect x="53" y="22" width="4" height="22" rx="2" />
          </g>
          <g fill={mid}>
            <rect x="18" y="13" width="4" height="31" rx="2" />
            <rect x="46" y="16" width="4" height="28" rx="2" />
          </g>
          <g fill={accent}>
            <rect x="25" y="6" width="4" height="38" rx="2" />
            <rect x="32" y="2" width="4" height="42" rx="2" />
            <rect x="39" y="9" width="4" height="35" rx="2" />
          </g>
        </g>
      )}
      {motif === "star" && (
        <g>
          <rect width="18" height="44" fill={tint} />
          <path d={sparkle(9, 18, 8)} fill={accent} />
          <circle cx="9" cy="34" r="2" fill={mid} />
          <circle cx="40" cy="24" r="13" fill={mid} fillOpacity="0.55" />
          <path d={sparkle(40, 24, 9)} fill={accent} />
        </g>
      )}
      {motif === "cloud" && (
        <g>
          <g fill={mid}>
            <circle cx="22" cy="16" r="12" />
            <circle cx="36" cy="14" r="9" />
            <circle cx="30" cy="26" r="11" />
          </g>
          <g fill={accent}>
            <circle cx="47" cy="25" r="5.5" />
            <circle cx="54" cy="30" r="5.5" />
            <circle cx="51" cy="38" r="5.5" />
            <circle cx="43" cy="38" r="5.5" />
            <circle cx="40" cy="30" r="5.5" />
          </g>
          <path d={sparkle(20, 20, 8)} fill={tint} />
        </g>
      )}
      {motif === "beacon" && (
        <g>
          <circle cx="32" cy="22" r="16" fill="none" stroke={mid} strokeWidth="2" />
          <circle cx="32" cy="22" r="9" fill="none" stroke={accent} strokeWidth="2" strokeOpacity="0.7" />
          <circle cx="32" cy="22" r="3.5" fill={accent} />
          <path d="M32 22 48 10" stroke={accent} strokeWidth="2" strokeLinecap="round" />
          <circle cx="12" cy="36" r="1.6" fill={tint} />
        </g>
      )}
    </svg>
  );
}
