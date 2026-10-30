import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const app = readFileSync(new URL("./App.tsx", import.meta.url), "utf8");

/** Every page the registry can show. Each one is its own chunk. */
const PAGES = [
  "SecurityReference", "Notes", "ConfigurationPage", "SystemInfoPage", "AiHistoryPage",
  "CheckAuditPage", "IntegrityPage", "LogAnalysisPage", "PacketCapturePage",
  "KubernetesPage", "DockerPage", "EmergencyCommandsPage", "ResponseEnginePage",
];

/**
 * Pages hosted by another page rather than by the shell. They ride in their
 * host's chunk, which is still loaded on demand, so the shell must not import
 * them at all.
 */
const HOSTED = { ConfigurationPage: ["BaselinePage", "ConfigGeneratorPage", "NginxRepairPage"] };

describe("renderer code splitting", () => {
  /**
   * Every page used to be parsed at boot even though the window shows one at a
   * time, which put the entry chunk over the bundler's size warning. A static
   * import added back here would silently undo that, so the shape is pinned.
   */
  it("loads each page on demand rather than in the entry chunk", () => {
    for (const page of PAGES) {
      expect(app, page).toContain(
        `const ${page} = lazy(async () => ({ default: (await import("./${page}")).${page} }));`,
      );
      // A static import of the same component would pull it back into the entry.
      expect(app, page).not.toMatch(
        new RegExp(`^import \\{[^}]*\\b${page}\\b[^}]*\\} from "\\./${page}";`, "mu"),
      );
    }
  });

  /** A chunk that is still arriving needs somewhere to land. */
  it("keeps one boundary around the page area", () => {
    expect(app).toContain("Suspense");
    expect(app).toMatch(/<Suspense fallback=\{<div className="content-page-loading"/u);
    expect(app.match(/<Suspense/gu)).toHaveLength(1);
    expect(app.match(/<\/Suspense>/gu)).toHaveLength(1);
    // The fallback sits inside the content area, so the shell never blanks.
    const content = app.slice(app.indexOf('<main className="content">'));
    expect(content.indexOf("<Suspense")).toBeLessThan(content.indexOf("activePage === null"));
  });

  /**
   * The handles the shell asks before leaving a page are types only, so they
   * cost nothing at runtime and must not drag the component back in.
   */
  it("keeps the imperative handles as type-only imports", () => {
    expect(app).toContain('import type { NotesHandle } from "./Notes";');
    expect(app).toContain(
      'import type { ConfigurationPageHandle } from "./ConfigurationPage";',
    );
  });

  /** The shell itself stays eager: it is what draws while a page loads. */
  it("keeps the window shell in the entry chunk", () => {
    for (const shell of ["AppTitleBar", "WelcomeView", "NotificationStack"]) {
      expect(app, shell).toMatch(new RegExp(`import \\{ ${shell}[,} ]`, "u"));
    }
  });
});
