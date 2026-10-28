import { createRoot } from "react-dom/client";

import { installChannelHost, installChildHost } from "../host/install";
import { WindowsChannelWindow } from "./WindowsChannelWindow";
import { FileEditorWindow } from "./FileEditorWindow";
import { TerminalWindow, terminalWindowKind } from "./TerminalWindow";
import "./theme/themes.css";
import "./styles.css";

const kind = new URLSearchParams(window.location.search).get("window");
if (kind === "windows-channel") installChannelHost();
else installChildHost();

const root = document.getElementById("root");
if (root === null) throw new Error("LovelyHawk terminal renderer root is missing.");

/**
 * Which of the terminal-family windows this is.
 *
 * Read from the URL the host loaded, which the host also validated: a window that is
 * not one of the family never reaches this file, because the host refuses any
 * other page for it. Anything unrecognised falls back to the terminal rather
 * than rendering nothing.
 */

/**
 * xterm measures its cells once, when it opens. With the bundled monospace
 * font still loading it measured the fallback font; the real one then made
 * every cell wider in a box that did not change size, so nothing refitted the
 * grid and its last columns ran past the right edge. Waiting for the font
 * first costs a few milliseconds; a font that never comes is waited for
 * briefly and then given up on, and the terminal uses the fallback throughout.
 */
const FONT_WAIT_MS = 1_500;
const fontReady = Promise.race([
  document.fonts.load('13px "Cascadia Mono"').then(() => undefined, () => undefined),
  new Promise<void>((resolve) => window.setTimeout(resolve, FONT_WAIT_MS)),
]);

void fontReady.then(() => {
  createRoot(root).render(
    kind === "windows-channel" ? <WindowsChannelWindow /> : kind === "file-editor" ? <FileEditorWindow /> : <TerminalWindow kind={terminalWindowKind(kind)} />,
  );
});
