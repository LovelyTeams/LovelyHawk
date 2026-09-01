import { createRoot } from "react-dom/client";

import { FileEditorWindow } from "./FileEditorWindow";
import { TerminalWindow } from "./TerminalWindow";
import "./theme/themes.css";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) throw new Error("LovelyRes terminal renderer root is missing.");

/**
 * Which of the terminal-family windows this is.
 *
 * Read from the URL main loaded, which main also validated: a window that is
 * not one of the family never reaches this file, because the custom protocol
 * refuses to serve it. Anything unrecognised falls back to the terminal rather
 * than rendering nothing.
 */
const kind = new URLSearchParams(window.location.search).get("window");

createRoot(root).render(kind === "file-editor" ? <FileEditorWindow /> : <TerminalWindow />);
