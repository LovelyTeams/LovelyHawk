import { createRoot } from "react-dom/client";

import { TerminalWindow } from "./TerminalWindow";
import "./theme/themes.css";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) throw new Error("LovelyRes terminal renderer root is missing.");

createRoot(root).render(<TerminalWindow />);
