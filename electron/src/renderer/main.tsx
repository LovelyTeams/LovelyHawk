import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./theme/themes.css";
import "./styles.css";

const root = document.getElementById("root");
if (root === null) throw new Error("LovelyRes renderer root is missing.");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
