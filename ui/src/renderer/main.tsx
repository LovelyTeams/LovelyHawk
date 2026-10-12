import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { installMainHost } from "../host/install";
import { App } from "./App";
import "./theme/themes.css";
import "./styles.css";

installMainHost();

const root = document.getElementById("root");
if (root === null) throw new Error("LovelyHawk renderer root is missing.");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
