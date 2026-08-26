import { forwardRef, useImperativeHandle, useRef, useState } from "react";

import type { BaselineReadApi } from "../shared/baseline-read-contract";
import { BaselinePage } from "./BaselinePage";
import {
  ConfigGeneratorPage,
  type ConfigGeneratorPageHandle,
} from "./ConfigGeneratorPage";
import "./configuration-page.css";

/** What the operator is doing with a configuration right now. */
export type ConfigurationMode = "inspect" | "generate";

export interface ConfigurationPageProps {
  bindingHandle: string | null;
  api: BaselineReadApi;
}

export interface ConfigurationPageHandle {
  beforeDeactivate(): Promise<boolean>;
}

const MODES: { mode: ConfigurationMode; label: string; hint: string }[] = [
  {
    mode: "inspect",
    label: "检查这台主机",
    hint: "读取这台主机上的配置文件，对照基线看哪里不合规。只读，不改动。",
  },
  {
    mode: "generate",
    label: "生成新配置",
    hint: "从受控模板生成一份配置，检查无误后再照着改主机。",
  },
];

/**
 * Checking a configuration and writing one are the same job seen from two
 * ends, so they share a page: the same shell, and on the right the same thing
 * — a configuration file. In one mode that file is the one on the target; in
 * the other it is the one being written.
 *
 * Only the checking half needs a target. Generating works with nothing
 * connected, which is what preparation before an event looks like, so the page
 * itself stays reachable offline.
 *
 * The switch between the two rides in whichever row the half below already
 * has. It used to sit in a header of its own, with the page's name repeated
 * from the title bar and a paragraph explaining each half — a hundred pixels
 * across the top of the window, every time, to say something the operator
 * learned once.
 */
export const ConfigurationPage = forwardRef<ConfigurationPageHandle, ConfigurationPageProps>(
function ConfigurationPage({ bindingHandle, api }, ref) {
  const [mode, setMode] = useState<ConfigurationMode>("inspect");
  const generatorRef = useRef<ConfigGeneratorPageHandle>(null);

  // A half-written draft belongs to the generator, so leaving the page asks it
  // first — including when the page is left by switching away from it entirely.
  useImperativeHandle(ref, () => ({
    async beforeDeactivate() {
      return await generatorRef.current?.beforeDeactivate() ?? true;
    },
  }), []);

  async function switchTo(next: ConfigurationMode): Promise<void> {
    if (next === mode) return;
    if (mode === "generate" && await generatorRef.current?.beforeDeactivate() === false) return;
    setMode(next);
  }

  const modeSwitch = (
    <div className="configuration-modes" role="group" aria-label="配置视图">
      {MODES.map((entry) => (
        <button
          key={entry.mode}
          type="button"
          className={mode === entry.mode ? "is-active" : ""}
          aria-pressed={mode === entry.mode}
          title={entry.hint}
          onClick={() => void switchTo(entry.mode)}
        >
          <strong>{entry.label}</strong>
        </button>
      ))}
    </div>
  );

  return (
    <div className="configuration-page">
      {/* Disconnected, the checking half still lists what it would check and
          says it cannot scan. Reading the catalogue before an event is worth
          more than a screen that refuses to open. */}
      {mode === "inspect" ? (
        <BaselinePage bindingHandle={bindingHandle} api={api} embedded modeSwitch={modeSwitch} />
      ) : (
        <ConfigGeneratorPage ref={generatorRef} embedded modeSwitch={modeSwitch} />
      )}
    </div>
  );
});
