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
    hint: "看它现在的配置哪里不合规",
  },
  {
    mode: "generate",
    label: "生成新配置",
    hint: "按受控模板写一份可以照抄的",
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

  return (
    <div className="configuration-page">
      <header className="configuration-header">
        <div>
          <h1>配置</h1>
          <p>
            {mode === "inspect"
              ? "读取这台主机上的配置文件，对照基线看哪里不合规。只读，不改动。"
              : "从受控模板生成一份配置，检查无误后再照着改主机。"}
          </p>
        </div>
        <nav className="configuration-modes" aria-label="配置视图">
          {MODES.map((entry) => (
            <button
              key={entry.mode}
              type="button"
              className={mode === entry.mode ? "is-active" : ""}
              aria-current={mode === entry.mode ? "page" : undefined}
              onClick={() => void switchTo(entry.mode)}
            >
              <strong>{entry.label}</strong>
              <em>{entry.hint}</em>
            </button>
          ))}
        </nav>
      </header>

      {/* Disconnected, the checking half still lists what it would check and
          says it cannot scan. Reading the catalogue before an event is worth
          more than a screen that refuses to open. */}
      {mode === "inspect" ? (
        <BaselinePage bindingHandle={bindingHandle} api={api} embedded />
      ) : (
        <ConfigGeneratorPage ref={generatorRef} embedded />
      )}
    </div>
  );
});
