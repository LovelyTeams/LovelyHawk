import { forwardRef, useImperativeHandle, useRef, useState } from "react";

import type { BaselineReadApi } from "../shared/baseline-read-contract";
import { isConfigVisualView, type ConfigVisualApi, type ConfigVisualView } from "../shared/config-visual-contract";
import type { NginxRepairApi } from "../shared/nginx-repair-contract";
import { NginxRepairPage, type NginxRepairPageHandle } from "./NginxRepairPage";
import { BaselinePage } from "./BaselinePage";
import {
  ConfigGeneratorPage,
  type ConfigGeneratorPageHandle,
} from "./ConfigGeneratorPage";
import { ConfigVisualEditor, type ConfigVisualEditorHandle } from "./ConfigVisualEditor";
import "./configuration-page.css";

/** What the operator is doing with a configuration right now. */
export type ConfigurationMode = "inspect" | "generate" | "visual" | "repair";

export interface ConfigurationPageProps {
  bindingHandle: string | null;
  api: BaselineReadApi & NginxRepairApi & ConfigVisualApi;

  onCopyRecord?: ((text: string) => Promise<unknown>) | undefined;
}

export interface ConfigurationPageHandle {
  beforeDeactivate(): Promise<boolean>;
}

const MODES: { mode: ConfigurationMode; label: string; hint: string }[] = [
  {
    mode: "inspect",
    label: "检查这台主机",
    hint: "读取这台主机上的配置文件，对照基线看哪里不合规；选中一项后可以先看修改计划，确认后才改动。",
  },
  {
    mode: "repair",
    label: "修补已有配置",
    hint: "识别 Nginx 实例，预览差异后修补并验证，可从历史准备恢复。",
  },
  {
    mode: "generate",
    label: "生成新配置",
    hint: "从受控模板生成一份配置，检查无误后再照着改主机。",
  },
  {
    mode: "visual",
    label: "可视化编辑",
    hint: "把 Nginx、Apache httpd、Redis 或 HAProxy 配置文件显示成一棵树，带中文说明，逐项修改、添加、删除并另存为新文件。",
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
function ConfigurationPage({ bindingHandle, api, onCopyRecord }, ref) {
  const [mode, setMode] = useState<ConfigurationMode>("inspect");
  const [openedVisual, setOpenedVisual] = useState<ConfigVisualView | null>(null);
  /** How a document opened from the goal search starts: unsaved, and with a parameter to find. */
  const [openedFocus, setOpenedFocus] = useState<{ dirty: boolean; parameterKey: string | null } | null>(null);
  const generatorRef = useRef<ConfigGeneratorPageHandle>(null);
  const repairRef = useRef<NginxRepairPageHandle>(null);
  const visualRef = useRef<ConfigVisualEditorHandle>(null);

  // A half-written draft belongs to the generator, so leaving the page asks it
  // first — including when the page is left by switching away from it entirely.
  useImperativeHandle(ref, () => ({
    async beforeDeactivate() {
      if (await repairRef.current?.beforeDeactivate() === false) return false;
      if (await visualRef.current?.beforeDeactivate() === false) return false;
      return await generatorRef.current?.beforeDeactivate() ?? true;
    },
  }), []);

  async function switchTo(next: ConfigurationMode): Promise<void> {
    if (next === mode) return;
    if (mode === "generate" && await generatorRef.current?.beforeDeactivate() === false) return;
    if (mode === "repair" && await repairRef.current?.beforeDeactivate() === false) return;
    if (mode === "visual" && await visualRef.current?.beforeDeactivate() === false) return;
    setOpenedVisual(null);
    setOpenedFocus(null);
    setMode(next);
  }

  /**
   * A database file the goal search found, or a value it wrote, opened in
   * the visual editor. The document is made first; if the generator then
   * keeps the page, the new document is let go and nothing else changes.
   */
  async function openVisualView(create: () => Promise<ConfigVisualView>,
    focus: { dirty: boolean; parameterKey: string | null }): Promise<boolean> {
    const opened = await create();
    if (await generatorRef.current?.beforeDeactivate() === false) {
      await api.configVisual({ action: "close", documentHandle: opened.documentHandle, revision: opened.revision })
        .catch(() => undefined);
      return false;
    }
    setOpenedVisual(opened);
    setOpenedFocus(focus);
    setMode("visual");
    return true;
  }

  /**
   * A quick Nginx draft opened as a tree. The tree is made first, from the
   * draft as it is now; only then does the generator let its draft go.
   */
  async function openInVisual(source: { handle: string; revision: number; artifactKey: string }): Promise<void> {
    const opened = await api.configVisual({ action: "open-quick", ...source });
    if (!isConfigVisualView(opened)) throw new Error("可视化文档没有通过校验。");
    if (await generatorRef.current?.beforeDeactivate() === false) {
      await api.configVisual({ action: "close", documentHandle: opened.documentHandle, revision: opened.revision })
        .catch(() => undefined);
      return;
    }
    setOpenedVisual(opened);
    setMode("visual");
  }

  const modeSwitch = (
    <div className="configuration-modes view-tabs" role="group" aria-label="配置视图">
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
    <div className={mode === "generate" ? "configuration-page is-filling" : "configuration-page"}>
      {/* Disconnected, the checking half still lists what it would check and
          says it cannot scan. Reading the catalogue before an event is worth
          more than a screen that refuses to open. */}
      {mode === "inspect" ? (
        <BaselinePage bindingHandle={bindingHandle} api={api} embedded modeSwitch={modeSwitch} />
      ) : mode === "repair" ? (
        <NginxRepairPage ref={repairRef} bindingHandle={bindingHandle} api={api} modeSwitch={modeSwitch} onCopyRecord={onCopyRecord} />
      ) : mode === "visual" ? (
        <ConfigVisualEditor ref={visualRef} api={api} initialView={openedVisual} modeSwitch={modeSwitch}
          initialDirty={openedFocus?.dirty ?? false} initialParameterKey={openedFocus?.parameterKey ?? null} />
      ) : (
        <ConfigGeneratorPage ref={generatorRef} embedded modeSwitch={modeSwitch} onOpenVisual={openInVisual}
          onOpenVisualView={openVisualView} />
      )}
    </div>
  );
});
