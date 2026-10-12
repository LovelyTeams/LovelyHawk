import { forwardRef, useImperativeHandle, useRef, useState, type ComponentProps } from "react";
import type { CaseLibraryApi, CaseStatusAction } from "../shared/case-library-contract";
import { CaseWorkspacePage, type CaseWorkspaceHandle } from "./CaseWorkspacePage";
import { CaseLibraryPanel } from "./CaseLibraryPanel";

type Props = ComponentProps<typeof CaseWorkspacePage> & { api: CaseLibraryApi; initialCaseId?: string | undefined };
export const CasesPage = forwardRef<CaseWorkspaceHandle, Props>(function CasesPage(props, ref) {
  const [mode, setMode] = useState<"live" | "library">(props.bindingHandle === null || props.initialCaseId ? "library" : "live");
  const [statusRequest, setStatusRequest] = useState<{ caseId: string; action: CaseStatusAction } | null>(null);
  const child = useRef<CaseWorkspaceHandle>(null);
  const local = mode === "library" || props.bindingHandle === null;
  useImperativeHandle(ref, () => ({ beforeDeactivate: async () => await child.current?.beforeDeactivate() ?? true }), []);
  async function select(next: "live" | "library") { if (await child.current?.beforeDeactivate() ?? true) { setStatusRequest(null); setMode(next); } }
  async function statusCase(caseId: string, action: CaseStatusAction) {
    if (await child.current?.beforeDeactivate() ?? true) { setStatusRequest({ caseId, action }); setMode("library"); }
  }
  return <div className="cases-page"><nav className="cases-mode" aria-label="案件范围">
    <div className="cases-mode-switch">
      <button type="button" aria-pressed={!local} disabled={props.bindingHandle === null} onClick={() => void select("live")}>当前主机</button>
      <button type="button" aria-pressed={local} onClick={() => void select("library")}>本机案件库</button>
    </div>
    {props.bindingHandle === null ? <span>未连接主机，可离线查看已保存的案件</span> : null}
  </nav>{local ? <CaseLibraryPanel ref={child} api={props.api} initialCaseId={statusRequest?.caseId ?? props.initialCaseId} initialStatusAction={statusRequest?.action} /> : <CaseWorkspacePage {...props} ref={child} onStatusCase={statusCase} />}</div>;
});
