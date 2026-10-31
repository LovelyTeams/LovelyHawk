// Synthetic data for the real debug desktop host. Never shipped in the app.
import { createRoot } from "react-dom/client";
import { EmergencyCommandsPage, type EmergencyCommandsPageProps } from "../src/renderer/EmergencyCommandsPage";
import type { EmergencyCommandCatalog, EmergencyCommandResult } from "../src/shared/emergency-command-contract";

interface Options { delay?: boolean; fail?: boolean; empty?: boolean; long?: boolean;
  observations?: Record<string, { stdout: string; status: number }>; }
export function mount() {
  const container = document.createElement("div");
  container.id = "command-workbench-fixture";
  container.style.cssText = "height:100%;width:100%;min-width:0";
  const content = document.querySelector("main.content")!;
  [...content.children].forEach(child => { if (child instanceof HTMLElement) child.hidden = true; });
  content.append(container);
  const root = createRoot(container);
  const calls: { binding: string; snapshot: string; command: string; container?: string | undefined }[] = [];
  const pending: (() => void)[] = [];
  let options: Options = {};
  let generation = 0;
  let binding: string | null = null;
  const forbidden = async () => { throw new Error("Fixture does not authorize file changes"); };
  const catalog = (value: string): EmergencyCommandCatalog => ({
    snapshotHandle: `catalog-${value}`, expiresInSeconds: 300, commandSet: "detected",
    commands: [
      { commandHandle: `${value}-wrapper`, category: "persistence", title: "排查命令包装器", description: "检查 /usr/local/bin 中调用系统程序并过滤输出的脚本；只读核对，不执行或删除。", timeoutSeconds: 30 },
      { commandHandle: `${value}-pam`, category: "persistence", title: "PAM 认证规则与变更", description: "检查直接放行认证的 pam_permit 规则并查看配置、模块文件属性；需结合完整认证链核实。", timeoutSeconds: 60 },
      { commandHandle: `${value}-preload`, category: "processes", title: "预加载与会话环境", description: "检查预加载配置与进程的预加载、审计库、提示命令变量；仅显示位置和变量名。", timeoutSeconds: 60 },
      { commandHandle: `${value}-deleted`, category: "processes", title: "已删除文件与映射", description: "查看进程仍持有的已删除文件和映射；升级、日志轮转也可能产生此现象。", timeoutSeconds: 60 },
      { commandHandle: `${value}-network`, category: "network", title: "监听端口", description: "复用原有网络排查入口。", timeoutSeconds: 30 },
      { commandHandle: `${value}-history`, category: "logs", title: "命令历史文件", description: "检查口令、下载执行与清理记录线索；只显示位置和特征。", timeoutSeconds: 60 },
      { commandHandle: `${value}-credential`, category: "files", title: "凭据与站点备份文件", description: "列出凭据属性与站点备份、数据库导出；不读取内容。", timeoutSeconds: 60 },
      { commandHandle: `${value}-web`, category: "files", title: "站点可疑代码特征", description: "检查请求输入或解码结果进入执行函数的特征，不执行代码。", timeoutSeconds: 60 },
    ],
    containers: [{ kind: "container", containerHandle: `container-${value}`, name: "fixture-lab", image: "fixture:readonly" }],
  });
  const api: EmergencyCommandsPageProps["api"] = {
    async loadEmergencyCommandCatalog(value) { return catalog(value); },
    async runEmergencyCommand(value, snapshot, command, place) {
      calls.push({ binding: value, snapshot, command, container: place });
      const captured = { ...options };
      const observed = captured.observations?.[command.slice(value.length + 1)];
      const output = (observed?.stdout ?? (captured.empty ? "" : ["# 范围：当前账号可读内容", "普通清单信息",
        `关注：${value} | <img src=x onerror=steal()> ${captured.long ? "长中文证据".repeat(130) : "调用系统程序并过滤输出，需核对来源"}`,
        "缺口：部分进程权限不足，尚未检查", "# 已检查对象 4；关注线索 1；读取缺口 1。线索不等于入侵结论。"].join("\n"))).replace(/\n$/u, "");
      const lines = output === "" ? [] : output.split("\n");
      const result: EmergencyCommandResult = { snapshotHandle: snapshot, commandHandle: command,
        resultKind: captured.empty ? "empty" : observed?.status === 0 ? "success" : "non-zero", exitCode: observed?.status ?? (captured.empty ? 0 : 1),
        output, observedLineCount: lines.length, displayedLineCount: lines.length,
        findingLines: lines.flatMap((line, index) => line.startsWith("关注：") ? [index] : []), findingReason: captured.empty ? null : "标记的是检查线索，需核对来源与用途，不能据此直接删除或结束进程。",
        truncated: false, paths: [] };
      if (captured.delay) await new Promise<void>(resolve => pending.push(resolve));
      if (captured.fail) throw new Error("fixture read failed");
      return result;
    },
    fileEvidence: forbidden, inspectEmergencyPath: forbidden, planEmergencyPathAction: forbidden,
    confirmEmergencyPathAction: forbidden, executeEmergencyPathAction: forbidden,
    cancelEmergencyPathAction: forbidden, undoEmergencyPathAction: forbidden,
    async locateEmergencyHistoryCommand(value) { return { status: "found", commandHandle: `${value}-wrapper` }; },
  };
  return {
    calls,
    render(value: string | null, next: Options = {}, extra: Pick<EmergencyCommandsPageProps, "rerun" | "runIn"> = {}) {
      binding = value; options = next;
      root.render(<EmergencyCommandsPage key={generation} bindingHandle={binding} api={api} {...extra} />);
    },
    reset() { generation++; calls.length = 0; },
    resolveOne() { pending.shift()?.(); },
    pendingCount() { return pending.length; },
    unmount() { root.unmount(); container.remove(); },
  };
}
