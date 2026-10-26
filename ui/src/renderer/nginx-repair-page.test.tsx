import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { NginxRepairState } from "./nginx-repair-controller";
const fixture = vi.hoisted(() => ({ state: {} as NginxRepairState }));
vi.mock("./nginx-repair-controller", () => ({ NginxRepairController: class {
  getSnapshot = () => fixture.state;
  subscribe = () => () => {};
} }));
import { NginxRepairPage } from "./NginxRepairPage";
const api = { nginxRepair: vi.fn() };
beforeEach(() => { fixture.state = { inventory: null, configuration: null, history: null, selectedInstance: null, endpoints: null, connectivity: null, reading: null, error: null, dialog: null }; });
const render = (bindingHandle: string | null = "b") => renderToStaticMarkup(<NginxRepairPage api={api} bindingHandle={bindingHandle} />);
describe("Nginx repair presentation", () => {
  it("keeps unsaved observations readable and offers retry or explicit discard without a saved receipt", () => {
    fixture.state.selectedInstance = "i";
    fixture.state.connectivity = { kind: "connectivity", observationHandle: "observation-1", recordText: "原始完整记录 <img>",
      retention: { state: "unsaved", caseId: "original", caseTitle: "原案件", evidenceId: null, sha256: null, detail: "案件保存失败", canRetry: true },
      endpointHandle: "e", serverName: "a.test", path: "/", checkedAt: "2026-09-08T12:00:00Z", report: { clientVersion: "OpenSSL test", rows: (["TLSv1", "TLSv1_1", "TLSv1_2", "TLSv1_3"] as const).map((version) => ({ version, outcome: "inconclusive", detail: "timeout", certificateSha256: null, httpOutcome: "not-sent", httpStatus: null })) } };
    const markup = renderToStaticMarkup(<NginxRepairPage api={api} bindingHandle="b" onCopyRecord={vi.fn()} />);
    for (const text of ["本次观察尚未留证", "重试保存本次观察", "复制完整记录", "放弃未保存结果", "5 分钟", "未能判断"]) expect(markup).toContain(text);
    expect(markup).not.toContain("已留存到案件"); expect(markup).not.toContain("查看留证案件");
    expect(markup).toContain('disabled="">识别 Nginx 实例'); expect(markup).not.toContain("案件记录 SHA-256");
    expect(markup).toContain("原始完整记录 &lt;img&gt;"); expect(markup).not.toContain("<img>");
    fixture.state.connectivity.retention.caseId = null; fixture.state.connectivity.retention.caseTitle = null;
    expect(render()).toContain("本次尚未确定归属案件"); expect(render()).toContain("重试保存时使用届时的当前案件");
    fixture.state.connectivity.retention.canRetry = false; fixture.state.connectivity.recordText = null;
    const unavailable = renderToStaticMarkup(<NginxRepairPage api={api} bindingHandle="b" onCopyRecord={vi.fn()} />);
    expect(unavailable).not.toContain("重试保存本次观察"); expect(unavailable).not.toContain("复制完整记录"); expect(unavailable).toContain("放弃未保存结果");
  });
  it("reports TLS refusal, certificate failure and HTTP errors without claiming business recovery", () => {
    fixture.state.selectedInstance = "i";
    fixture.state.endpoints = { kind: "listeners", instanceHandle: "i", endpoints: [{ endpointHandle: "e", address: "127.0.0.1", port: 8443, connectAddress: "127.0.0.1" }] };
    fixture.state.connectivity = { kind: "connectivity", observationHandle: "observation-1", recordText: "完整观察", retention: { state: "saved", caseId: "case-1", caseTitle: "应急案件", evidenceId: "evidence-1", sha256: "a".repeat(64), detail: "已保存", canRetry: false }, endpointHandle: "e", serverName: "a.test", path: "/missing", checkedAt: "2026-09-08T12:00:00Z", report: { clientVersion: "OpenSSL test", rows: [
      { version: "TLSv1", outcome: "protocol-rejected", detail: "server-protocol-alert", certificateSha256: null, httpOutcome: "not-sent", httpStatus: null },
      { version: "TLSv1_1", outcome: "inconclusive", detail: "handshake-failed", certificateSha256: null, httpOutcome: "not-sent", httpStatus: null },
      { version: "TLSv1_2", outcome: "accepted", detail: "identity-verified", certificateSha256: "a".repeat(64), httpOutcome: "status", httpStatus: 404 },
      { version: "TLSv1_3", outcome: "certificate-rejected", detail: "certificate-verification-failed", certificateSha256: null, httpOutcome: "not-sent", httpStatus: null },
    ] } };
    const markup = render();
    for (const text of ["读取监听端口", "HTTP 404", "明确拒绝此版本", "未能判断", "证书校验失败", "目标系统信任库", "不能证明公网", "连接可能产生访问日志"]) expect(markup).toContain(text);
    expect(markup).not.toContain("业务已恢复"); expect(markup).toContain('disabled="">开始连接复核');
  });
  it("offers a discoverable offline explanation without mutation controls", () => {
    const markup = render(null);
    expect(markup).toContain("请先连接目标主机"); expect(markup).toContain("识别 Nginx 实例");
    expect(markup).not.toContain("确认并执行"); expect(markup).toContain("不会自动安装工具");
  });
  it("shows unresolved scope and exact file/line, and renders host data as plain text", () => {
    fixture.state.configuration = { kind: "configuration", instanceHandle: "i", configurationHandle: "g", fileCount: 3, unresolvedIncludes: 2,
      candidates: [{ candidateHandle: "c", setting: "autoindex", title: "关闭目录列表", path: "/etc/nginx/<img onerror=alert(1)>.conf", line: 37, before: "autoindex on;", after: "autoindex off;" }] };
    const markup = render(); expect(markup).toContain("第 37 行"); expect(markup).toContain("当前不能修补");
    expect(markup).toContain('disabled="" aria-label="准备修补'); expect(markup).not.toContain("<img");
    expect(markup).toContain("&lt;img");
  });
  it("does not label an empty supported rule list as compliant", () => {
    fixture.state.configuration = { kind: "configuration", instanceHandle: "i", configurationHandle: "g", fileCount: 2, unresolvedIncludes: 0, candidates: [] };
    expect(render()).toContain("这不代表整个实例已通过安全基线");
  });
  it("makes TLS compatibility and the exact protocol reduction visible", () => {
    fixture.state.configuration = { kind: "configuration", instanceHandle: "i", configurationHandle: "g", fileCount: 3, unresolvedIncludes: 0,
      candidates: [{ candidateHandle: "tls", setting: "ssl-protocols", title: "移除旧版 TLS/SSL 协议", path: "/etc/nginx/tls-policy.conf", line: 2,
        before: "ssl_protocols TLSv1 TLSv1.2;", after: "ssl_protocols TLSv1.2;" }] };
    const markup = render();
    expect(markup).toContain("移除旧版 TLS/SSL 协议"); expect(markup).toContain("ssl_protocols TLSv1.2;");
    expect(markup).toContain("仅支持旧版协议的客户端可能无法连接"); expect(markup).toContain("默认服务器");
    expect(markup).toContain("只有旧版协议或包含未知值的位置需单独规划升级");
  });
  it("explains concrete changes, backup and separate business verification inside a modal", () => {
    fixture.state.dialog = { id: 1, phase: "ready", error: null, receipt: null, plan: { planHandle: "p", targetLabel: "root@lab:22 · Nginx 主进程 1", candidateHandle: "c", title: "关闭目录列表",
      path: "/etc/nginx/site.conf", line: 4, diff: "- autoindex on;\n+ autoindex off;", impact: "平滑重载", restoreDescription: "保留远端备份",
      confirmed: false, expiresInSeconds: 300 } };
    const markup = render(); expect(markup).toContain('aria-modal="true"'); expect(markup).toContain('inert=""');
    expect(markup).toContain("root@lab:22 · Nginx 主进程 1");
    expect(markup).toContain("保留远端备份"); expect(markup).toContain("确认并执行"); expect(markup).toContain("本次确认只用于下方计划");
    fixture.state.dialog.phase = "done";
    fixture.state.dialog.receipt = { planHandle: "p", state: "verified", detail: "进程检查通过", recordHandle: "r" };
    const result = render(); expect(result).toContain("修补已通过配置与进程验证"); expect(result).toContain("不能替代业务健康检查");
    expect(result).not.toContain("确认并执行");
  });
});
