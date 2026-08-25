import { useEffect, useReducer, useRef, useState } from "react";

import {
  isQuickDetectionCancellation,
  isQuickDetectionCatalog,
  isQuickDetectionHistoryPage,
  isQuickDetectionPlan,
  isQuickDetectionPlanInput,
  isQuickDetectionPoll,
  isQuickDetectionReport,
  isQuickDetectionScanStarted,
  type QuickDetectionApi,
  type QuickDetectionModuleId,
  type QuickDetectionOutcome,
  type QuickDetectionReport,
} from "../shared/quick-detection-contract";
import {
  cancelQuickDetectionLifecycle,
  createQuickDetectionPlanInput,
  filterQuickDetectionModules,
  formatQuickDetectionTime,
  quickDetectionOutcomeLabel,
  quickDetectionProgress,
  quickDetectionSeverityLabel,
  quickDetectionStageIsActive,
  quickDetectionStatusLabel,
  type QuickDetectionResultFilter,
} from "./quick-detection-helpers";
import {
  createQuickDetectionState,
  quickDetectionReducer,
} from "./quick-detection-state";
import "./quick-detection.css";

interface QuickDetectionPageProps {
  bindingHandle: string | null;
  api: QuickDetectionApi;
}

const HISTORY_PAGE_SIZE = 8;
const POLL_PAGE_SIZE = 32;
const POLL_DELAY_MS = 250;

export function QuickDetectionPage({ bindingHandle, api }: QuickDetectionPageProps) {
  const [state, dispatch] = useReducer(quickDetectionReducer, undefined, createQuickDetectionState);
  const [historyVersion, setHistoryVersion] = useState(0);
  const requestRef = useRef(0);
  const lifecycleScanRef = useRef<{
    bindingHandle: string;
    scanHandle: string;
    stage: typeof state.scanStage;
  } | null>(null);
  const scope = bindingHandle;
  const stateIsCurrent = state.scope === scope;

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (scope === null) return;
    dispatch({ type: "catalog-started", scope });
    void api.getQuickDetectionCatalog().then((result) => {
      if (!isQuickDetectionCatalog(result)) throw new Error();
      dispatch({ type: "catalog-loaded", scope, catalog: result });
    }).catch(() => {
      dispatch({ type: "catalog-failed", scope, error: "快速检测目录未通过本地边界校验。" });
    });
  }, [api, scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null) return;
    const request = ++requestRef.current;
    dispatch({ type: "history-started", scope, request });
    void api.listQuickDetectionHistory(bindingHandle, 0, HISTORY_PAGE_SIZE).then((result) => {
      if (!isQuickDetectionHistoryPage(result) || result.offset !== 0) throw new Error();
      dispatch({ type: "history-loaded", scope, request, history: result });
    }).catch(() => {
      dispatch({ type: "history-failed", scope, request, error: "无法读取当前 SSH 绑定的检测历史。" });
    });
  }, [api, bindingHandle, historyVersion, scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope || state.scanHandle === null ||
      !quickDetectionStageIsActive(state.scanStage)) return;
    const scanHandle = state.scanHandle;
    let stopped = false;
    let cursor = state.eventCursor;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const poll = async () => {
      const afterEvent = cursor;
      const request = ++requestRef.current;
      dispatch({ type: "poll-started", scope, scanHandle, request, afterEvent });
      try {
        const result = await api.pollQuickDetection(bindingHandle, scanHandle, afterEvent, POLL_PAGE_SIZE);
        if (stopped) return;
        if (!isQuickDetectionPoll(result) || result.scanHandle !== scanHandle ||
          result.nextEventCursor < afterEvent) throw new Error();
        cursor = result.nextEventCursor;
        dispatch({ type: "poll-loaded", scope, scanHandle, request, afterEvent, poll: result });
        if (quickDetectionStageIsActive(result.stage)) {
          timer = setTimeout(() => void poll(), POLL_DELAY_MS);
        } else if (result.reportHandle !== null) {
          setHistoryVersion((version) => version + 1);
        }
      } catch {
        if (!stopped) {
          dispatch({
            type: "poll-failed", scope, scanHandle, request, afterEvent,
            error: "无法轮询当前检测任务。",
          });
        }
      }
    };

    void poll();
    return () => {
      stopped = true;
      if (timer !== null) clearTimeout(timer);
    };
  }, [api, bindingHandle, scope, state.scanHandle]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope || state.scanHandle === null) {
      return;
    }
    lifecycleScanRef.current = {
      bindingHandle,
      scanHandle: state.scanHandle,
      stage: state.scanStage,
    };
  }, [bindingHandle, scope, state.scanHandle, state.scanStage, state.scope]);

  useEffect(() => () => {
    const scan = lifecycleScanRef.current;
    lifecycleScanRef.current = null;
    if (scan !== null) {
      void cancelQuickDetectionLifecycle(api, scan.bindingHandle, scan.scanHandle, scan.stage);
    }
  }, [api, scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope ||
      state.selectedReportHandle === null || state.reportStatus !== "idle") return;
    const handle = state.selectedReportHandle;
    const request = ++requestRef.current;
    dispatch({ type: "report-started", scope, request, handle });
    void api.getQuickDetectionReport(bindingHandle, handle).then((result) => {
      if (!isQuickDetectionReport(result) || result.reportHandle !== handle) throw new Error();
      dispatch({ type: "report-loaded", scope, request, handle, report: result });
    }).catch(() => {
      dispatch({ type: "report-failed", scope, request, handle, error: "检测报告已过期、目标已变化或响应无效。" });
    });
  }, [api, bindingHandle, scope, state.reportStatus, state.scope, state.selectedReportHandle]);

  if (bindingHandle === null) {
    return (
      <section className="page quick-detection-page">
        <div className="quick-detection-connect-prompt">
          <span aria-hidden="true">⌁</span>
          <h1>连接目标后运行快速检测</h1>
          <p>只能运行内置的检测模块，且始终针对当前目标。</p>
        </div>
      </section>
    );
  }

  const visibleState = stateIsCurrent ? state : createQuickDetectionState();
  const catalog = visibleState.catalog;
  const scanActive = quickDetectionStageIsActive(visibleState.scanStage);
  const canPlan = catalog !== null && visibleState.catalogStatus === "ready" && !scanActive &&
    visibleState.scanRequest === null && visibleState.selectedModules.length > 0;
  const canStart = visibleState.planStatus === "ready" && visibleState.plan !== null && !scanActive &&
    visibleState.scanRequest === null;

  async function createPlan() {
    if (scope === null || bindingHandle === null || catalog === null || !canPlan) return;
    const input = createQuickDetectionPlanInput(
      visibleState.profile,
      visibleState.selectedModules,
      catalog.maximumFindingsPerModule,
    );
    if (!isQuickDetectionPlanInput(input)) return;
    const request = ++requestRef.current;
    dispatch({ type: "plan-started", scope, request });
    try {
      const result = await api.planQuickDetection(bindingHandle, input);
      if (!isQuickDetectionPlan(result) || result.profile !== input.profile) throw new Error();
      dispatch({ type: "plan-loaded", scope, request, plan: result });
    } catch {
      dispatch({ type: "plan-failed", scope, request, error: "无法为当前 SSH 绑定生成不可变检测计划。" });
    }
  }

  async function startScan() {
    if (scope === null || bindingHandle === null || visibleState.plan === null || !canStart) return;
    const planHandle = visibleState.plan.planHandle;
    const request = ++requestRef.current;
    dispatch({ type: "scan-starting", scope, request, planHandle });
    try {
      const result = await api.startQuickDetection(bindingHandle, planHandle);
      if (!isQuickDetectionScanStarted(result) || result.total !== visibleState.plan.moduleCount) throw new Error();
      dispatch({ type: "scan-started", scope, request, planHandle, started: result });
    } catch {
      dispatch({
        type: "scan-start-failed", scope, request, planHandle,
        error: "检测计划已失效或当前目标已有扫描任务。",
      });
    }
  }

  async function cancelScan() {
    if (scope === null || bindingHandle === null || visibleState.scanHandle === null || !scanActive) return;
    const scanHandle = visibleState.scanHandle;
    dispatch({ type: "cancel-marked", scope, scanHandle });
    try {
      const result = await api.cancelQuickDetection(bindingHandle, scanHandle);
      if (!isQuickDetectionCancellation(result)) throw new Error();
    } catch {
      dispatch({
        type: "scan-cancel-failed", scope, scanHandle,
        error: "无法确认取消；目标变更时旧结果仍会被拒绝。",
      });
    }
  }

  return (
    <section className="page quick-detection-page">
      <header className="page-heading quick-detection-heading">
        <div>
          <h1>快速检测</h1>
          <p>只读检测在当前 SSH 连接上进行。</p>
        </div>
        <div className="quick-detection-actions">
          <button type="button" disabled={!canPlan} onClick={() => void createPlan()}>
            {visibleState.planStatus === "loading" ? "正在生成…" : "生成不可变计划"}
          </button>
          <button type="button" className="primary" disabled={!canStart} onClick={() => void startScan()}>启动检测</button>
          <button type="button" className="danger" disabled={!scanActive} onClick={() => void cancelScan()}>
            {visibleState.scanStage === "cancelling" ? "正在取消…" : "取消检测"}
          </button>
        </div>
      </header>

      {visibleState.error !== null ? <div className="quick-detection-notice error" role="alert">{visibleState.error}</div> : null}
      {visibleState.eventsTruncated ? (
        <div className="quick-detection-notice" role="status">部分进度提示被丢弃，不影响最终报告。</div>
      ) : null}

      <section className="quick-detection-planner" aria-label="检测计划">
        <header>
          <div><p>STEP 1</p><h2>选择扫描配置</h2></div>
          <span>每模块最多 {catalog?.maximumFindingsPerModule ?? 200} 项</span>
        </header>
        {visibleState.catalogStatus === "loading" || visibleState.catalogStatus === "idle" ? (
          <div className="quick-detection-state" role="status">正在读取封闭检测目录…</div>
        ) : null}
        {visibleState.catalogStatus === "ready" && catalog !== null ? (
          <>
            <div className="quick-detection-profiles" role="group" aria-label="扫描配置">
              {catalog.profiles.map((profile) => (
                <button
                  type="button"
                  key={profile.id}
                  className={visibleState.profile === profile.id ? "active" : undefined}
                  aria-pressed={visibleState.profile === profile.id}
                  disabled={scanActive}
                  onClick={() => dispatch({ type: "profile-selected", profile: profile.id })}
                >
                  <strong>{profile.label}</strong>
                  <span>{profile.id === "competition-triage" ? "固定 6 项首分钟只读模块" : "从 13 项封闭模块中选择"}</span>
                </button>
              ))}
              <button
                type="button"
                disabled={visibleState.profile !== "selected" || scanActive}
                onClick={() => dispatch({ type: "select-all-modules" })}
              >选择全部</button>
            </div>
            <div className="quick-detection-modules">
              {catalog.modules.map((module) => {
                const selected = visibleState.selectedModules.includes(module.id);
                const progress = visibleState.moduleProgress[module.id];
                return (
                  <label key={module.id} className={selected ? "selected" : undefined}>
                    <input
                      type="checkbox"
                      checked={selected}
                      disabled={visibleState.profile !== "selected" || scanActive}
                      onChange={() => dispatch({ type: "module-toggled", module: module.id })}
                    />
                    <span><strong>{module.label}</strong><small>{module.categoryLabel} · {module.description}</small></span>
                    {progress !== undefined ? (
                      <em className={progress.outcome ?? "running"}>
                        {progress.outcome === null ? "运行中" : quickDetectionOutcomeLabel(progress.outcome)}
                      </em>
                    ) : null}
                  </label>
                );
              })}
            </div>
          </>
        ) : null}
      </section>

      <section className="quick-detection-progress" aria-live="polite">
        <header>
          <div><p>STEP 2</p><h2>计划与进度</h2></div>
          <strong>{quickDetectionProgress(visibleState.completed, visibleState.total)}%</strong>
        </header>
        {visibleState.plan === null ? <p>选择模块后生成计划；模块变化会使旧计划失效。</p> : (
          <div className="quick-detection-plan-summary">
            <span>{visibleState.plan.summary}</span>
            <small>计划在 {visibleState.plan.expiresInSeconds} 秒内单次使用。</small>
          </div>
        )}
        <div className="quick-detection-progress-track" aria-label="检测进度">
          <span style={{ width: `${quickDetectionProgress(visibleState.completed, visibleState.total)}%` }} />
        </div>
        <footer>
          <span>{visibleState.completed}/{visibleState.total || visibleState.selectedModules.length} 模块</span>
          <span>{visibleState.currentModule === null ? scanStageLabel(visibleState.scanStage) : `正在运行 ${moduleLabel(catalog, visibleState.currentModule)}`}</span>
        </footer>
      </section>

      <div className="quick-detection-results-layout">
        <aside className="quick-detection-history">
          <header><p>历史记录</p><h2>当前目标历史</h2></header>
          {visibleState.historyStatus === "loading" || visibleState.historyStatus === "idle" ? (
            <div className="quick-detection-state" role="status">正在读取历史…</div>
          ) : null}
          {visibleState.historyStatus === "error" ? <div className="quick-detection-state error">历史不可用。</div> : null}
          {visibleState.historyStatus === "ready" && visibleState.history?.items.length === 0 ? (
            <div className="quick-detection-state">当前目标尚无检测历史。</div>
          ) : null}
          {visibleState.history?.items.map((item) => (
            <button
              type="button"
              key={item.reportHandle}
              className={visibleState.selectedReportHandle === item.reportHandle ? "active" : undefined}
              onClick={() => dispatch({ type: "report-selected", handle: item.reportHandle })}
            >
              <span><strong>{quickDetectionStatusLabel(item.status)}</strong><em>{item.overallScore}</em></span>
              <small>{formatQuickDetectionTime(item.startedAt)} · {item.moduleCount} 模块</small>
              <small>严重 {item.summary.critical} · 高危 {item.summary.high} · 失败模块 {item.summary.failedModules}</small>
            </button>
          ))}
        </aside>

        <section className="quick-detection-report-shell">
          {visibleState.selectedReportHandle === null ? (
            <div className="quick-detection-state">运行检测或选择历史记录以查看报告。</div>
          ) : null}
          {visibleState.reportStatus === "loading" ? <div className="quick-detection-state" role="status">正在读取报告…</div> : null}
          {visibleState.reportStatus === "error" ? <div className="quick-detection-state error" role="alert">报告不可用。</div> : null}
          {visibleState.reportStatus === "ready" && visibleState.report !== null ? (
            <QuickDetectionReportView
              report={visibleState.report}
              selectedModuleId={visibleState.selectedReportModule}
              onSelectModule={(module) => dispatch({ type: "report-module-selected", module })}
            />
          ) : null}
        </section>
      </div>
    </section>
  );
}

export function QuickDetectionReportView({
  report,
  selectedModuleId,
  onSelectModule,
}: {
  report: QuickDetectionReport;
  selectedModuleId: QuickDetectionModuleId | null;
  onSelectModule: (module: QuickDetectionModuleId) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<QuickDetectionResultFilter>("all");
  const visibleModules = filterQuickDetectionModules(report.modules, query, filter);
  const selected = visibleModules.find((module) => module.id === selectedModuleId) ?? visibleModules[0] ?? null;

  return (
    <div className="quick-detection-report">
      <header>
        <div>
          <p>BOUND REPORT · {quickDetectionStatusLabel(report.status)}</p>
          <h2>检测报告</h2>
          <span>{formatQuickDetectionTime(report.startedAt)} · {report.durationMs} ms</span>
        </div>
        <strong>{report.overallScore}<small>/100</small></strong>
      </header>
      <section className="quick-detection-summary" aria-label="检测摘要">
        <article><span>严重</span><strong>{report.summary.critical}</strong></article>
        <article><span>高危</span><strong>{report.summary.high}</strong></article>
        <article><span>中危</span><strong>{report.summary.medium}</strong></article>
        <article><span>失败模块</span><strong>{report.summary.failedModules}</strong></article>
        <article><span>错误模块</span><strong>{report.summary.errorModules}</strong></article>
      </section>
      <div className="quick-detection-remediation-boundary" role="note">
        自动修复尚未迁移到完整的 plan / exact confirmation / journal / verify / restore 闭环，本页不提供修复操作。
      </div>
      {report.redactedFieldCount > 0 ? (
        <div className="quick-detection-notice" role="status">
          {report.redactedFieldCount} 个敏感字段已被遮蔽。
        </div>
      ) : null}
      <div className="quick-detection-report-filters">
        <label>筛选<input value={query} maxLength={256} onChange={(event) => setQuery(event.target.value)} placeholder="模块、发现或原始文本" /></label>
        <label>结果<select value={filter} onChange={(event) => setFilter(event.target.value as QuickDetectionResultFilter)}>
          <option value="all">全部</option>
          {(["failed", "passed", "not-applicable", "error", "cancelled"] as QuickDetectionOutcome[]).map((outcome) => (
            <option key={outcome} value={outcome}>{quickDetectionOutcomeLabel(outcome)}</option>
          ))}
        </select></label>
      </div>
      <div className="quick-detection-report-workbench">
        <nav aria-label="检测模块结果">
          {visibleModules.map((module) => (
            <button
              type="button"
              key={module.id}
              className={selected?.id === module.id ? "active" : undefined}
              onClick={() => onSelectModule(module.id)}
            >
              <span><strong>{module.label}</strong><em className={module.outcome}>{quickDetectionOutcomeLabel(module.outcome)}</em></span>
              <small>评分 {module.score} · {module.findings.length} 项发现</small>
            </button>
          ))}
          {visibleModules.length === 0 ? <p>没有符合筛选条件的模块。</p> : null}
        </nav>
        <article className="quick-detection-module-detail">
          {selected === null ? <div className="quick-detection-state">选择模块查看结果。</div> : (
            <>
              <header><div><h3>{selected.label}</h3><p>{quickDetectionOutcomeLabel(selected.outcome)} · {selected.durationMs} ms</p></div><strong>{selected.score}</strong></header>
              <section>
                <h4>发现</h4>
                {selected.findings.length === 0 ? <p className="quick-detection-empty">没有结构化发现。</p> : null}
                {selected.findings.map((finding, index) => (
                  <article className={`quick-detection-finding ${finding.severity}`} key={`${finding.title}:${index}`}>
                    <header><strong>{finding.title || "未命名发现"}</strong><span>{quickDetectionSeverityLabel(finding.severity)}</span></header>
                    <p>{finding.description}</p>
                    {finding.recommendation !== null ? <small>建议：{finding.recommendation}</small> : null}
                    {finding.redacted ? <em>敏感字段已替换</em> : null}
                    {finding.textTruncated ? <em>文本已截断</em> : null}
                  </article>
                ))}
                {selected.findingsTruncated ? <p className="quick-detection-truncated">发现列表已按报告边界截断。</p> : null}
              </section>
              <section>
                <h4>原始纯文本</h4>
                <pre>{selected.rawText || "（无原始文本）"}</pre>
                {selected.rawTextRedacted ? <p className="quick-detection-truncated">敏感原始文本已替换。</p> : null}
                {selected.rawTextTruncated ? <p className="quick-detection-truncated">原始文本已截断。</p> : null}
              </section>
            </>
          )}
        </article>
      </div>
    </div>
  );
}

function scanStageLabel(stage: "idle" | "running" | "cancelling" | "completed" | "cancelled" | "failed"): string {
  switch (stage) {
    case "idle": return "尚未启动";
    case "running": return "检测运行中";
    case "cancelling": return "正在取消";
    case "completed": return "检测完成";
    case "cancelled": return "检测已取消";
    case "failed": return "检测失败";
  }
}

function moduleLabel(
  catalog: ReturnType<typeof createQuickDetectionState>["catalog"],
  id: QuickDetectionModuleId,
): string {
  return catalog?.modules.find((module) => module.id === id)?.label ?? id;
}
