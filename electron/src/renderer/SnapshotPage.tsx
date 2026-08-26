import { useEffect, useReducer, useRef, useState } from "react";

import { targetFailureMessage } from "./target-lost";

import {
  forensicCollectors,
  isSnapshotDetail,
  isSnapshotDiffResult,
  isSnapshotListResult,
  type ForensicCollector,
  type ForensicSnapshotDetail,
  type SnapshotDetail,
  type SnapshotDiffResult,
  type SnapshotListItem,
  type SnapshotListResult,
  type SnapshotReadApi,
} from "../shared/snapshot-read-contract";
import {
  displaySnapshotBytes,
  filterDiffField,
  filterDirectoryItems,
  filterPlainText,
  filterSnapshotList,
  forensicCollectorLabel,
  isChronologicalDiff,
  snapshotPresetLabel,
  snapshotScope,
} from "./snapshot-read-helpers";
import {
  createSnapshotReadState,
  snapshotReadReducer,
  type SnapshotLoadStatus,
  type SnapshotTab,
} from "./snapshot-read-state";
import "./snapshot-page.css";

export interface SnapshotPageProps {
  bindingHandle: string | null;
  api: SnapshotReadApi;
}

const tabs: readonly SnapshotTab[] = ["directory", "forensic", "diff"];

export function SnapshotPage({ bindingHandle, api }: SnapshotPageProps) {
  const [state, dispatch] = useReducer(snapshotReadReducer, undefined, createSnapshotReadState);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [diffVersion, setDiffVersion] = useState(0);
  const requestRef = useRef(0);
  const consumedDiffVersion = useRef(0);
  const scope = bindingHandle === null ? null : snapshotScope(bindingHandle);

  useEffect(() => {
    dispatch({ type: "scope-changed", scope });
  }, [scope]);

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope) return;
    const request = ++requestRef.current;
    let cancelled = false;
    dispatch({ type: "list-started", scope, request });
    void api.listSnapshots(bindingHandle).then((result) => {
      if (cancelled) return;
      if (!isSnapshotListResult(result)) throw new Error();
      dispatch({ type: "list-loaded", scope, request, list: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "list-failed",
        scope,
        request,
        error: targetFailureMessage(reason, "快照索引不可用、目标已变化或当前绑定已失效。"),
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, refreshVersion, scope, state.scope]);

  const selectedHandle = state.tab === "directory"
    ? state.selectedDirectoryHandle
    : state.tab === "forensic" ? state.selectedForensicHandle : null;

  useEffect(() => {
    if (scope === null || bindingHandle === null || state.scope !== scope || selectedHandle === null ||
      state.list === null || state.tab === "diff") return;
    const request = { id: ++requestRef.current, snapshotHandle: selectedHandle };
    let cancelled = false;
    dispatch({ type: "detail-started", scope, request });
    void api.getSnapshotDetail(bindingHandle, selectedHandle).then((result) => {
      if (cancelled) return;
      if (!isSnapshotDetail(result) || result.snapshotHandle !== selectedHandle || result.kind !== state.tab) {
        throw new Error();
      }
      dispatch({ type: "detail-loaded", scope, request, detail: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "detail-failed",
        scope,
        request,
        error: "快照详情不可用；能力可能已过期或记录已变化。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [api, bindingHandle, scope, selectedHandle, state.list, state.scope, state.tab]);

  useEffect(() => {
    if (diffVersion === 0 || consumedDiffVersion.current === diffVersion || scope === null ||
      bindingHandle === null || state.scope !== scope || state.tab !== "diff" || state.list === null ||
      !isChronologicalDiff(state.list.snapshots, state.olderSnapshotHandle, state.newerSnapshotHandle)) return;
    consumedDiffVersion.current = diffVersion;
    const request = {
      id: ++requestRef.current,
      olderSnapshotHandle: state.olderSnapshotHandle!,
      newerSnapshotHandle: state.newerSnapshotHandle!,
    };
    let cancelled = false;
    dispatch({ type: "diff-started", scope, request });
    void api.diffForensicSnapshots(bindingHandle, {
      olderSnapshotHandle: request.olderSnapshotHandle,
      newerSnapshotHandle: request.newerSnapshotHandle,
    }).then((result) => {
      if (cancelled) return;
      if (!isSnapshotDiffResult(result) || result.olderSnapshotHandle !== request.olderSnapshotHandle ||
        result.newerSnapshotHandle !== request.newerSnapshotHandle) throw new Error();
      dispatch({ type: "diff-loaded", scope, request, diff: result });
    }).catch((reason: unknown) => {
      if (!cancelled) dispatch({
        type: "diff-failed",
        scope,
        request,
        error: "无法比较这两份取证快照；能力可能已过期或记录已变化。",
      });
    });
    return () => {
      cancelled = true;
    };
  }, [
    api,
    bindingHandle,
    diffVersion,
    scope,
    state.list,
    state.newerSnapshotHandle,
    state.olderSnapshotHandle,
    state.scope,
    state.tab,
  ]);

  if (bindingHandle === null) {
    return (
      <main className="snapshot-page snapshot-disconnected">
        <h1>快照调查</h1>
        <p>连接 SSH 目标后，可只读查看本地索引中的目录与取证快照。</p>
      </main>
    );
  }

  const current = state.scope === scope;
  return (
    <main className="snapshot-page">
      <header className="snapshot-header">
        <div>
          <p className="snapshot-kicker">只读</p>
          <h1>快照调查</h1>
          <p>目录记录来自便携索引；本页不会检查远端归档当前是否存在或仍然匹配。</p>
        </div>
        <button type="button" disabled={!current || state.listStatus === "loading"}
          onClick={() => setRefreshVersion((value) => value + 1)}>
          {state.listStatus === "loading" ? "刷新中…" : "刷新索引"}
        </button>
      </header>
      <p className="snapshot-readonly-banner">
        只读展示快照元数据、取证文本与差异；不会修改任何快照。
      </p>
      {!current || state.listStatus === "loading" && state.list === null ? (
        <SnapshotStatusPanel label="正在读取快照索引…" />
      ) : state.listStatus === "error" ? (
        <SnapshotErrorPanel message={state.listError ?? "快照索引不可用。"} />
      ) : state.list === null ? (
        <SnapshotEmptyPanel title="快照索引不可用" detail="手动刷新索引后重试。" />
      ) : (
        <>
          <div className="snapshot-toolbar">
            <nav className="snapshot-tabs" aria-label="快照调查视图">
              {tabs.map((tab) => <button key={tab} type="button" className={state.tab === tab ? "is-active" : ""}
                aria-current={state.tab === tab ? "page" : undefined}
                onClick={() => dispatch({ type: "tab-selected", tab })}>{snapshotTabLabel(tab)}</button>)}
            </nav>
            <label className="snapshot-search">搜索
              <input value={state.search} maxLength={256} onChange={(event) => dispatch({
                type: "search-changed", value: event.currentTarget.value,
              })} />
            </label>
            <span>能力约 {Math.max(1, Math.ceil(state.list.expiresInSeconds / 60))} 分钟有效</span>
          </div>
          {state.list.truncated && <p className="snapshot-warning" role="status">索引超过上限，当前结果已截断。</p>}
          {state.tab === "directory" && <SnapshotDirectoryView
            list={state.list}
            selectedHandle={state.selectedDirectoryHandle}
            detailStatus={state.detailStatus}
            detail={state.detail}
            detailError={state.detailError}
            search={state.search}
            onSelect={(snapshotHandle) => dispatch({ type: "snapshot-selected", kind: "directory", snapshotHandle })}
          />}
          {state.tab === "forensic" && <SnapshotForensicView
            list={state.list}
            selectedHandle={state.selectedForensicHandle}
            detailStatus={state.detailStatus}
            detail={state.detail}
            detailError={state.detailError}
            collector={state.collector}
            search={state.search}
            onSelect={(snapshotHandle) => dispatch({ type: "snapshot-selected", kind: "forensic", snapshotHandle })}
            onCollector={(collector) => dispatch({ type: "collector-selected", collector })}
          />}
          {state.tab === "diff" && <SnapshotDiffView
            list={state.list}
            status={state.diffStatus}
            result={state.diff}
            error={state.diffError}
            olderHandle={state.olderSnapshotHandle}
            newerHandle={state.newerSnapshotHandle}
            collector={state.collector}
            search={state.search}
            onOlder={(snapshotHandle) => dispatch({ type: "diff-selection", side: "older", snapshotHandle })}
            onNewer={(snapshotHandle) => dispatch({ type: "diff-selection", side: "newer", snapshotHandle })}
            onCollector={(collector) => dispatch({ type: "collector-selected", collector })}
            onCompare={() => setDiffVersion((value) => value + 1)}
          />}
        </>
      )}
    </main>
  );
}

export function SnapshotDirectoryView({ list, selectedHandle, detailStatus, detail, detailError, search, onSelect }: {
  list: SnapshotListResult;
  selectedHandle: string | null;
  detailStatus: SnapshotLoadStatus;
  detail: SnapshotDetail | null;
  detailError: string | null;
  search: string;
  onSelect: (snapshotHandle: string) => void;
}) {
  const snapshots = filterSnapshotList(list.snapshots, "directory", "");
  const items = detail === null ? [] : filterDirectoryItems(detail, search);
  return (
    <section className="snapshot-split" aria-label="目录快照">
      <aside className="snapshot-list">
        {snapshots.length === 0 ? <SnapshotEmptyPanel title="没有目录快照" detail="当前筛选没有可显示记录。" compact /> :
          snapshots.map((snapshot) => <SnapshotListButton key={snapshot.snapshotHandle} snapshot={snapshot}
            selected={snapshot.snapshotHandle === selectedHandle} onSelect={onSelect} />)}
      </aside>
      <div className="snapshot-detail">
        {selectedHandle === null ? <SnapshotEmptyPanel title="没有目录快照" detail="便携索引中没有目录记录。" /> :
          detailStatus === "loading" ? <SnapshotStatusPanel label="正在读取目录快照安全元数据…" /> :
            detailStatus === "error" ? <SnapshotErrorPanel message={detailError ?? "目录详情不可用。"} /> :
              detail?.kind !== "directory" ? <SnapshotEmptyPanel title="选择目录快照" detail="从左侧选择一条记录。" /> : (
                <>
                  <div className="snapshot-detail-heading">
                    <div><h2>目录归档内容</h2><time>{detail.capturedAt}</time></div>
                    <span className="snapshot-unverified">远端归档：未检查</span>
                  </div>
                  <p className="snapshot-index-note">这里只证明便携索引记录可读，不代表远端归档当前存在、不可变或已重新验证。</p>
                  {detail.truncated && <p className="snapshot-warning">详情已截断。</p>}
                  {items.length === 0 ? <SnapshotEmptyPanel title="没有匹配项目" detail="调整搜索条件后重试。" compact /> :
                    <div className="snapshot-directory-items">{items.map((item) => (
                      <article key={item.preset}>
                        <div><h3>{snapshotPresetLabel(item.preset)}</h3><span>{item.kind}</span></div>
                        <p>{displaySnapshotBytes(item.bytes)} · {item.present ? "采集时存在" : "采集时缺失"}</p>
                        <small>远端归档状态未检查</small>
                      </article>
                    ))}</div>}
                </>
              )}
      </div>
    </section>
  );
}

export function SnapshotForensicView({ list, selectedHandle, detailStatus, detail, detailError, collector, search,
  onSelect, onCollector }: {
  list: SnapshotListResult;
  selectedHandle: string | null;
  detailStatus: SnapshotLoadStatus;
  detail: SnapshotDetail | null;
  detailError: string | null;
  collector: ForensicCollector;
  search: string;
  onSelect: (snapshotHandle: string) => void;
  onCollector: (collector: ForensicCollector) => void;
}) {
  const snapshots = filterSnapshotList(list.snapshots, "forensic", "");
  const forensic = detail?.kind === "forensic" ? detail : null;
  const field = forensic?.fields.find((item) => item.collector === collector) ?? null;
  const text = field === null ? "" : filterPlainText(field.text, search);
  return (
    <section className="snapshot-split" aria-label="取证快照">
      <aside className="snapshot-list">
        {snapshots.length === 0 ? <SnapshotEmptyPanel title="没有取证快照" detail="便携索引中没有取证记录。" compact /> :
          snapshots.map((snapshot) => <SnapshotListButton key={snapshot.snapshotHandle} snapshot={snapshot}
            selected={snapshot.snapshotHandle === selectedHandle} onSelect={onSelect} />)}
      </aside>
      <div className="snapshot-detail">
        {selectedHandle === null ? <SnapshotEmptyPanel title="没有取证快照" detail="便携索引中没有取证记录。" /> :
          detailStatus === "loading" ? <SnapshotStatusPanel label="正在读取并遮蔽取证字段…" /> :
            detailStatus === "error" ? <SnapshotErrorPanel message={detailError ?? "取证详情不可用。"} /> :
              forensic === null ? <SnapshotEmptyPanel title="选择取证快照" detail="从左侧选择一条记录。" /> :
                <ForensicDetailContent detail={forensic} fieldText={text} collector={collector}
                  field={field} onCollector={onCollector} search={search} />}
      </div>
    </section>
  );
}

export function ForensicDetailContent({ detail, field, fieldText, collector, onCollector, search }: {
  detail: ForensicSnapshotDetail;
  field: ForensicSnapshotDetail["fields"][number] | null;
  fieldText: string;
  collector: ForensicCollector;
  onCollector: (collector: ForensicCollector) => void;
  search: string;
}) {
  return (
    <>
      <div className="snapshot-detail-heading">
        <div><h2>取证字段</h2><time>{detail.capturedAt}</time></div>
        <span>{detail.completedCollectors}/{detail.totalCollectors} 完成 · {detail.failedCollectors} 失败</span>
      </div>
      <CollectorSelect collector={collector} onCollector={onCollector} />
      {(detail.truncated || field?.truncated) && <p className="snapshot-warning">取证文本已按行数或字节上限截断。</p>}
      {detail.redactedLineCount > 0 && <p className="snapshot-redacted">已遮蔽 {detail.redactedLineCount} 行敏感内容。</p>}
      {fieldText.length === 0 ? <SnapshotEmptyPanel title={search.trim() === "" ? "字段为空" : "没有匹配行"}
        detail={search.trim() === "" ? "该 collector 没有可显示文本。" : "调整搜索条件后重试。"} compact /> :
        <pre className="snapshot-forensic-text">{fieldText}</pre>}
    </>
  );
}

export function SnapshotDiffView({ list, status, result, error, olderHandle, newerHandle, collector, search,
  onOlder, onNewer, onCollector, onCompare }: {
  list: SnapshotListResult;
  status: SnapshotLoadStatus;
  result: SnapshotDiffResult | null;
  error: string | null;
  olderHandle: string | null;
  newerHandle: string | null;
  collector: ForensicCollector;
  search: string;
  onOlder: (snapshotHandle: string) => void;
  onNewer: (snapshotHandle: string) => void;
  onCollector: (collector: ForensicCollector) => void;
  onCompare: () => void;
}) {
  const forensic = list.snapshots.filter((snapshot) => snapshot.kind === "forensic");
  const validPair = isChronologicalDiff(list.snapshots, olderHandle, newerHandle);
  const field = result?.fields.find((item) => item.collector === collector) ?? null;
  const filtered = field === null ? null : filterDiffField(field, search);
  return (
    <section className="snapshot-diff">
      {forensic.length < 2 ? <SnapshotEmptyPanel title="至少需要两份取证快照"
        detail="当前便携索引不足以计算差异。" /> : (
          <>
            <div className="snapshot-diff-controls">
              <label>较早快照<select value={olderHandle ?? ""} onChange={(event) => onOlder(event.currentTarget.value)}>
                {forensic.map((snapshot) => <option key={snapshot.snapshotHandle} value={snapshot.snapshotHandle}>
                  {snapshot.capturedAt}
                </option>)}
              </select></label>
              <label>较新快照<select value={newerHandle ?? ""} onChange={(event) => onNewer(event.currentTarget.value)}>
                {forensic.map((snapshot) => <option key={snapshot.snapshotHandle} value={snapshot.snapshotHandle}>
                  {snapshot.capturedAt}
                </option>)}
              </select></label>
              <CollectorSelect collector={collector} onCollector={onCollector} />
              <button type="button" disabled={!validPair || status === "loading"} onClick={onCompare}>
                {status === "loading" ? "比较中…" : "比较取证字段"}
              </button>
            </div>
            {!validPair && <p className="snapshot-warning">较早快照必须严格早于较新快照。</p>}
            {status === "loading" ? <SnapshotStatusPanel label="正在计算差异…" /> :
              status === "error" ? <SnapshotErrorPanel message={error ?? "快照差异不可用。"} /> :
                result === null ? <SnapshotEmptyPanel title="尚未计算差异" detail="选择有效时间顺序后执行比较。" /> :
                  <SnapshotDiffContent result={result} field={filtered} collector={collector} search={search} />}
          </>)}
    </section>
  );
}

export function SnapshotDiffContent({ result, field, collector, search }: {
  result: SnapshotDiffResult;
  field: SnapshotDiffResult["fields"][number] | null;
  collector: ForensicCollector;
  search: string;
}) {
  if (field === null || field.added.length + field.removed.length === 0) {
    return <SnapshotEmptyPanel title={search.trim() === "" ? "此字段没有差异" : "没有匹配差异"}
      detail={`${forensicCollectorLabel(collector)} 未发现可显示的新增或删除行。`} />;
  }
  return (
    <div className="snapshot-diff-result">
      <div className="snapshot-detail-heading">
        <h2>{forensicCollectorLabel(collector)} 差异</h2>
        <span>全部字段：新增 {result.addedLineCount} · 删除 {result.removedLineCount}</span>
      </div>
      {result.truncated && <p className="snapshot-warning">差异已按行数或字节上限截断。</p>}
      {result.redactedLineCount > 0 && <p className="snapshot-redacted">已遮蔽 {result.redactedLineCount} 行敏感差异。</p>}
      <div className="snapshot-diff-lines">
        {field.added.map((line, index) => <pre key={`a-${index}`} className="is-added">+ {line}</pre>)}
        {field.removed.map((line, index) => <pre key={`r-${index}`} className="is-removed">- {line}</pre>)}
      </div>
    </div>
  );
}

function SnapshotListButton({ snapshot, selected, onSelect }: {
  snapshot: SnapshotListItem;
  selected: boolean;
  onSelect: (snapshotHandle: string) => void;
}) {
  return <button type="button" className={selected ? "snapshot-list-item is-selected" : "snapshot-list-item"}
    onClick={() => onSelect(snapshot.snapshotHandle)}>
    <strong>{snapshot.kind === "directory" ? `${snapshot.itemCount} 项目录归档` : "12 项主机取证"}</strong>
    <time>{snapshot.capturedAt}</time>
    {snapshot.kind === "forensic" && <small>{snapshot.completedCollectors}/12 完成 · {snapshot.failedCollectors} 失败</small>}
  </button>;
}

function CollectorSelect({ collector, onCollector }: {
  collector: ForensicCollector;
  onCollector: (collector: ForensicCollector) => void;
}) {
  return <label className="snapshot-collector">Collector
    <select value={collector} onChange={(event) => onCollector(event.currentTarget.value as ForensicCollector)}>
      {forensicCollectors.map((item) => <option key={item} value={item}>{forensicCollectorLabel(item)}</option>)}
    </select>
  </label>;
}

function snapshotTabLabel(tab: SnapshotTab): string {
  switch (tab) {
    case "directory": return "目录";
    case "forensic": return "取证";
    case "diff": return "差异";
  }
}

export function SnapshotStatusPanel({ label }: { label: string }) {
  return <div className="snapshot-status" aria-live="polite"><span aria-hidden="true" />{label}</div>;
}

export function SnapshotErrorPanel({ message }: { message: string }) {
  return <div className="snapshot-error" role="alert"><strong>读取失败</strong><p>{message}</p></div>;
}

export function SnapshotEmptyPanel({ title, detail, compact = false }: {
  title: string;
  detail: string;
  compact?: boolean;
}) {
  return <div className={compact ? "snapshot-empty is-compact" : "snapshot-empty"}><strong>{title}</strong><p>{detail}</p></div>;
}
