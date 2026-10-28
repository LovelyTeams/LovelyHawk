import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";

import type { WindowsRegistrySnapshot, WindowsRegistryValue } from "../shared/windows-incident-contract";
import { CollectionWarnings, ColumnResizer, DataTable, FilterChips, RiskCell, SearchBox, riskChipOptions, riskSort, useFocusRequest, type Column } from "./WinIrKit";
import { WinIrRelated, type RelatedContext } from "./WinIrRelated";
import { REGISTRY_PLACES } from "./win-ir-presets";
export { REGISTRY_PLACES } from "./win-ir-presets";
import { WinIrInspector } from "./WinIrInspector";
import { WinIrTree } from "./WinIrTree";
import { matchesQuery, riskCounts, type RiskFilter } from "./win-ir-helpers";
import { RELATED_ID, commandPath } from "./win-ir-links";
import type { FocusTarget, InvestigationFocus } from "./win-ir-model";

function parentKey(keyPath: string): string | null {
  const trimmed = keyPath.replace(/\\+$/u, "");
  const index = trimmed.lastIndexOf("\\");
  return index > 0 && !trimmed.slice(0, index).endsWith(":") ? trimmed.slice(0, index) : index > 0 ? `${trimmed.slice(0, index)}\\` : null;
}

export interface RegistryBrowserProps {
  snapshot: WindowsRegistrySnapshot | null;
  busy: boolean;
  connected: boolean;
  focus?: InvestigationFocus<Extract<FocusTarget, { tab: "registry" }>> | null;
  related?: RelatedContext;
  onNavigate: (keyPath: string) => void;
  onDeleteValue?: (keyPath: string, value: WindowsRegistryValue) => void;
  onCopy: (text: string) => void;
}

const sameKey = (a: string, b: string) => a.replace(/\\+$/u, "").toLowerCase() === b.replace(/\\+$/u, "").toLowerCase();

/** Registry editor view: key places, subkeys, and the values of the open key. */
export function WinIrRegistry({ snapshot, busy, connected, focus, related, onNavigate, onDeleteValue, onCopy }: RegistryBrowserProps) {
  const [address, setAddress] = useState(snapshot?.keyPath ?? REGISTRY_PLACES[0]!.keyPath);
  const [query, setQuery] = useState("");
  const [placeQuery, setPlaceQuery] = useState("");
  const [leftMode, setLeftMode] = useState<"places" | "tree">("places");
  const addressRef = useRef<HTMLInputElement>(null);
  const [trail, setTrail] = useState<{ items: string[]; index: number }>({ items: [], index: -1 });
  const travelling = useRef<number | null>(null);
  const [risk, setRisk] = useState<RiskFilter>("all");
  const [selected, setSelected] = useState<string | null>(null);
  const [missing, setMissing] = useState(false);
  const [treeWidth, setTreeWidth] = useState(260);
  const keyPath = snapshot?.keyPath ?? null;
  const previousKey = useRef<string | null>(null);
  useEffect(() => {
    if (keyPath === null || keyPath === previousKey.current) return;
    previousKey.current = keyPath;
    setAddress(keyPath);
    setSelected(null); setMissing(false);
    const travelled = travelling.current; travelling.current = null;
    setTrail(({ items, index }) => {
      if (travelled !== null && items[travelled] === keyPath) return { items, index: travelled };
      const next = [...items.slice(0, index + 1), keyPath].slice(-50); return { items: next, index: next.length - 1 };
    });
  }, [keyPath]);
  function travel(index: number) { const target = trail.items[index]; if (target) { travelling.current = index; onNavigate(target); } }
  // Declared after the key reset above so a value chosen by a cross-link survives the same commit.
  useFocusRequest(focus, keyPath !== null && focus !== null && focus !== undefined && sameKey(keyPath, focus.target.keyPath), (target) => {
    setQuery(""); setRisk("all");
    const found = target.valueName === undefined ? undefined : snapshot?.values.find((value) => value.name.toLowerCase() === target.valueName!.toLowerCase());
    setSelected(found?.name ?? null);
    setMissing(target.valueName !== undefined && found === undefined);
  });

  const values = snapshot?.values ?? [];
  const counts = useMemo(() => riskCounts(values, (value) => value.riskLevel), [values]);
  const visible = values.filter((value) => (risk === "all" || value.riskLevel === risk) && matchesQuery(query, value.name, value.data, value.kind));
  const roots = ["HKLM", "HKCU", "HKU", "HKCR", "HKCC"].map((hive) => ({ label: hive, path: `${hive}:\\` }));
  const pieces = keyPath?.replace(/\\+$/u, "").split("\\") ?? [];
  const ancestors = pieces.map((part, i) => ({ label: i === 0 ? part.replace(":", "") : part, path: pieces.slice(0, i + 1).join("\\") + (i === 0 ? "\\" : "") }));
  const selectedValue = values.find((value) => value.name === selected) ?? null;
  const up = keyPath === null ? null : parentKey(keyPath);
  const groups = [...new Set(REGISTRY_PLACES.map((place) => place.group))];

  const columns: Column<WindowsRegistryValue>[] = [
    { key: "name", label: "名称", width: "24%", sort: (value) => value.name, render: (value) => <strong>{value.name || "(默认)"}</strong> },
    { key: "kind", label: "类型", width: "13%", sort: (value) => value.kind, render: (value) => value.kind },
    { key: "data", label: "数据", mono: true, render: (value) => <span className="wir-clip" title={value.data}>{value.data}</span> },
    { key: "risk", label: "风险", width: "90px", sort: riskSort((value) => value.riskLevel), render: (value) => <RiskCell level={value.riskLevel} /> },
  ];

  return (
    <div className="wir-explorer wir-registry-explorer" onKeyDown={(event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "l") { event.preventDefault(); addressRef.current?.focus(); addressRef.current?.select(); }
      if (event.altKey && event.key === "ArrowUp" && up && connected && !busy) { event.preventDefault(); onNavigate(up); }
      if (event.key === "F5" && keyPath && connected && !busy) { event.preventDefault(); onNavigate(keyPath); }
    }}>
      <div className="wir-explorer-bar">
        <div className="wir-nav-buttons">
          <button type="button" className="wir-icon-button" aria-label="后退" disabled={busy || !connected || trail.index <= 0} onClick={() => travel(trail.index - 1)}>←</button>
          <button type="button" className="wir-icon-button" aria-label="前进" disabled={busy || !connected || trail.index >= trail.items.length - 1} onClick={() => travel(trail.index + 1)}>→</button>
          <button type="button" className="wir-icon-button" aria-label="上一级" title="上一级" disabled={busy || !connected || up === null} onClick={() => up && onNavigate(up)}>↑</button>
          <button type="button" className="wir-icon-button" aria-label="刷新" title="刷新" disabled={busy || !connected || keyPath === null} onClick={() => keyPath && onNavigate(keyPath)}>⟳</button>
        </div>
        <form className="wir-address" onSubmit={(event) => { event.preventDefault(); if (connected && !busy && address.trim() !== "") onNavigate(address.trim()); }}>
          <input ref={addressRef} value={address} aria-label="注册表路径" spellCheck={false} placeholder="如 HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" onChange={(event) => setAddress(event.target.value)} />
          <button type="submit" className="win-ir-btn is-primary" disabled={busy || !connected}>转到</button>
        </form>
        <SearchBox value={query} onChange={setQuery} placeholder="筛选当前键的值名称或数据" />
      </div>
      <div className="wir-explorer-body is-resizable" style={{ "--wir-places-width": `${treeWidth}px` } as CSSProperties}>
        <ColumnResizer label="调整注册表键树宽度" width={treeWidth} min={160} max={560} onChange={setTreeWidth} />
        <nav className="wir-places wir-registry-navigation" aria-label="注册表导航">
          <div className="wir-detail-tabs" role="group" aria-label="注册表导航方式"><button type="button" aria-pressed={leftMode === "places"} onClick={() => setLeftMode("places")}>排查位置</button><button type="button" aria-pressed={leftMode === "tree"} onClick={() => setLeftMode("tree")}>完整键树</button></div>
          {leftMode === "places" ? <><SearchBox value={placeQuery} onChange={setPlaceQuery} placeholder="搜索注册表预设" />
            {groups.map((group) => <div key={group} className="wir-places-group"><p>{group}</p>{REGISTRY_PLACES.filter((place) => place.group === group && matchesQuery(placeQuery, place.label, place.keyPath)).map((place) => <button key={place.keyPath} type="button" title={place.keyPath} className={keyPath && sameKey(keyPath, place.keyPath) ? "is-active" : undefined} disabled={busy || !connected} onClick={() => onNavigate(place.keyPath)}>{place.label}</button>)}</div>)}
            <small className="wir-preset-note">{REGISTRY_PLACES.length} 个预设。HKCU 对应采集账户；未返回键或拒绝访问均不能当作安全。</small>
          </> : null}
          <div className={leftMode === "places" ? "wir-current-key-tree" : undefined}><p>{leftMode === "places" ? "当前键与子键" : "已读取的键"}</p>
            <WinIrTree label="注册表键树" roots={leftMode === "places" && keyPath ? [{ label: pieces.at(-1) || keyPath, path: keyPath }] : roots} currentPath={keyPath} ancestors={leftMode === "places" ? [] : ancestors}
              children={(snapshot?.subkeys ?? []).map((name) => ({ label: name, path: `${keyPath?.replace(/\\+$/u, "")}\\${name}` }))} disabled={busy || !connected} onNavigate={onNavigate} />
          </div>
        </nav>
        <section className="wir-explorer-main" aria-label="键值内容">
          <CollectionWarnings source="注册表" warnings={snapshot?.warnings ?? []} />
          <div className="wir-explorer-actions" role="toolbar" aria-label="注册表操作">
            <button type="button" className="win-ir-btn" disabled={!keyPath} onClick={() => keyPath && onCopy(keyPath)}>复制键路径</button>
            <button type="button" className="win-ir-btn" disabled={!selectedValue} onClick={() => selectedValue && onCopy(selectedValue.data)}>复制值数据</button>
            {selectedValue && related && commandPath(selectedValue.data) ? <button type="button" className="win-ir-btn" disabled={busy || !connected} onClick={() => related.onGo({ tab: "files", path: commandPath(selectedValue.data)! })}>在文件排查中打开 ↗</button> : null}
          </div>
          <FilterChips label="按风险筛选" value={risk} onChange={setRisk} options={riskChipOptions(counts)} />
          {missing ? <p className="wir-footnote" role="status">当前键中没有要定位的值，可能已被修改或删除，请刷新键值后再查找。</p> : null}
          <div className="wir-master">
            <DataTable
              label="注册表值"
              columns={columns}
              rows={visible}
              rowKey={(value) => value.name}
              selectedKey={selected}
              onSelect={(value) => setSelected(value?.name ?? null)}
              rowRisk={(value) => value.riskLevel}
              defaultSort={{ key: "risk", descending: true }}
              empty={snapshot === null ? "从左侧选择注册表键，或在地址栏输入注册表路径。" : values.length === 0 ? "本次读取没有返回键值。" : "没有符合筛选条件的值。"}
            />
          </div>
          {selectedValue && snapshot ? <WinIrInspector key={`${snapshot.keyPath}:${selectedValue.name}`} title={`${selectedValue.name || "(默认)"} · ${selectedValue.kind}`} onClose={() => setSelected(null)} tabs={[
            { id: "value", label: "值数据", content: <div className="wir-inspector-split"><div className="wir-value-reader">
              {selectedValue.riskReason ? <p className="wir-context-note">{selectedValue.riskReason}</p> : null}
              <CollectionWarnings source="注册表值" summary="值数据已截断 · 查看说明" warnings={selectedValue.truncated ? ["数据已截断，复制仅包含已返回部分；不能据此判断完整配置。"] : []} />
              <pre className="wir-registry-data">{selectedValue.data || "（空字符串）"}</pre>
              <div className="wir-toolbar"><button type="button" className="win-ir-btn is-primary" onClick={() => onCopy(selectedValue.data)}>复制数据</button>
                {onDeleteValue && selectedValue.name !== "" ? <button type="button" className="win-ir-btn is-danger" disabled={busy || !connected || selectedValue.truncated || (/\\winlogon$/iu.test(snapshot.keyPath) && /^(shell|userinit)$/iu.test(selectedValue.name))} title="删除前另行确认；截断数据和核心登录项不可删除" onClick={() => onDeleteValue(snapshot.keyPath, selectedValue)}>删除键值…</button> : null}
              </div>
            </div><RegistryProperties keyPath={snapshot.keyPath} value={selectedValue} /></div> },
            { id: "properties", label: "属性", content: <RegistryProperties keyPath={snapshot.keyPath} value={selectedValue} /> },
            ...(related ? [{ id: "related", label: "关联线索", content: <WinIrRelated context={related} query={{ paths: [commandPath(selectedValue.data) ?? ""], exclude: RELATED_ID.registry(snapshot.keyPath, selectedValue.name) }} /> }] : []),
          ]} /> : null}
          <footer className="wir-explorer-status">
            <span>{snapshot ? `${snapshot.values.length} 个值 · ${snapshot.subkeys.length} 个子键 · 筛选后 ${visible.length} 个值` : "未打开注册表键"}</span>
            <span className="wir-status-hint">只筛选当前键 · 只读浏览，删除另行确认</span>
          </footer>
        </section>
      </div>
    </div>
  );
}

function RegistryProperties({ keyPath, value }: { keyPath: string; value: WindowsRegistryValue }) {
  return <dl className="wir-reader-fields"><div><dt>所在键</dt><dd>{keyPath}</dd></div><div><dt>值名称</dt><dd>{value.name || "(默认)"}</dd></div><div><dt>数据类型</dt><dd>{value.kind}</dd></div><div><dt>数据范围</dt><dd>{value.truncated ? "已截断" : "本次返回未截断"}</dd></div><div><dt>权限边界</dt><dd>当前采集账户权限；不会自动提权或取得所有权。</dd></div></dl>;
}
