import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";

import type { WindowsRegistrySnapshot, WindowsRegistryValue } from "../shared/windows-incident-contract";
import { CollectionWarnings, ColumnResizer, DataTable, DetailPane, FilterChips, RiskBadge, RiskCell, SearchBox, riskChipOptions, riskSort, useFocusRequest, type Column } from "./WinIrKit";
import { WinIrRelated, type RelatedContext } from "./WinIrRelated";
import { WinIrTree } from "./WinIrTree";
import { matchesQuery, riskCounts, type RiskFilter } from "./win-ir-helpers";
import { RELATED_ID, commandPath } from "./win-ir-links";
import type { FocusTarget, InvestigationFocus } from "./win-ir-model";

export const REGISTRY_PLACES: ReadonlyArray<{ group: string; label: string; keyPath: string }> = [
  { group: "自启动", label: "本机 Run", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
  { group: "自启动", label: "本机 RunOnce", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
  { group: "自启动", label: "当前用户 Run", keyPath: "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
  { group: "自启动", label: "32 位 Run (WOW6432Node)", keyPath: "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
  { group: "劫持", label: "登录外壳 (Winlogon)", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
  { group: "劫持", label: "映像劫持 (IFEO)", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" },
  { group: "劫持", label: "AppInit_DLLs", keyPath: "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" },
  { group: "服务", label: "服务列表", keyPath: "HKLM:\\SYSTEM\\CurrentControlSet\\Services" },
  { group: "凭据", label: "WDigest", keyPath: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" },
  { group: "凭据", label: "LSA", keyPath: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa" },
  { group: "远程访问", label: "远程桌面 (RDP-Tcp)", keyPath: "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" },
  { group: "痕迹", label: "最近运行 (RunMRU)", keyPath: "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU" },
  { group: "痕迹", label: "地址栏输入 (TypedPaths)", keyPath: "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths" },
  { group: "痕迹", label: "远程桌面连接历史", keyPath: "HKCU:\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers" },
];

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
    setSelected(null);
  }, [keyPath]);
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
    <div className="wir-explorer">
      <div className="wir-explorer-bar">
        <div className="wir-nav-buttons">
          <button type="button" className="wir-icon-button" aria-label="上一级" title="上一级" disabled={busy || !connected || up === null} onClick={() => up && onNavigate(up)}>↑</button>
          <button type="button" className="wir-icon-button" aria-label="刷新" title="刷新" disabled={busy || !connected || keyPath === null} onClick={() => keyPath && onNavigate(keyPath)}>⟳</button>
        </div>
        <form className="wir-address" onSubmit={(event) => { event.preventDefault(); if (connected && !busy && address.trim() !== "") onNavigate(address.trim()); }}>
          <input value={address} aria-label="注册表路径" spellCheck={false} placeholder="如 HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" onChange={(event) => setAddress(event.target.value)} />
          <button type="submit" className="win-ir-btn is-primary" disabled={busy || !connected}>转到</button>
        </form>
        <SearchBox value={query} onChange={setQuery} placeholder="筛选子键、值名称或数据" />
      </div>
      <div className={`wir-explorer-body wir-registry-body is-resizable${selectedValue ? " has-detail" : ""}`} style={{ "--wir-places-width": `${treeWidth}px` } as CSSProperties}>
        <ColumnResizer label="调整注册表键树宽度" width={treeWidth} min={160} max={560} onChange={setTreeWidth} />
        <WinIrTree label="注册表键树" roots={roots} currentPath={keyPath} ancestors={ancestors}
          children={(snapshot?.subkeys ?? []).map((name) => ({ label: name, path: `${keyPath?.replace(/\\+$/u, "")}\\${name}` }))}
          disabled={busy || !connected} onNavigate={onNavigate} />
        <section className="wir-explorer-main" aria-label="键值内容">
          <CollectionWarnings warnings={snapshot?.warnings ?? []} />
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
              empty={snapshot === null ? "从左侧选择注册表键，或从右侧选择应急常用位置，或在地址栏输入注册表路径。" : values.length === 0 ? "本次读取没有返回键值。" : "没有符合筛选条件的值。"}
            />
          </div>
          <footer className="wir-explorer-status">
            <span>{snapshot ? `${snapshot.values.length} 个值 · ${snapshot.subkeys.length} 个子键` : "未打开注册表键"}</span>
            <span className="wir-status-hint">只读浏览，不修改注册表</span>
          </footer>
        </section>
        {selectedValue ? <div className="wir-registry-side">
          <DetailPane
            title={selectedValue.name || "(默认)"}
            subtitle={selectedValue.kind}
            risk={selectedValue.riskLevel}
            reasons={selectedValue.riskReason ? [selectedValue.riskReason] : []}
            onClose={() => setSelected(null)}
            onCopy={onCopy}
            fields={[
              { label: "所在键", value: snapshot?.keyPath ?? "", mono: true },
              { label: selectedValue.truncated ? "数据（已截断）" : "数据", value: selectedValue.data || "（空字符串）", mono: true },
            ]}
            actions={<>
              <button type="button" className="win-ir-btn" onClick={() => onCopy(selectedValue.data)}>复制数据</button>
              {onDeleteValue && snapshot && selectedValue.name !== "" ? (
                <button
                  type="button"
                  className="win-ir-btn is-danger"
                  disabled={busy || !connected || (/\\winlogon$/iu.test(snapshot.keyPath) && /^(shell|userinit)$/iu.test(selectedValue.name))}
                  title={/\\winlogon$/iu.test(snapshot.keyPath) && /^(shell|userinit)$/iu.test(selectedValue.name) ? "Winlogon 核心登录项不能直接删除，以免无法登录" : undefined}
                  onClick={() => onDeleteValue(snapshot.keyPath, selectedValue)}
                >
                  删除键值
                </button>
              ) : null}
            </>}
          >
            {related && snapshot ? <WinIrRelated key={`${snapshot.keyPath}:${selectedValue.name}`} context={related} query={{ paths: [commandPath(selectedValue.data) ?? ""], exclude: RELATED_ID.registry(snapshot.keyPath, selectedValue.name) }} /> : null}
          </DetailPane>
        </div> : <nav className="wir-places wir-registry-shortcuts" aria-label="应急常用位置">
          {groups.map((group) => (
            <div key={group} className="wir-places-group">
              <p>{group}</p>
              {REGISTRY_PLACES.filter((place) => place.group === group).map((place) => (
                <button
                  key={place.keyPath}
                  type="button"
                  title={place.keyPath}
                  className={keyPath !== null && keyPath.toLowerCase() === place.keyPath.toLowerCase() ? "is-active" : undefined}
                  disabled={busy || !connected}
                  onClick={() => onNavigate(place.keyPath)}
                >
                  <span>{place.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>}
      </div>
    </div>
  );
}
