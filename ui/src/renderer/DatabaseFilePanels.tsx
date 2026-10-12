import { useEffect, useMemo, useRef, useState } from "react";

import {
  isConfigVisualDatabaseCatalog,
  type ConfigVisualActivation,
  type ConfigVisualApi,
  type ConfigVisualDatabase,
  type ConfigVisualDatabaseCatalog,
  type ConfigVisualParameter,
  type ConfigVisualReadOnly,
  type ConfigVisualRisk,
  type ConfigVisualSchema,
  type ConfigVisualScope,
  type ConfigVisualSensitivity,
} from "../shared/config-visual-contract";
import { MAX_CONFIG_VISUAL_QUERY_CHARS } from "./config-visual-helpers";

/*
 * The parts of the visual editor that only a catalogued database file has:
 * choosing which file to open, which reviewed version to read it against,
 * and that version's parameters with what each means. Everything here comes
 * from the built-in catalogue and is said to be so; nothing is a check
 * against a server.
 */

export function databaseScopeLabel(scope: ConfigVisualScope): string {
  switch (scope) {
    case "session": return "会话";
    case "instance": return "实例";
    case "component": return "组件";
    case "cluster": return "集群";
    case "global": return "全局";
    case "vendor-defined": return "厂商定义";
  }
}

export function databaseActivationLabel(activation: ConfigVisualActivation): string {
  switch (activation) {
    case "dynamic": return "立即生效";
    case "reload": return "重新加载后生效";
    case "restart": return "重启后生效";
    case "rolling-restart": return "滚动重启后生效";
    case "vendor-procedure": return "按厂商步骤生效";
  }
}

export function databaseRiskLabel(risk: ConfigVisualRisk): string {
  switch (risk) {
    case "informational": return "提示";
    case "low": return "低风险";
    case "medium": return "中风险";
    case "high": return "高风险";
    case "critical": return "严重风险";
  }
}

export function databaseSensitivityLabel(sensitivity: ConfigVisualSensitivity): string {
  switch (sensitivity) {
    case "public": return "公开";
    case "operational-metadata": return "运维信息";
    case "may-contain-secrets": return "可能含秘密，值会被隐藏";
    case "private-key-reference": return "私钥引用，值会被隐藏";
  }
}

export function databaseReadOnlyNotice(readOnly: ConfigVisualReadOnly): string {
  return readOnly === "vendor-schema"
    ? "只读：这个文件要按厂商对应版本的完整说明来改，这里只能查看和另存副本；选择版本也不会解锁修改。"
    : "只读：这个文件由服务器或厂商工具生成，这里只能查看和另存副本，不能修改。";
}

/** A version to read against, as one line: its name, the exact range when the name is short, and its coverage. */
export function schemaOptionText(schema: ConfigVisualSchema): string {
  const range = schema.label.includes(schema.version) ? "" : `（${schema.version}）`;
  return `${schema.label}${range}${schema.complete ? "" : " · 部分参数"}`;
}

/** Whether a parameter's reviewed words contain the query (ASCII letters in any case). */
export function databaseParameterMatches(parameter: ConfigVisualParameter, rawQuery: string): boolean {
  const query = rawQuery.trim();
  if (query === "") return true;
  if ([...query].length > MAX_CONFIG_VISUAL_QUERY_CHARS || /[\u0000-\u001f\u007f-\u009f]/u.test(query)) return false;
  const needle = asciiLower(query);
  const words = [
    ...parameter.searchTerms,
    databaseScopeLabel(parameter.scope),
    databaseActivationLabel(parameter.activation),
    databaseRiskLabel(parameter.risk),
    parameter.valueDomain,
  ];
  return words.some((word) => asciiLower(word).includes(needle));
}

function asciiLower(text: string): string {
  return text.replace(/[A-Z]/gu, (letter) => letter.toLowerCase());
}

/** The catalogued files, by product, to open or import. */
export function DatabaseFilePicker({ api, disabled, artifactKey, onArtifact }: {
  api: ConfigVisualApi;
  disabled: boolean;
  artifactKey: string | null;
  onArtifact(key: string, draftable: boolean): void;
}) {
  const [catalog, setCatalog] = useState<ConfigVisualDatabaseCatalog | null>(null);
  const [failed, setFailed] = useState(false);
  const [product, setProduct] = useState<string>("");

  useEffect(() => {
    let current = true;
    api.configVisual({ action: "database-catalog" })
      .then((value) => {
        if (!current) return;
        if (!isConfigVisualDatabaseCatalog(value)) throw new Error("catalog");
        setCatalog(value);
        const first = value.products[0];
        if (first !== undefined && first.files[0] !== undefined) {
          setProduct(first.product);
          onArtifact(first.files[0].key, first.files[0].readOnly === null);
        }
      })
      .catch(() => { if (current) setFailed(true); });
    return () => { current = false; };
    // The catalogue is fixed for the life of the program: read it once.
  }, [api]);

  if (failed) return <p className="config-visual-hint is-blocking">读不到内置的数据库文件目录，请重新打开这一页。</p>;
  if (catalog === null) return <p className="config-visual-hint">正在读取内置的数据库文件目录…</p>;
  const files = catalog.products.find((entry) => entry.product === product)?.files ?? [];
  return (
    <div className="config-visual-database-picker" data-testid="config-visual-database-picker">
      <label>
        <span>数据库</span>
        <select value={product} disabled={disabled} data-testid="config-visual-database-product"
          onChange={(event) => {
            const next = catalog.products.find((entry) => entry.product === event.target.value);
            setProduct(event.target.value);
            const file = next?.files[0];
            if (file !== undefined) onArtifact(file.key, file.readOnly === null);
          }}>
          {catalog.products.map((entry) => <option key={entry.product} value={entry.product}>{entry.label}</option>)}
        </select>
      </label>
      <label>
        <span>配置文件</span>
        <select value={artifactKey ?? ""} disabled={disabled} data-testid="config-visual-database-file"
          onChange={(event) => {
            const file = files.find((entry) => entry.key === event.target.value);
            if (file !== undefined) onArtifact(file.key, file.readOnly === null);
          }}>
          {files.map((file) => (
            <option key={file.key} value={file.key}>
              {`${file.label}${file.readOnly === null ? "" : "（只读）"}${file.schemas > 0 ? ` · ${file.schemas} 个对照版本` : ""}`}
            </option>
          ))}
        </select>
      </label>
    </div>
  );
}

/** What a parameter is, in words, from the catalogue; never its value in a file. */
export function DatabaseParameterDetail({ parameter, testId }: { parameter: ConfigVisualParameter; testId: string }) {
  return (
    <div className="config-visual-help config-visual-parameter" data-testid={testId} role="note">
      <p><strong>参数</strong><code>{parameter.group === null ? parameter.key : `[${parameter.group}] ${parameter.key}`}</code></p>
      <p><strong>取值</strong>{parameter.valueDomain}</p>
      <p>
        <span><strong>作用范围</strong>{databaseScopeLabel(parameter.scope)}</span>
        <span><strong>生效</strong>{databaseActivationLabel(parameter.activation)}</span>
        <span><strong>风险</strong>{databaseRiskLabel(parameter.risk)}</span>
      </p>
      <p><strong>内容</strong>{databaseSensitivityLabel(parameter.sensitivity)}</p>
      {parameter.documentedDefault !== null ? (
        <p><strong>文档默认值</strong><code>{parameter.documentedDefault === "" ? "（空字符串）" : parameter.documentedDefault}</code></p>
      ) : null}
      {parameter.capability !== null ? <p><strong>需要</strong>{parameter.capability}</p> : null}
      <details>
        <summary>目录里的原文说明</summary>
        <p>{parameter.rationale}</p>
        <p>{parameter.purpose}</p>
        {parameter.reference !== null ? <p>依据：{parameter.reference}</p> : null}
      </details>
      <p className="config-visual-hint">以上来自内置目录，没有核对过任何服务器。</p>
    </div>
  );
}

/**
 * The version a file is read against, and that version's parameters: find
 * one, see what it is, and set its value when the catalogue allows it.
 */
export function DatabaseVersionPanels({ database, working, focusKey = null, onSchema, onSetParameter }: {
  database: ConfigVisualDatabase;
  working: boolean;
  /** A parameter to find and select when the panel first shows this file and version. */
  focusKey?: string | null;
  onSchema(index: number | null): void;
  onSetParameter(index: number, value: string): Promise<boolean>;
}) {
  const focused = focusKey === null ? undefined : database.parameters.find((parameter) => parameter.key === focusKey);
  const [query, setQuery] = useState(focused === undefined ? "" : focused.key);
  const [selected, setSelected] = useState<number | null>(focused?.index ?? null);
  const [value, setValue] = useState("");
  /** The file and version the search and the choice belong to. */
  const shownFor = useRef(`${database.artifactKey}:${database.schemaIndex ?? ""}`);
  const visible = useMemo(
    () => database.parameters.filter((parameter) => databaseParameterMatches(parameter, query)),
    [database.parameters, query],
  );
  const current = selected === null ? null : database.parameters[selected] ?? null;
  // A choice the search hides, or from another version, is dropped.
  useEffect(() => {
    if (selected !== null && !visible.some((parameter) => parameter.index === selected)) setSelected(null);
  }, [selected, visible]);
  useEffect(() => {
    const now = `${database.artifactKey}:${database.schemaIndex ?? ""}`;
    if (shownFor.current === now) return;
    shownFor.current = now;
    setSelected(null);
    setQuery("");
  }, [database.schemaIndex, database.artifactKey]);
  useEffect(() => { setValue(""); }, [selected]);

  return (
    <>
      <section className="config-visual-panel" aria-label="对照的版本" data-testid="config-visual-database">
        <h2>对照的版本</h2>
        <p className="config-visual-hint">{`${database.productLabel} · ${database.fileLabel}`}</p>
        {database.readOnly !== null ? <p className="config-visual-hint is-blocking">{databaseReadOnlyNotice(database.readOnly)}</p> : null}
        {database.schemas.length === 0 ? (
          <p className="config-visual-hint">{database.readOnly !== null
            ? "内置目录还没有这个文件的版本说明，只能按语法查看。"
            : "内置目录还没有这个文件的版本说明，只能按语法查看和修改。"}</p>
        ) : (
          <label className="config-visual-field">
            <span>按哪个版本的目录读这个文件</span>
            <select value={database.schemaIndex ?? ""} disabled={working} data-testid="config-visual-schema"
              onChange={(event) => onSchema(event.target.value === "" ? null : Number(event.target.value))}>
              <option value="">不对照（只按语法显示）</option>
              {database.schemas.map((schema) => (
                <option key={schema.index} value={schema.index}>{schemaOptionText(schema)}</option>
              ))}
            </select>
          </label>
        )}
        <p className="config-visual-hint">选了版本后，目录描述过的项会标出“目录说明”；说明只供参考，没有核对过目标服务器，也不会改动文件。</p>
      </section>
      {database.schemaIndex === null ? null : (
        <section className="config-visual-panel" aria-label="目录里的参数" data-testid="config-visual-parameters">
          <h2>{`目录里的参数（${database.parameters.length}）`}</h2>
          <label className="config-visual-search">
            <span>按名称、作用或风险筛选</span>
            <input type="search" value={query} maxLength={MAX_CONFIG_VISUAL_QUERY_CHARS} data-testid="config-visual-parameter-search"
              placeholder="例如 max_connections、重启、高风险" onChange={(event) => setQuery(event.target.value)} />
          </label>
          {visible.length === 0 ? <p className="config-visual-hint">没有匹配的参数。</p> : (
            <ul className="config-visual-parameter-list">
              {visible.map((parameter) => (
                <li key={parameter.index}>
                  <button type="button" aria-pressed={parameter.index === selected}
                    className={parameter.index === selected ? "is-selected" : undefined}
                    onClick={() => setSelected(parameter.index === selected ? null : parameter.index)}>
                    <span className="config-visual-parameter-key">{parameter.group === null ? parameter.key : `[${parameter.group}] ${parameter.key}`}</span>
                    <span className="config-visual-parameter-facts">
                      {`${parameter.occurrences === 0 ? "文件里没有" : `文件里有 ${parameter.occurrences} 处`} · ${databaseRiskLabel(parameter.risk)}`}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {current === null ? null : (
            <>
              <DatabaseParameterDetail parameter={current} testId="config-visual-parameter-detail" />
              {current.settable && database.readOnly === null ? (
                <form className="config-visual-parameter-set" onSubmit={async (event) => {
                  event.preventDefault();
                  if (await onSetParameter(current.index, value)) setValue("");
                }}>
                  <label className="config-visual-field">
                    <span>{current.occurrences === 0 ? "写入草稿的值（会新加一行）" : "写入草稿的值（会改掉文件里那一行）"}</span>
                    <input value={value} maxLength={4096} spellCheck={false} data-testid="config-visual-parameter-value"
                      placeholder={current.documentedDefault === null || current.documentedDefault === ""
                        ? "按上面的取值范围填写" : `文档默认值 ${current.documentedDefault}`}
                      onChange={(event) => setValue(event.target.value)} />
                  </label>
                  <button type="submit" className="primary" disabled={working || value.trim() === ""}
                    data-testid="config-visual-parameter-apply">写入草稿</button>
                  <p className="config-visual-hint">值先按所选版本的目录检查，写入后再读回核对；只改本地草稿，另存后才是文件。</p>
                </form>
              ) : (
                <p className="config-visual-hint">
                  {database.readOnly !== null ? "这个文件只读，不能写入。"
                    : current.sensitivity !== "public" ? "这个参数可能含秘密，不在这里填写；需要时请在左边的树里自己添加。"
                    : current.capability !== null ? "这个参数要先确认目标具备上面列出的能力，不在这里直接写入。"
                    : "这个参数不能从这里写入，请在左边的树里自己添加。"}
                </p>
              )}
            </>
          )}
        </section>
      )}
    </>
  );
}
