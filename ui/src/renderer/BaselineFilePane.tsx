import { useCallback, useEffect, useRef, useState } from "react";

import {
  isBaselineFile,
  type BaselineCatalogItem,
  type BaselineFile,
  type BaselineReadApi,
  type BaselineStatus,
} from "../shared/baseline-read-contract";
import { baselineCandidateScope } from "./baseline-read-helpers";

export type BaselineFileStatus = "idle" | "loading" | "ready" | "error";

/**
 * Reads the configuration file behind one check, and keeps it only while that
 * check is the one being looked at.
 *
 * The check is named by the handle the catalogue handed out; the file it lives
 * in is decided inside the core. A late reply for a check the operator has
 * already moved on from is dropped rather than drawn over the new one.
 */
export function useBaselineFile(api: BaselineReadApi, bindingHandle: string | null) {
  const [file, setFile] = useState<BaselineFile | null>(null);
  const [status, setStatus] = useState<BaselineFileStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const sequence = useRef(0);
  const currentScope = useRef({ api, bindingHandle, active: true });
  if (currentScope.current.api !== api || currentScope.current.bindingHandle !== bindingHandle) {
    currentScope.current = { api, bindingHandle, active: true };
  }
  const scope = currentScope.current;

  const open = useCallback(async (itemHandle: string | null) => {
    if (currentScope.current !== scope || !scope.active) return;
    const request = ++sequence.current;
    const ownsRequest = () => currentScope.current === scope && scope.active && sequence.current === request;
    if (itemHandle === null || bindingHandle === null) {
      setFile(null);
      setStatus("idle");
      setError(null);
      return;
    }
    setStatus("loading");
    setError(null);
    setFile(null);
    try {
      const value = await api.readBaselineFile(bindingHandle, itemHandle);
      if (!ownsRequest()) return;
      if (!isBaselineFile(value) || value.itemHandle !== itemHandle) {
        throw new Error("目标机返回的配置文件无法识别。");
      }
      setFile(value);
      setStatus("ready");
    } catch (cause) {
      if (!ownsRequest()) return;
      setFile(null);
      setStatus("error");
      setError(cause instanceof Error && cause.message.length > 0
        ? cause.message
        : "读取配置文件失败。");
    }
  }, [api, bindingHandle, scope]);

  // A different target means the previous file is about a machine nobody is
  // looking at any more.
  useEffect(() => {
    scope.active = true;
    setFile(null);
    setStatus("idle");
    setError(null);
    return () => {
      scope.active = false;
      if (currentScope.current === scope) sequence.current++;
    };
  }, [scope]);

  return { file, status, error, open };
}

export interface BaselineFilePaneProps {
  item: BaselineCatalogItem | null;
  status: BaselineStatus | null;
  file: BaselineFile | null;
  fileStatus: BaselineFileStatus;
  error: string | null;
  connected: boolean;
  onReload: () => void;
}

/**
 * The configuration file the selected check reads, with the line it reads
 * marked.
 *
 * A status of "不合规" is an assertion, and this is where the operator gets to
 * see the line it was made from. Lines that name the same setting but are
 * commented out are marked differently, because they set nothing — which is the
 * mistake the check itself used to make.
 */
export function BaselineFilePane({
  item,
  status,
  file,
  fileStatus,
  error,
  connected,
  onReload,
}: BaselineFilePaneProps) {
  const effectiveRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    effectiveRef.current?.scrollIntoView({ block: "center" });
  }, [file]);

  if (item === null) {
    return (
      <aside className="baseline-file-pane" aria-label="配置文件">
        <div className="baseline-file-empty">
          <span aria-hidden="true">{"</>"}</span>
          <h2>选择左侧的一项</h2>
          <p>右边会显示这项检查读的那个配置文件，并标出它读的是哪一行。</p>
        </div>
      </aside>
    );
  }

  return (
    <aside className="baseline-file-pane" aria-label="配置文件">
      <header>
        <div>
          <p className="baseline-file-path" title={file?.path ?? ""}>{file?.path ?? "…"}</p>
          <h2>{item.title}</h2>
        </div>
        <button type="button" disabled={!connected || fileStatus === "loading"} onClick={onReload}>
          {fileStatus === "loading" ? "读取中…" : "重新读取"}
        </button>
      </header>

      <dl className="baseline-file-facts">
        <div><dt>这项检查读的设置</dt><dd><code>{file?.key ?? "—"}</code></dd></div>
        <div><dt>建议值</dt><dd><code>{item.recommendation}</code></dd></div>
        <div><dt>{baselineCandidateScope(item.component) === null ? "目标机上的值" : "候选文件中的观察"}</dt><dd><code>{status?.observed ?? "尚未扫描"}</code></dd></div>
      </dl>

      {/* Whether the recommendation is right for this machine is the
          operator's call. What the tool owes them either way is the change
          itself: which file on this target, which lines, and what makes it
          take effect. */}
      {status !== null && (
        <section className="baseline-fix" aria-label="怎么改">
          <header>
            <strong>怎么改</strong>
            <code title={status.fix.file}>{status.fix.file}</code>
          </header>
          <pre>{status.fix.lines.join("\n")}</pre>
          {status.fix.reload !== null && (
            <p className="baseline-fix-reload">改完执行：<code>{status.fix.reload}</code></p>
          )}
          {status.fix.manualReason !== null && (
            <p className="baseline-fix-manual">{status.fix.manualReason}</p>
          )}
        </section>
      )}

      {!connected ? (
        <p className="baseline-file-note" role="status">连接目标后才能读取它的配置文件。</p>
      ) : fileStatus === "error" ? (
        <p className="baseline-file-error" role="alert">{error ?? "读取配置文件失败。"}</p>
      ) : fileStatus === "loading" && file === null ? (
        <p className="baseline-file-note" role="status">正在读取目标机上的这个文件…</p>
      ) : file === null ? (
        <p className="baseline-file-note" role="status">点上面的重新读取，看这台机器上的实际内容。</p>
      ) : !file.exists ? (
        <p className="baseline-file-note" role="status">
          这个路径没有可读取的普通文件；设置仍可能来自其他文件、启动参数或程序默认值。
        </p>
      ) : (
        <BaselineFileText file={file} effectiveRef={effectiveRef} scopeMessage={baselineCandidateScope(item.component)} />
      )}

      {file?.truncated === true && (
        <p className="baseline-file-note">文件太长，已按行数或大小上限截断；未显示的部分不代表没有设置。</p>
      )}
    </aside>
  );
}

function BaselineFileText({
  file,
  effectiveRef,
  scopeMessage,
}: {
  file: BaselineFile;
  effectiveRef: React.RefObject<HTMLSpanElement | null>;
  scopeMessage: string | null;
}) {
  const scoped = scopeMessage !== null;
  const lines = file.text.length === 0 ? [] : file.text.split("\n");
  const marks = new Map(file.mentions.map((mention) => [mention.line, mention]));
  const effective = file.mentions.find((mention) => mention.effective) ?? null;
  return (
    <>
      <p className="baseline-file-verdict">
        {scoped ? `这里只展示候选配置，不能将某一行认定为唯一生效项。${scopeMessage}` : effective === null
          ? file.mentions.length === 0
            ? `文件里没有写 ${file.key}，所以用的是程序自己的默认值。`
            : `${file.key} 只出现在注释里，注释不生效，用的还是默认值。`
          : `第 ${effective.line + 1} 行是真正生效的那条${
            file.mentions.length > 1 ? `，另外 ${file.mentions.length - 1} 处不生效` : ""
          }。`}
      </p>
      <div className="baseline-file-text">
        <span className="baseline-file-gutter" aria-hidden="true">
          {lines.map((_line, index) => (
            <span key={index} className={markClass(marks.get(index), scoped)}>{index + 1}</span>
          ))}
        </span>
        <pre>{lines.map((line, index) => {
          const mention = marks.get(index);
          return (
            <span
              key={index}
              className={markClass(mention, scoped)}
              ref={mention?.effective === true ? effectiveRef : undefined}
            >{line}{"\n"}</span>
          );
        })}</pre>
      </div>
    </>
  );
}

function markClass(mention: { commented: boolean; effective: boolean } | undefined, scoped: boolean): string | undefined {
  if (mention === undefined) return undefined;
  if (scoped && !mention.commented) return "is-mentioned";
  if (mention.effective) return "is-effective";
  return mention.commented ? "is-commented" : "is-inert";
}
