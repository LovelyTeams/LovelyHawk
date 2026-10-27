import { TransientNotice } from "./NotificationCenter";
import { forwardRef, useEffect, useId, useImperativeHandle, useMemo, useRef, useState, type ReactNode } from "react";

import {
  isConfigVisualView,
  type ConfigVisualApi,
  type ConfigVisualDocumentProduct,
  type ConfigVisualParameter,
  type ConfigVisualProduct,
  type ConfigVisualRequest,
  type ConfigVisualRow,
  type ConfigVisualView,
} from "../shared/config-visual-contract";
import { ConfigGoalAssignmentBox } from "./ConfigGoalPanel";
import { DatabaseFilePicker, DatabaseParameterDetail, DatabaseVersionPanels } from "./DatabaseFilePanels";
import {
  configVisualHelp,
  configVisualPlace,
  configVisualRowHelps,
  configVisualSuggestions,
  configVisualUnknownHelp,
  type ConfigVisualHelp,
} from "./config-visual-glossary";
import {
  MAX_CONFIG_VISUAL_QUERY_CHARS,
  configVisualCheckAdvice,
  configVisualKindLabel,
  configVisualPartlyOpaqueNotice,
  configVisualProductLabel,
  configVisualRowFacts,
  configVisualRowLabel,
  configVisualRowReason,
  configVisualSignature,
  configVisualSourceLabel,
  formatConfigVisualBytes,
  isOptionFileProduct,
  nearestConfigVisualRow,
  visibleConfigVisualRows,
} from "./config-visual-helpers";
import { DialogHost } from "./DialogHost";
import { useConfirmDialog } from "./use-confirm-dialog";
import "./config-visual.css";

export interface ConfigVisualEditorHandle {
  /** Asks before unsaved edits are dropped; closes the document when leaving. */
  beforeDeactivate(): Promise<boolean>;
}

interface ConfigVisualEditorProps {
  api: ConfigVisualApi;
  /** A document opened elsewhere, such as from a quick Nginx draft. */
  initialView?: ConfigVisualView | null | undefined;
  /** The opened document holds a value written for it but not yet saved. */
  initialDirty?: boolean | undefined;
  /** A catalogued parameter to find in the opened database file. */
  initialParameterKey?: string | null | undefined;
  modeSwitch?: ReactNode;
}

type Notice = { tone: "info" | "error"; text: string };
type AddKind = "directive" | "block" | "comment";

const PRODUCTS: readonly ConfigVisualDocumentProduct[] = ["nginx", "apache", "redis", "haproxy", "mysql", "mariadb", "database"];
/** Database files whose syntax has groups (or tables) to add. */
const DATABASE_GROUP_SYNTAXES: readonly string[] = ["mysql-option", "ini", "toml"];
const MAX_NOTE_CHARS = 512;

/**
 * An Nginx, Apache httpd or Redis file as a tree: each row a directive, a
 * block (server, location) or section (<VirtualHost>, <Directory>), or a
 * comment; redis.conf is one flat list of lines. Rows are changed one at a
 * time, every change is checked by the same parser that reads the file, and
 * the result is saved to a new file. Nothing here is applied to a server.
 *
 * Every item the built-in notes know carries a short Chinese explanation, and
 * a new item can take one along as a comment line right above it.
 */
export const ConfigVisualEditor = forwardRef<ConfigVisualEditorHandle, ConfigVisualEditorProps>(
function ConfigVisualEditor({ api, initialView = null, modeSwitch, initialDirty = false, initialParameterKey = null }, ref) {
  const [view, setView] = useState<ConfigVisualView | null>(initialView);
  /** Which syntax a new or imported document is in, or a catalogued database file. */
  const [product, setProduct] = useState<ConfigVisualDocumentProduct>(initialView?.product ?? "nginx");
  /** The catalogued database file the picker has chosen, and whether it can be drafted. */
  const [databaseFile, setDatabaseFile] = useState<{ key: string; draftable: boolean } | null>(null);
  const [dirty, setDirty] = useState(initialView !== null && initialDirty);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [editName, setEditName] = useState("");
  const [editArguments, setEditArguments] = useState("");
  const [editText, setEditText] = useState("");
  const [addKind, setAddKind] = useState<AddKind>("directive");
  const [addInside, setAddInside] = useState(true);
  const [addName, setAddName] = useState("");
  const [addArguments, setAddArguments] = useState("");
  const [addText, setAddText] = useState("");
  /** Whether a new directive or block takes a Chinese comment line above it. */
  const [noteOn, setNoteOn] = useState(true);
  /** The comment as the operator rewrote it; null follows the built-in note. */
  const [noteEdited, setNoteEdited] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice | null>(null);
  const busyRef = useRef(false);
  const viewRef = useRef(view);
  const dirtyRef = useRef(dirty);
  viewRef.current = view;
  dirtyRef.current = dirty;
  const confirm = useConfirmDialog();
  const formId = useId();

  const rows = view?.rows ?? [];
  const docProduct: ConfigVisualDocumentProduct = view?.product ?? product;
  /** The built-in notes cover the six products; a database file's meaning comes from its catalogue. */
  const glossaryProduct: ConfigVisualProduct | null = docProduct === "database" ? null : docProduct;
  const database = view?.database ?? null;
  const flat = docProduct === "redis" ||
    (database !== null && !DATABASE_GROUP_SYNTAXES.includes(database.syntax));
  const block = configVisualKindLabel("block", docProduct);
  const visibleRows = useMemo(() => visibleConfigVisualRows(rows, query, docProduct), [rows, query, docProduct]);
  const rowHelps = useMemo(
    () => glossaryProduct === null ? new Map<string, ConfigVisualHelp>() : configVisualRowHelps(rows, glossaryProduct),
    [rows, glossaryProduct],
  );
  const selected = rows.find((row) => row.id === selectedId) ?? null;
  const selectedIndex = selected === null ? -1 : rows.indexOf(selected);

  // A search that hides the selection drops it, so an edit never lands on a
  // row nobody can see.
  useEffect(() => {
    if (selectedId !== null && !visibleRows.some((row) => row.id === selectedId)) setSelectedId(null);
  }, [selectedId, visibleRows]);

  useEffect(() => {
    setEditName(selected?.name ?? "");
    setEditArguments(selected?.arguments ?? "");
    setEditText(selected?.kind === "comment" ? selected.arguments ?? "" : "");
  }, [selected?.id]);

  // redis.conf has no blocks to add.
  useEffect(() => {
    if (flat && addKind === "block") setAddKind("directive");
  }, [flat, addKind]);

  async function confirmDiscard(): Promise<boolean> {
    if (!dirtyRef.current) return true;
    return await confirm.ask(
      "放弃未另存的修改？",
      "当前文档有还没另存为文件的修改。继续的话这些修改会丢失，已经另存的文件不受影响。",
      "放弃修改",
    );
  }

  // Leaving asks about unsaved edits, then releases the document: there is
  // nothing to keep it for once nobody shows it. (Not an unmount effect —
  // development renders run those twice and would close a live document.)
  useImperativeHandle(ref, () => ({
    async beforeDeactivate() {
      if (busyRef.current) {
        setNotice({ tone: "error", text: "请等当前操作完成后再离开。" });
        return false;
      }
      if (!(await confirmDiscard())) return false;
      const current = viewRef.current;
      if (current !== null) {
        await api.configVisual({ action: "close", documentHandle: current.documentHandle, revision: current.revision })
          .catch(() => undefined);
        setView(null);
        setDirty(false);
      }
      return true;
    },
  }));

  async function run(label: string, work: () => Promise<void>): Promise<void> {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(label);
    try {
      await work();
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error && error.message.trim() !== "" ? error.message : "操作没有完成。" });
    } finally {
      busyRef.current = false;
      setBusy(null);
    }
  }

  async function replaceDocument(open: () => Promise<ConfigVisualView | null>, message: string): Promise<void> {
    if (!(await confirmDiscard())) return;
    await run("open", async () => {
      const next = await open();
      if (next === null) return;
      const previous = viewRef.current;
      if (previous !== null) {
        await api.configVisual({ action: "close", documentHandle: previous.documentHandle, revision: previous.revision })
          .catch(() => undefined);
      }
      setView(next);
      setDirty(false);
      setSelectedId(null);
      setQuery("");
      setNotice({ tone: "info", text: message });
    });
  }

  async function openNew(template: "blank" | "competition"): Promise<void> {
    if (product === "database") {
      await openDatabase();
      return;
    }
    const chosen = product;
    await replaceDocument(async () => {
      const next = await api.configVisual({ action: "new", product: chosen, template });
      if (!isConfigVisualView(next)) throw new Error("新文档没有通过校验。");
      return next;
    }, template === "blank"
      ? `已新建空白 ${configVisualProductLabel(chosen)} 文档。`
      : `已按比赛模板新建 ${configVisualProductLabel(chosen)} 文档，模板里的中文注释说明了每一段的用途。`);
  }

  async function importFile(): Promise<void> {
    if (product === "database") {
      if (databaseFile === null) return;
      const key = databaseFile.key;
      await replaceDocument(() => api.importConfigVisualDatabase(key),
        "已导入本地文件。没有改动前，另存的内容与原文件逐字节相同。");
      return;
    }
    await replaceDocument(() => api.importConfigVisual(product),
      "已导入本地文件。没有改动前，另存的内容与原文件逐字节相同。");
  }

  /** The chosen catalogued file: its reviewed starting content, or an empty read-only view. */
  async function openDatabase(): Promise<void> {
    if (databaseFile === null) return;
    const { key, draftable } = databaseFile;
    await replaceDocument(async () => {
      const next = await api.configVisual({ action: "new-database", artifactKey: key });
      if (!isConfigVisualView(next)) throw new Error("文件没有通过校验。");
      return next;
    }, draftable
      ? "已打开这个文件的起始内容。改好后另存为新文件。"
      : "这个文件只读：可以导入本地副本查看，并另存副本。");
  }

  /** Reads the rows against another reviewed version; the file's bytes stay as they are. */
  async function selectSchema(schema: number | null): Promise<void> {
    const current = viewRef.current;
    if (current === null) return;
    await run("edit", async () => {
      const next = await api.configVisual({ action: "select-schema", documentHandle: current.documentHandle, revision: current.revision, schema });
      if (!isConfigVisualView(next)) throw new Error("版本选择的结果没有通过校验。");
      setView(next);
      setNotice({ tone: "info", text: schema === null ? "已取消对照，只按语法显示。" : "已按所选版本的目录标出说明；这些说明没有核对过任何服务器。" });
    });
  }

  /** One catalogue parameter's value into the draft, checked and read back by the backend. */
  async function setParameter(parameterIndex: number, value: string): Promise<boolean> {
    const current = viewRef.current;
    if (current === null) return false;
    const key = current.database?.parameters[parameterIndex]?.key ?? "参数";
    return await edit({ action: "set-parameter", documentHandle: current.documentHandle, revision: current.revision, parameterIndex, value },
      null, `已把 ${key} 写入草稿，并按所选版本的目录核对过写回的内容。`);
  }

  /**
   * A confirmed assignment: the open file at its next revision, or a new
   * draft. A new draft only comes when the open file had nothing unsaved,
   * so letting the open file go loses nothing.
   */
  async function landAssignment(next: ConfigVisualView, message: string): Promise<void> {
    const previous = viewRef.current;
    if (previous !== null && previous.documentHandle !== next.documentHandle) {
      await api.configVisual({ action: "close", documentHandle: previous.documentHandle, revision: previous.revision })
        .catch(() => undefined);
    }
    setView(next);
    setDirty(true);
    setSelectedId(null);
    setNotice({ tone: "info", text: message });
  }

  async function closeDocument(): Promise<void> {
    if (view === null || !(await confirmDiscard())) return;
    await run("close", async () => {
      await api.configVisual({ action: "close", documentHandle: view.documentHandle, revision: view.revision });
      setView(null);
      setDirty(false);
      setSelectedId(null);
      setNotice(null);
    });
  }

  /** One edit against the revision on screen; the answer replaces the view. */
  async function edit(request: ConfigVisualRequest, select: { signature: string; near: number } | null,
    message: string): Promise<boolean> {
    let done = false;
    await run("edit", async () => {
      const next = await api.configVisual(request);
      if (!isConfigVisualView(next)) throw new Error("修改结果没有通过校验。");
      setView(next);
      setDirty(true);
      const chosen = select === null ? null : nearestConfigVisualRow(next.rows, select.signature, select.near);
      setSelectedId(chosen?.id ?? null);
      setNotice({ tone: "info", text: message });
      done = true;
    });
    return done;
  }

  async function saveSelected(): Promise<void> {
    if (view === null || selected === null || !selected.editable) return;
    if (selected.kind === "comment") {
      await edit({ action: "update", documentHandle: view.documentHandle, revision: view.revision, nodeId: selected.id, text: editText },
        { signature: configVisualSignature({ ...selected, arguments: editText.trim() }), near: selectedIndex }, "注释已更新。");
      return;
    }
    await edit({
      action: "update", documentHandle: view.documentHandle, revision: view.revision, nodeId: selected.id,
      name: editName, arguments: editArguments,
    }, {
      signature: configVisualSignature({ ...selected, name: editName.trim(), arguments: editArguments.trim() || null }),
      near: selectedIndex,
    }, `已更新${configVisualKindLabel(selected.kind, docProduct)} ${editName.trim()}。`);
  }

  async function move(direction: "up" | "down"): Promise<void> {
    if (view === null || selected === null) return;
    await edit({ action: "move", documentHandle: view.documentHandle, revision: view.revision, nodeId: selected.id, direction },
      { signature: configVisualSignature(selected), near: selectedIndex + (direction === "up" ? -1 : 1) },
      direction === "up" ? "已上移一位。" : "已下移一位。");
  }

  async function remove(): Promise<void> {
    if (view === null || selected === null) return;
    if (selected.kind === "block" && selected.childCount > 0 && !(await confirm.ask(
      `删除 ${selected.name ?? `这个${block}`} ${block}？`,
      `会连同里面的 ${selected.childCount} 个直接子项（以及它们里面的内容）一起删除。删除只改这份草稿，还没另存的话可以关闭文档不保存。`,
      `删除整个${block}`,
    ))) return;
    const parent = selected.parentId === null ? null : rows.find((row) => row.id === selected.parentId) ?? null;
    await edit({ action: "remove", documentHandle: view.documentHandle, revision: view.revision, nodeId: selected.id },
      parent === null ? null : { signature: configVisualSignature(parent), near: rows.indexOf(parent) },
      `已删除${configVisualKindLabel(selected.kind, docProduct)}${selected.name !== null ? ` ${selected.name}` : ""}。`);
  }

  // HAProxy sections and option-file groups hold lines one level deep and
  // never nest: a selected line stands for its section, a new section always
  // goes at the top, and a setting always goes inside one. An option file's
  // !include line may also stand at the top.
  const optionFile = isOptionFileProduct(docProduct);
  const sectioned = docProduct === "haproxy" || optionFile;
  const insideTarget = selected === null ? null
    : selected.kind === "block" ? selected
    : sectioned && selected.parentId !== null ? rows.find((row) => row.id === selected.parentId) ?? null
    : null;
  const canAddInside = !flat && insideTarget !== null && insideTarget.kind === "block" && insideTarget.editable &&
    view?.structured === true;
  const addParent = sectioned && addKind === "block" ? null
    : sectioned && addKind === "directive" ? (canAddInside ? insideTarget : null)
    : addInside && canAddInside ? insideTarget : null;
  const addingInclude = optionFile && addKind === "directive" && addName.trim().startsWith("!");
  const addNeedsSection = sectioned && addKind === "directive" && addParent === null && !addingInclude;
  // An option group's header is its name alone; so is a database file's group or table.
  const addTakesArguments = !((optionFile || database !== null) && addKind === "block");
  const addPlace = glossaryProduct === null ? "" : configVisualPlace(rows, addParent, glossaryProduct);
  const addStatement = addKind === "comment" ? null : addKind;
  const suggestions = useMemo(
    () => addStatement === null || glossaryProduct === null ? [] : configVisualSuggestions(glossaryProduct, addStatement, addPlace),
    [glossaryProduct, addStatement, addPlace],
  );
  const addHelp = addStatement === null || glossaryProduct === null ? null
    : configVisualHelp(glossaryProduct, addStatement, addName, addPlace);
  const noteText = noteEdited ?? addHelp?.summary ?? "";
  const pickedSuggestion = suggestions.find((entry) => entry.name === addName.trim()) ?? null;

  function pickSuggestion(name: string): void {
    const entry = suggestions.find((candidate) => candidate.name === name);
    if (entry === undefined) return;
    setAddName(entry.name);
    setAddArguments(entry.example ?? "");
    setNoteEdited(null);
  }

  async function add(): Promise<void> {
    if (view === null || !view.structured || addNeedsSection) return;
    const parentId = addParent?.id ?? null;
    const depth = addParent === null ? 0 : addParent.depth + 1;
    const where = addParent === null ? (addingInclude ? "文件开头" : flat || sectioned ? "文件末尾" : "文件最外层")
      : `${sectioned ? sectionTitle(addParent, docProduct) : addParent.name ?? `所选${block}`} ${block}里`;
    const argumentsSent = addTakesArguments ? addArguments : "";
    if (addKind === "comment") {
      await edit({ action: "add", documentHandle: view.documentHandle, revision: view.revision, parentId, kind: "comment", text: addText },
        { signature: configVisualSignature({ kind: "comment", depth, name: null, arguments: addText.trim() }), near: selectedIndex + 1 },
        `已在${where}添加注释。`);
      setAddText("");
      return;
    }
    const note = noteOn ? noteText.trim() : "";
    const request: ConfigVisualRequest = {
      action: "add", documentHandle: view.documentHandle, revision: view.revision, parentId, kind: addKind,
      name: addName, arguments: argumentsSent, ...(note === "" ? {} : { note }),
    };
    const added = await edit(request, {
      signature: configVisualSignature({ kind: addKind, depth, name: addName.trim(), arguments: argumentsSent.trim() || null }),
      near: selectedIndex + (note === "" ? 1 : 2),
    }, `已在${where}添加${configVisualKindLabel(addKind, docProduct)} ${addName.trim()}${note === "" ? "" : "，上方附了一行中文注释"}。`);
    if (!added) return;
    setAddName("");
    setAddArguments("");
    setNoteEdited(null);
  }

  async function copy(): Promise<void> {
    if (view === null) return;
    await run("copy", async () => {
      const result = await api.copyConfigVisual(view.documentHandle, view.revision);
      setNotice({ tone: "info", text: `已复制全部内容（${formatConfigVisualBytes(result.byteLength)}）。` });
    });
  }

  async function save(): Promise<void> {
    if (view === null) return;
    await run("save", async () => {
      const result = await api.saveConfigVisual(view.documentHandle, view.revision);
      if (!result.saved) return;
      setDirty(false);
      setNotice({ tone: "info", text: `已另存为 ${result.fileName}。${configVisualCheckAdvice(docProduct)}` });
    });
  }

  const working = busy !== null;
  const addKinds: readonly AddKind[] = flat ? ["directive", "comment"] : ["directive", "block", "comment"];

  return (
    <section className="config-visual" aria-label="可视化编辑" data-testid="config-visual">
      <header className="config-visual-toolbar">
        {modeSwitch}
        <div className="config-visual-product" role="group" aria-label="新建或导入的产品">
          {PRODUCTS.map((choice) => (
            <button type="button" key={choice} aria-pressed={product === choice} disabled={working}
              className={product === choice ? "is-active" : undefined} onClick={() => setProduct(choice)}>
              {configVisualProductLabel(choice)}
            </button>
          ))}
        </div>
        {product === "database" ? (
          <div className="config-visual-actions is-database" role="group" aria-label="数据库配置文件">
            <DatabaseFilePicker api={api} disabled={working} artifactKey={databaseFile?.key ?? null}
              onArtifact={(key, draftable) => setDatabaseFile({ key, draftable })} />
            <button type="button" disabled={working || databaseFile === null} onClick={() => void openDatabase()}
              data-testid="config-visual-database-open">
              {databaseFile?.draftable === false ? "打开（只读）" : "打开起始内容"}
            </button>
            <button type="button" disabled={working || databaseFile === null} onClick={() => void importFile()}>导入本地文件…</button>
          </div>
        ) : (
          <div className="config-visual-actions" role="group" aria-label="文档">
            <button type="button" disabled={working} onClick={() => void openNew("competition")}>新建比赛模板</button>
            <button type="button" disabled={working} onClick={() => void openNew("blank")}>新建空白文档</button>
            <button type="button" disabled={working} onClick={() => void importFile()}>导入本地文件…</button>
          </div>
        )}
        {view !== null ? (
          <div className="config-visual-actions" role="group" aria-label="另存与复制">
            <button type="button" disabled={working || !view.copyAllowed} onClick={() => void copy()}
              title={view.copyAllowed ? undefined : "含有隐藏的敏感内容、不是 UTF-8 文本或超过 256 KB 的文档不能复制。"}>
              {busy === "copy" ? "复制中…" : "复制全部"}
            </button>
            <button type="button" className="primary" disabled={working} onClick={() => void save()}>
              {busy === "save" ? "另存中…" : "另存为文件…"}
            </button>
            <button type="button" disabled={working} onClick={() => void closeDocument()}>关闭文档</button>
          </div>
        ) : null}
      </header>

      {notice !== null ? (
        <TransientNotice source="配置编辑" message={notice.text ?? ""} severity={(notice.tone === "error" ? "alert" : "status") === "alert" ? "error" : "info"} inline><p className={`config-visual-notice ${notice.tone}`} role={notice.tone === "error" ? "alert" : "status"}>{notice.text}</p></TransientNotice>
      ) : null}

      {view === null && product === "database" ? (
        <div className="config-visual-empty" data-testid="config-visual-empty">
          <h2>按内置目录查看和修改数据库配置文件</h2>
          <p>先在上面选数据库和配置文件。能起草的文件可以从经过审查的起始内容开始，也可以导入本机已有的副本；服务器或厂商工具生成的文件只能查看和另存副本，不能修改。</p>
          <p>打开后可以选一个“对照的版本”：目录描述过的项会标出“目录说明”，右边列出这个版本的参数，以及每个参数的取值、作用范围、生效方式和风险；能写入的参数可以直接填值，值先按目录检查，写入后再读回核对。这些说明来自内置目录，没有核对过任何服务器。</p>
          <p>口令、密钥这类内容会被隐藏，不能在这里填写，整份文件也不能复制和预览。改好后另存为新文件，不会覆盖已有文件，也不会改动任何服务器。</p>
          <div className="config-visual-empty-actions">
            <button type="button" className="primary" disabled={working || databaseFile === null} onClick={() => void openDatabase()}>
              {databaseFile?.draftable === false ? "打开（只读）" : "打开起始内容"}
            </button>
            <button type="button" disabled={working || databaseFile === null} onClick={() => void importFile()}>导入本地文件…</button>
          </div>
        </div>
      ) : view === null ? (
        <div className="config-visual-empty" data-testid="config-visual-empty">
          <h2>把 Nginx、Apache httpd、Redis、HAProxy、MySQL 或 MariaDB 配置当成一棵树来改</h2>
          <p>每一行是一条指令、一个块或区段（Nginx 的 server、location，Apache 的 VirtualHost、Directory，HAProxy 的 frontend、backend），MySQL、MariaDB 选项文件里的一个选项组（[mysqld]、[client]）或选项，或者一行注释；Redis 配置没有块，是一列配置项。选中一行就能改它的名称和参数，也可以上下移动、删除，或者往块里添加新的项。每次修改都会按这个产品的语法重新检查，检查不过就不会生效。</p>
          <p>常用的指令和配置项旁边都有中文说明，告诉你它管什么、常见怎么写、要注意什么；添加新项时可以从常用项里选，并在它上方自动加一行中文注释，方便以后的人看懂。</p>
          <p>先在上面选产品，再从比赛模板、空白文档或本机已有的配置文件开始；也可以在“生成新配置”里生成配置后，点“在可视化编辑中打开”。改好后另存为新文件，不会覆盖已有文件，也不会改动任何服务器。</p>
          <div className="config-visual-empty-actions">
            <button type="button" className="primary" disabled={working} onClick={() => void openNew("competition")}>新建比赛模板</button>
            <button type="button" disabled={working} onClick={() => void importFile()}>导入本地文件…</button>
          </div>
        </div>
      ) : (
        <>
          <div className="config-visual-status" data-testid="config-visual-status">
            <strong>{database === null ? configVisualProductLabel(view.product) : `${database.productLabel} · ${database.fileLabel}`}</strong>
            <span>{configVisualSourceLabel(view.source)}</span>
            <span>{view.totalRows} 项</span>
            <span>{formatConfigVisualBytes(view.totalBytes)}</span>
            {dirty ? <span className="config-visual-dirty" data-testid="config-visual-dirty">有未另存的修改</span> : <span>没有未另存的修改</span>}
          </div>
          <div className="config-visual-banners">
            {!view.structured ? <p className="warning">这个文件没能按 {configVisualProductLabel(view.product)} 语法完整解析（或者不是 UTF-8 文本），只能原样保留，不能逐项编辑。另存的内容与原文件逐字节相同。</p> : null}
            {view.structured && view.partlyOpaque ? <p className="warning">{configVisualPartlyOpaqueNotice(view.product)}</p> : null}
            {view.containsSensitive ? <p className="warning">文件里有疑似口令、令牌或带账号的地址。相关的行已隐藏，不能在这里修改、删除或移动，整份文件也不能复制和预览；另存时这些内容原样保留。</p> : null}
            {view.rowsTruncated ? <p className="warning">文件很大，这里只列出前 {view.rows.length} 项（共 {view.totalRows} 项）。</p> : null}
            <p>这是本机草稿，没有在目标服务器上校验过，不能直接部署。{configVisualCheckAdvice(view.product)}中文说明是内置的通用解释，不代表目标上的版本一定支持某一项。</p>
          </div>

          <div className="config-visual-body">
            <section className="config-visual-tree" aria-label="配置结构">
              <label className="config-visual-search">
                <span>按名称、类型或中文说明筛选</span>
                <input type="search" value={query} maxLength={MAX_CONFIG_VISUAL_QUERY_CHARS}
                  placeholder={searchPlaceholder(view.product)}
                  onChange={(event) => setQuery(event.target.value)} />
              </label>
              <p className="config-visual-count">{query.trim() === "" ? `${rows.length} 项` : `显示 ${visibleRows.length} / ${rows.length} 项${flat ? "" : `（含所在的${block}）`}`}</p>
              {visibleRows.length === 0 ? (
                <p className="config-visual-tree-empty">{rows.length === 0
                  ? `文档是空的。用右边的“添加”加入第一项，例如 ${firstItemExample(view.product)}。`
                  : "没有匹配的项。筛选只看名称、类型和内置的中文说明，不看参数和注释内容。"}</p>
              ) : (
                <ul className="config-visual-rows" data-testid="config-visual-rows">
                  {visibleRows.map((row) => {
                    const help = rowHelps.get(row.id);
                    return (
                      <li key={row.id}>
                        <button type="button" aria-pressed={row.id === selectedId}
                          className={`config-visual-row${row.editable ? "" : " is-locked"}${row.id === selectedId ? " is-selected" : ""}`}
                          style={{ paddingLeft: `${10 + Math.min(row.depth, 16) * 16}px` }}
                          data-kind={row.kind} onClick={() => setSelectedId(row.id === selectedId ? null : row.id)}>
                          <span className="config-visual-row-label">
                            {configVisualRowLabel(row, view.product)}
                            {row.meaning === "catalog" ? <em className="config-visual-row-catalog" data-testid="config-visual-row-catalog">目录说明</em> : null}
                          </span>
                          <span className="config-visual-row-preview">{rowPreview(row)}</span>
                          {help !== undefined ? <span className="config-visual-row-help" data-testid="config-visual-row-help">{help.summary}</span> : null}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            <div className="config-visual-side">
              {database !== null ? (
                <DatabaseVersionPanels database={database} working={working} focusKey={initialParameterKey}
                  onSchema={(schema) => void selectSchema(schema)} onSetParameter={setParameter} />
              ) : null}
              {database !== null && database.readOnly === null ? (
                <ConfigGoalAssignmentBox api={api} working={working}
                  document={{ documentHandle: view.documentHandle, revision: view.revision, unsaved: dirty }}
                  onLanded={landAssignment} />
              ) : null}
              <section className="config-visual-panel" aria-label="所选项" data-testid="config-visual-selected">
                <h2>所选项</h2>
                {selected === null ? (
                  <p className="config-visual-hint">{database?.readOnly != null
                    ? "在左边选择一行查看它；这个文件只读，不能修改或添加。"
                    : "在左边选择一行来修改它，或在下面添加新的一项。"}</p>
                ) : (
                  <SelectedRow row={selected} product={view.product} help={rowHelps.get(selected.id) ?? null}
                    parameter={selected.parameterIndex === null ? null : database?.parameters[selected.parameterIndex] ?? null}
                    fileReadOnly={database?.readOnly != null}
                    working={working} name={editName} args={editArguments} text={editText}
                    onName={setEditName} onArgs={setEditArguments} onText={setEditText}
                    onSave={() => void saveSelected()} onMove={(direction) => void move(direction)} onRemove={() => void remove()} />
                )}
              </section>

              <section className="config-visual-panel" aria-label="添加" data-testid="config-visual-add">
                <h2>添加</h2>
                {database?.readOnly != null ? (
                  <p className="config-visual-hint">这个文件只读，不能添加新项。</p>
                ) : !view.structured ? (
                  <p className="config-visual-hint">文件没能完整解析，不能添加新项。</p>
                ) : (
                  <form onSubmit={(event) => { event.preventDefault(); void add(); }}>
                    <div className="config-visual-choice" role="radiogroup" aria-label="添加什么">
                      {addKinds.map((kind) => (
                        <label key={kind}>
                          <input type="radio" name="config-visual-add-kind" checked={addKind === kind} onChange={() => setAddKind(kind)} />
                          {configVisualKindLabel(kind, view.product)}
                        </label>
                      ))}
                    </div>
                    {flat ? (
                      <p className="config-visual-hint">{docProduct === "database"
                        ? "这种文件没有分组，新配置项加在文件末尾；同一项写了多次时，哪一行生效由这个产品决定。"
                        : "Redis 配置没有块，新项加在文件末尾；同一项写了多次时，大多以最后一次为准。"}</p>
                    ) : sectioned && addKind === "block" ? (
                      <p className="config-visual-hint">{optionFile
                        ? "选项组不能嵌套，新选项组加在文件末尾；组名写在方括号里，例如 mysqld 会写成 [mysqld]。"
                        : "HAProxy 的区段不能嵌套，新区段加在文件末尾。"}</p>
                    ) : sectioned && addKind === "directive" ? (
                      <p className={`config-visual-hint${addNeedsSection ? " is-blocking" : ""}`} data-testid="config-visual-add-place">
                        {addParent !== null
                          ? `加在 ${sectionTitle(addParent, view.product)} ${block}的最后。`
                          : addingInclude
                            ? "!include 这类引用行加在文件开头、第一个选项组之前。"
                            : optionFile
                              ? "选项必须写在选项组里：先在左边选一个选项组，或选中组里的任意一行。只有 !include、!includedir 引用行可以写在所有组之外。"
                              : "HAProxy 的设置必须写在区段里：先在左边选一个区段，或选中区段里的任意一行。"}
                      </p>
                    ) : (
                      <div className="config-visual-choice" role="radiogroup" aria-label="加在哪里">
                        <label>
                          <input type="radio" name="config-visual-add-place" checked={addInside && canAddInside}
                            disabled={!canAddInside} onChange={() => setAddInside(true)} />
                          {canAddInside && insideTarget !== null
                            ? `加在 ${sectioned ? sectionTitle(insideTarget, view.product) : insideTarget.name ?? "所选"} ${block}里面`
                            : `加在所选${block}里面（先在左边选一个能修改的${block}）`}
                        </label>
                        <label>
                          <input type="radio" name="config-visual-add-place" checked={!(addInside && canAddInside)}
                            onChange={() => setAddInside(false)} />
                          加在文件最外层
                        </label>
                      </div>
                    )}
                    {addKind === "comment" ? (
                      <label className="config-visual-field">
                        <span>注释内容</span>
                        <input value={addText} maxLength={2048} onChange={(event) => setAddText(event.target.value)} placeholder="一行说明文字，建议用中文写清楚这一段的用途" />
                      </label>
                    ) : (
                      <>
                        {suggestions.length > 0 ? (
                          <div className="config-visual-suggest">
                            <label htmlFor={`${formId}-suggest`}>从常用项中选（会填好名称和常见写法）</label>
                            <select id={`${formId}-suggest`} data-testid="config-visual-suggest" disabled={working}
                              value={pickedSuggestion?.name ?? ""} onChange={(event) => pickSuggestion(event.target.value)}>
                              <option value="">自己填写名称…</option>
                              {suggestions.map((entry) => (
                                <option key={entry.name} value={entry.name}>{`${entry.name} — ${entry.summary}`}</option>
                              ))}
                            </select>
                          </div>
                        ) : null}
                        <label className="config-visual-field">
                          <span>名称</span>
                          <input value={addName} maxLength={256} required spellCheck={false}
                            placeholder={namePlaceholder(view.product, addKind)}
                            onChange={(event) => setAddName(event.target.value)} />
                        </label>
                        {addTakesArguments ? (
                          <label className="config-visual-field">
                            <span>{optionFile ? "值" : "参数"}</span>
                            <input value={addArguments} maxLength={4096} spellCheck={false}
                              placeholder={argumentsPlaceholder(view.product, addKind)}
                              onChange={(event) => setAddArguments(event.target.value)} />
                          </label>
                        ) : null}
                        {addName.trim() !== "" ? (
                          <HelpBox help={addHelp} product={view.product} name={addName.trim()} testId="config-visual-add-help" />
                        ) : null}
                        <div className="config-visual-note">
                          <label className="config-visual-note-toggle">
                            <input type="checkbox" checked={noteOn} data-testid="config-visual-note-toggle"
                              onChange={(event) => setNoteOn(event.target.checked)} />
                            在上方加一行中文注释
                          </label>
                          {noteOn ? (
                            <input value={noteText} maxLength={MAX_NOTE_CHARS} data-testid="config-visual-note-text"
                              aria-label="注释内容" placeholder="写一句话说明这一项的用途；留空就不加注释"
                              onChange={(event) => setNoteEdited(event.target.value)} />
                          ) : null}
                        </div>
                      </>
                    )}
                    <button type="submit" className="primary"
                      disabled={working || addNeedsSection || (addKind !== "comment" && addName.trim() === "")}>
                      {busy === "edit" ? "处理中…" : `添加${configVisualKindLabel(addKind, view.product)}`}
                    </button>
                  </form>
                )}
              </section>

              <section className="config-visual-panel config-visual-preview" aria-label="完整内容" data-testid="config-visual-preview">
                <h2>完整内容</h2>
                {view.text !== null ? (
                  <>
                    <pre tabIndex={0}>{view.text === "" ? "（空文件）" : view.text}</pre>
                    {view.textTruncated ? <p className="config-visual-hint">内容较长，这里只显示前 128 KB；另存的文件是完整的。</p> : null}
                  </>
                ) : (
                  <p className="config-visual-hint">{view.containsSensitive ? "文件含有隐藏的敏感内容，不在这里显示全文。" : "文件不是 UTF-8 文本，不能在这里显示。"}</p>
                )}
              </section>
            </div>
          </div>
        </>
      )}
      {confirm.dialog !== null ? <DialogHost dialog={confirm.dialog} onResolve={confirm.resolve} /> : null}
    </section>
  );
});

function searchPlaceholder(product: ConfigVisualDocumentProduct): string {
  switch (product) {
    case "nginx": return "例如 location、server、注释、端口";
    case "apache": return "例如 VirtualHost、Directory、注释、日志";
    case "redis": return "例如 bind、maxmemory、口令、持久化";
    case "haproxy": return "例如 frontend、backend、timeout、超时";
    case "mysql":
    case "mariadb": return "例如 mysqld、bind-address、日志、连接数";
    case "database": return "例如 max_connections、端口、重启后生效、高风险";
  }
}

function firstItemExample(product: ConfigVisualDocumentProduct): string {
  switch (product) {
    case "nginx": return "http 块或 server 块";
    case "apache": return "Listen 指令或 VirtualHost 区段";
    case "redis": return "bind 或 protected-mode 配置项";
    case "haproxy": return "global 或 frontend 区段";
    case "mysql":
    case "mariadb": return "mysqld 选项组";
    case "database": return "一个配置项，或从右边的“目录里的参数”写入";
  }
}

function namePlaceholder(product: ConfigVisualDocumentProduct, kind: "directive" | "block"): string {
  if (product === "database") return kind === "block" ? "分组名，例如 mysqld（不用写方括号）" : "例如 max_connections";
  if (product === "apache") return kind === "block" ? "例如 VirtualHost、Directory" : "例如 Listen、ServerName";
  if (product === "redis") return "例如 bind、maxmemory、appendonly";
  if (product === "haproxy") return kind === "block" ? "例如 frontend、backend、listen" : "例如 bind、server、timeout";
  if (isOptionFileProduct(product)) return kind === "block" ? "例如 mysqld、client（不用写方括号）" : "例如 bind-address、max_connections 或 !includedir";
  return kind === "block" ? "例如 server、location" : "例如 listen、server_name";
}

function argumentsPlaceholder(product: ConfigVisualDocumentProduct, kind: "directive" | "block"): string {
  if (product === "database") return "例如 200";
  if (product === "apache") return kind === "block" ? "例如 *:80 或 /var/www/html" : "例如 80 或 example.com";
  if (product === "redis") return "例如 127.0.0.1 -::1 或 256mb";
  if (product === "haproxy") return kind === "block" ? "区段名，例如 web（global、defaults 可以留空）" : "例如 :80 或 app1 127.0.0.1:8080 check";
  if (isOptionFileProduct(product)) return "例如 127.0.0.1 或 500；skip-name-resolve 这类开关留空";
  return kind === "block" ? "例如 /api/（server 块可以留空）" : "例如 80 或 example.com";
}

/** A HAProxy section by its header (`frontend web`), an option group as `[mysqld]`. */
function sectionTitle(row: ConfigVisualRow, product: ConfigVisualDocumentProduct): string {
  if (isOptionFileProduct(product)) return row.name === null ? "所选" : `[${row.name}]`;
  return [row.name, row.arguments].filter((part) => part !== null && part !== "").join(" ") || "所选";
}

function rowPreview(row: ConfigVisualRow): string {
  if (row.sensitive) return "内容已隐藏";
  if (row.kind === "comment") return row.arguments ?? row.preview;
  if (row.kind === "opaque") return row.preview;
  return row.arguments ?? "";
}

/** The built-in note for an item, or a plain word that there is none. */
function HelpBox({ help, product, name, testId }: {
  help: ConfigVisualHelp | null;
  product: ConfigVisualDocumentProduct;
  name: string;
  testId: string;
}) {
  if (help === null) {
    return (
      <p className="config-visual-help is-unknown" data-testid={testId} role="note">
        {product === "database"
          ? "所选版本的目录没有描述这一项（或者还没选版本），这里只按语法显示。请对照目标上该产品版本的官方文档确认它的含义。"
          : configVisualUnknownHelp(product)}
      </p>
    );
  }
  return (
    <div className="config-visual-help" data-testid={testId} role="note">
      <p><strong>作用</strong>{help.summary}</p>
      {help.example !== undefined ? <p><strong>常见写法</strong><code>{`${name} ${help.example}`}</code></p> : null}
      {help.caution !== undefined ? <p className="config-visual-help-caution"><strong>注意</strong>{help.caution}</p> : null}
    </div>
  );
}

function SelectedRow({ row, product, help, parameter, fileReadOnly, working, name, args, text, onName, onArgs, onText, onSave, onMove, onRemove }: {
  row: ConfigVisualRow;
  product: ConfigVisualDocumentProduct;
  help: ConfigVisualHelp | null;
  /** The catalogue's entry for a database file's row, when the chosen version describes it. */
  parameter: ConfigVisualParameter | null;
  /** A file the server writes, or one that needs the vendor's full reference: shown, never changed. */
  fileReadOnly: boolean;
  working: boolean;
  name: string;
  args: string;
  text: string;
  onName(value: string): void;
  onArgs(value: string): void;
  onText(value: string): void;
  onSave(): void;
  onMove(direction: "up" | "down"): void;
  onRemove(): void;
}) {
  const reason = configVisualRowReason(row, product, fileReadOnly);
  const block = configVisualKindLabel("block", product);
  return (
    <div className="config-visual-selected">
      <p className="config-visual-facts">{configVisualRowFacts(row, product)}</p>
      {parameter !== null ? (
        <DatabaseParameterDetail parameter={parameter} testId="config-visual-help" />
      ) : (row.kind === "directive" || row.kind === "block") && row.name !== null ? (
        <HelpBox help={help} product={product} name={row.name} testId="config-visual-help" />
      ) : row.kind === "comment" ? (
        <p className="config-visual-help" data-testid="config-visual-help" role="note">注释以 # 开头，只给人看，不影响配置。用它写清楚下面几行的用途，方便以后的人看懂。</p>
      ) : null}
      {reason !== null ? <p className="config-visual-locked" role="note">{reason}</p> : (
        <form onSubmit={(event) => { event.preventDefault(); onSave(); }}>
          {row.kind === "comment" ? (
            <label className="config-visual-field">
              <span>注释内容</span>
              <input value={text} maxLength={2048} onChange={(event) => onText(event.target.value)} />
            </label>
          ) : (
            <>
              <label className="config-visual-field">
                <span>名称</span>
                <input value={name} maxLength={256} required spellCheck={false} onChange={(event) => onName(event.target.value)} />
              </label>
              {isOptionFileProduct(product) && row.kind === "block" ? (
                <p className="config-visual-hint">选项组只有组名；改名只改 [组名] 这一行，组里的选项不变。</p>
              ) : (
                <label className="config-visual-field">
                  <span>{isOptionFileProduct(product) ? "值（开关类选项留空）" : "参数"}{row.kind === "block" ? `（只改${block}的开头这一行，里面的子项不变）` : ""}</span>
                  <input value={args} maxLength={4096} spellCheck={false} onChange={(event) => onArgs(event.target.value)} />
                </label>
              )}
            </>
          )}
          <div className="config-visual-row-actions">
            <button type="submit" className="primary" disabled={working || (row.kind !== "comment" && name.trim() === "")}>保存修改</button>
            <button type="button" disabled={working} onClick={() => onMove("up")}>上移</button>
            <button type="button" disabled={working} onClick={() => onMove("down")}>下移</button>
            <button type="button" className="danger" disabled={working} onClick={onRemove}>
              {row.kind === "block" && row.childCount > 0 ? `删除整个${block}…` : "删除"}
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
