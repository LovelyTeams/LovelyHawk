import { TransientNotice } from "./NotificationCenter";
import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type FocusEvent,
} from "react";
import { createPortal } from "react-dom";

import type {
  NoteDeleteProposal,
  NoteListPage,
  NoteResult,
} from "../shared/contract";
import {
  formatNoteTimestamp,
  reconcileNoteSelection,
  retryTimedOut,
} from "./notes-helpers";
import { errorText } from "./error-text";
import { useModalScrim } from "./modal-scrim";
import { planExpiryLabel } from "./plan-expiry";
import { SearchIcon } from "./file-icons";

const PAGE_SIZE = 100;

const emptyPage: NoteListPage = {
  total: 0,
  offset: 0,
  hasMore: false,
  items: [],
};

export interface NotesHandle {
  beforeDeactivate(): Promise<boolean>;
}

type OperationResult<T> =
  | { status: "completed"; value: T }
  | { status: "busy" | "stale" }
  | { status: "failed"; reason: unknown };

export const Notes = forwardRef<NotesHandle>(function Notes(_props, ref) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState<NoteListPage>(emptyPage);
  const [listRevision, setListRevision] = useState(0);
  const [selected, setSelected] = useState<NoteResult | null>(null);
  const [title, setTitle] = useState("");
  const [content, setContent] = useState("");
  const [tagDraft, setTagDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadingList, setLoadingList] = useState(true);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleteProposal, setDeleteProposal] = useState<NoteDeleteProposal | null>(null);

  const pageRootRef = useRef<HTMLElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const cancelDeleteButtonRef = useRef<HTMLButtonElement>(null);
  const queryRef = useRef("");
  const selectedRef = useRef<NoteResult | null>(null);
  const titleRef = useRef("");
  const contentRef = useRef("");
  const deleteProposalRef = useRef<NoteDeleteProposal | null>(null);
  useModalScrim(deleteProposal !== null);
  const lifecycleGeneration = useRef(0);
  const listGeneration = useRef(0);
  const noteGeneration = useRef(0);
  const operationGeneration = useRef(0);
  const busyRef = useRef(false);
  const operationDoneRef = useRef<Promise<void> | null>(null);
  const savePromiseRef = useRef<Promise<boolean> | null>(null);
  const autoSelectionAttemptRef = useRef<string | null>(null);
  const saveCurrentRef = useRef<() => Promise<boolean>>(async () => true);
  const createMutationIdRef = useRef<string | null>(null);

  const dirty = useMemo(
    () => selected !== null && (title !== selected.title || content !== selected.content),
    [content, selected, title],
  );

  useEffect(
    () => () => {
      lifecycleGeneration.current += 1;
      listGeneration.current += 1;
      noteGeneration.current += 1;
      operationGeneration.current += 1;
      busyRef.current = false;
      operationDoneRef.current = null;
      savePromiseRef.current = null;
    },
    [],
  );

  const runExclusive = useCallback(async <T,>(
    work: (isCurrent: () => boolean) => Promise<T>,
  ): Promise<OperationResult<T>> => {
    if (busyRef.current) return { status: "busy" };

    busyRef.current = true;
    const lifecycle = lifecycleGeneration.current;
    const operation = ++operationGeneration.current;
    let finishOperation!: () => void;
    const operationDone = new Promise<void>((resolve) => {
      finishOperation = resolve;
    });
    operationDoneRef.current = operationDone;
    setBusy(true);

    const isCurrent = () =>
      lifecycle === lifecycleGeneration.current &&
      operation === operationGeneration.current;

    try {
      const value = await work(isCurrent);
      return isCurrent() ? { status: "completed", value } : { status: "stale" };
    } catch (reason: unknown) {
      return isCurrent() ? { status: "failed", reason } : { status: "stale" };
    } finally {
      if (isCurrent()) {
        busyRef.current = false;
        setBusy(false);
      }
      if (operationDoneRef.current === operationDone) {
        operationDoneRef.current = null;
      }
      finishOperation();
    }
  }, []);

  const loadList = useCallback(async (search: string, offset = 0, append = false) => {
    const lifecycle = lifecycleGeneration.current;
    const generation = ++listGeneration.current;
    setLoadingList(true);
    try {
      const result = await window.lovelyhawk.listNotes(search, offset, PAGE_SIZE);
      if (
        lifecycle !== lifecycleGeneration.current ||
        generation !== listGeneration.current
      ) return;
      setPage((current) =>
        append
          ? { ...result, items: [...current.items, ...result.items] }
          : result,
      );
      setListRevision((current) => current + 1);
      setError(null);
    } catch (reason: unknown) {
      if (
        lifecycle !== lifecycleGeneration.current ||
        generation !== listGeneration.current
      ) return;
      setError(messageFrom(reason, "笔记列表读取失败。"));
    } finally {
      if (
        lifecycle === lifecycleGeneration.current &&
        generation === listGeneration.current
      ) setLoadingList(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void loadList(query), 180);
    return () => window.clearTimeout(timer);
  }, [loadList, query]);

  const updateQuery = useCallback((value: string) => {
    if (queryRef.current === value) return;
    queryRef.current = value;
    listGeneration.current += 1;
    setLoadingList(true);
    setQuery(value);
  }, []);

  const applySelected = useCallback((note: NoteResult) => {
    selectedRef.current = note;
    titleRef.current = note.title;
    contentRef.current = note.content;
    setSelected(note);
    setTitle(note.title);
    setContent(note.content);
    setTagDraft("");
  }, []);

  const clearSelected = useCallback(() => {
    selectedRef.current = null;
    titleRef.current = "";
    contentRef.current = "";
    setSelected(null);
    setTitle("");
    setContent("");
    setTagDraft("");
  }, []);

  const saveCurrent = useCallback((): Promise<boolean> => {
    const pendingSave = savePromiseRef.current;
    if (pendingSave !== null) return pendingSave;

    const note = selectedRef.current;
    const draftTitle = titleRef.current;
    const draftContent = contentRef.current;
    if (
      note === null ||
      (draftTitle === note.title && draftContent === note.content)
    ) return Promise.resolve(true);

    const lifecycle = lifecycleGeneration.current;
    const mutationId = crypto.randomUUID();
    const save = (async () => {
      const result = await runExclusive(async (isCurrent) => {
        const updated = await retryTimedOut(() => window.lovelyhawk.updateNote({
          id: note.id,
          expectedRevision: note.revision,
          mutationId,
          title: draftTitle,
          content: draftContent,
        }));
        if (isCurrent() && selectedRef.current?.id === note.id) {
          applySelected(updated);
          setNotice("笔记已保存。");
          setError(null);
          await loadList(queryRef.current);
        }
        return updated;
      });

      if (
        result.status === "failed" &&
        lifecycle === lifecycleGeneration.current
      ) {
        if (shouldReconcileSave(result.reason)) {
          try {
            const persisted = await window.lovelyhawk.getNote(note.id);
            if (persisted.title === draftTitle && persisted.content === draftContent) {
              applySelected(persisted);
              await loadList(queryRef.current);
              setNotice("保存响应超时，但存储复核确认内容已写入。");
              setError(null);
              return true;
            }
          } catch {
            // The original timeout remains authoritative when reconciliation fails.
          }
        }
        setError(messageFrom(result.reason, "笔记保存失败。"));
      }
      return result.status === "completed";
    })();
    savePromiseRef.current = save;
    void save.then(() => {
      if (savePromiseRef.current === save) savePromiseRef.current = null;
    });
    return save;
  }, [applySelected, loadList, runExclusive]);
  saveCurrentRef.current = saveCurrent;

  const openNote = useCallback(async (id: string, automatic = false): Promise<boolean> => {
    if (selectedRef.current?.id === id) return true;
    if (busyRef.current || !(await saveCurrentRef.current())) return false;

    const lifecycle = lifecycleGeneration.current;
    const generation = ++noteGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const note = await window.lovelyhawk.getNote(id);
      if (isCurrent() && generation === noteGeneration.current) {
        applySelected(note);
        // Opening a note by hand starts with a clean slate. A note opened
        // automatically — the next one after a delete, say — must not wipe the
        // message about what the operator just did.
        if (!automatic) {
          setNotice(null);
          setError(null);
        }
      }
      return note;
    });
    if (
      result.status === "failed" &&
      lifecycle === lifecycleGeneration.current &&
      generation === noteGeneration.current
    ) {
      setError(messageFrom(result.reason, "笔记读取失败。"));
    }
    return result.status === "completed";
  }, [applySelected, runExclusive]);

  const clearSelectionAfterSave = useCallback(async () => {
    if (busyRef.current || !(await saveCurrentRef.current())) return;
    noteGeneration.current += 1;
    clearSelected();
  }, [clearSelected]);

  useEffect(() => {
    if (loadingList || busy) return;
    const desiredId = reconcileNoteSelection(page.items, selected?.id ?? null);
    if (desiredId === (selected?.id ?? null)) return;

    const attemptKey = `${listRevision}:${desiredId ?? "empty"}`;
    if (autoSelectionAttemptRef.current === attemptKey) return;
    autoSelectionAttemptRef.current = attemptKey;
    if (desiredId === null) {
      void clearSelectionAfterSave();
    } else {
      void openNote(desiredId, true);
    }
  }, [
    busy,
    clearSelectionAfterSave,
    listRevision,
    loadingList,
    openNote,
    page.items,
    selected?.id,
  ]);

  const beforeDeactivate = useCallback(async (): Promise<boolean> => {
    const lifecycle = lifecycleGeneration.current;
    while (operationDoneRef.current !== null) {
      const pendingOperation = operationDoneRef.current;
      await pendingOperation;
      if (lifecycle !== lifecycleGeneration.current) return false;
    }
    if (deleteProposalRef.current !== null) return false;
    return saveCurrentRef.current();
  }, []);
  useImperativeHandle(ref, () => ({ beforeDeactivate }), [beforeDeactivate]);

  async function createNote() {
    if (busyRef.current || !(await saveCurrentRef.current())) return;
    const lifecycle = lifecycleGeneration.current;
    const mutationId = createMutationIdRef.current ?? crypto.randomUUID();
    createMutationIdRef.current = mutationId;
    const result = await runExclusive(async (isCurrent) => {
      const note = await retryTimedOut(() => window.lovelyhawk.createNote({
        mutationId,
        content: "",
        tags: [],
      }));
      if (isCurrent()) {
        createMutationIdRef.current = null;
        updateQuery("");
        applySelected(note);
        setNotice("已新建笔记。");
        setError(null);
        await loadList("");
      }
      return note;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      if (!isBackendTimeout(result.reason)) createMutationIdRef.current = null;
      setError(messageFrom(result.reason, "新建笔记失败。"));
    }
  }

  async function togglePin(id: string, pinned: boolean) {
    if (busyRef.current || !(await saveCurrentRef.current())) return;
    const lifecycle = lifecycleGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const note = selectedRef.current?.id === id
        ? selectedRef.current
        : await window.lovelyhawk.getNote(id);
      const mutationId = crypto.randomUUID();
      const updated = await retryTimedOut(() =>
        window.lovelyhawk.setNotePinned(id, !pinned, note.revision, mutationId));
      if (isCurrent()) {
        if (selectedRef.current?.id === id) applySelected(updated);
        setNotice(updated.pinned ? "笔记已置顶。" : "已取消置顶。");
        setError(null);
        await loadList(queryRef.current);
      }
      return updated;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      setError(messageFrom(result.reason, "置顶状态更新失败。"));
    }
  }

  async function addTag() {
    const noteId = selectedRef.current?.id ?? null;
    const tag = tagDraft.trim();
    if (
      noteId === null ||
      tag === "" ||
      busyRef.current ||
      !(await saveCurrentRef.current())
    ) return;
    const note = selectedRef.current;
    if (note === null || note.id !== noteId) return;
    const lifecycle = lifecycleGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const mutationId = crypto.randomUUID();
      const updated = await retryTimedOut(() =>
        window.lovelyhawk.addNoteTag(note.id, tag, note.revision, mutationId));
      if (isCurrent() && selectedRef.current?.id === note.id) {
        applySelected(updated);
        setNotice("标签已添加。");
        setError(null);
        await loadList(queryRef.current);
      }
      return updated;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      setError(messageFrom(result.reason, "标签添加失败。"));
    }
  }

  async function removeTag(tag: string) {
    const noteId = selectedRef.current?.id ?? null;
    if (
      noteId === null ||
      busyRef.current ||
      !(await saveCurrentRef.current())
    ) return;
    const note = selectedRef.current;
    if (note === null || note.id !== noteId) return;
    const lifecycle = lifecycleGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const mutationId = crypto.randomUUID();
      const updated = await retryTimedOut(() =>
        window.lovelyhawk.removeNoteTag(note.id, tag, note.revision, mutationId));
      if (isCurrent() && selectedRef.current?.id === note.id) {
        applySelected(updated);
        setNotice("标签已移除。");
        setError(null);
        await loadList(queryRef.current);
      }
      return updated;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      setError(messageFrom(result.reason, "标签移除失败。"));
    }
  }

  async function requestDelete() {
    const noteId = selectedRef.current?.id ?? null;
    if (
      noteId === null ||
      busyRef.current ||
      !(await saveCurrentRef.current())
    ) return;
    const note = selectedRef.current;
    if (note === null || note.id !== noteId) return;
    const lifecycle = lifecycleGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const mutationId = crypto.randomUUID();
      const proposal = await retryTimedOut(() =>
        window.lovelyhawk.planNoteDelete(note.id, note.revision, mutationId));
      if (isCurrent() && selectedRef.current?.id === note.id) {
        deleteProposalRef.current = proposal;
        setDeleteProposal(proposal);
        setError(null);
      }
      return proposal;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      setError(messageFrom(result.reason, "删除计划创建失败。"));
    }
  }

  const cancelDeleteProposal = useCallback(async () => {
    const proposal = deleteProposalRef.current;
    if (proposal === null || busyRef.current) return;
    const lifecycle = lifecycleGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const mutationId = crypto.randomUUID();
      await retryTimedOut(() => window.lovelyhawk.cancelNoteDelete(proposal.handle, mutationId));
      if (isCurrent() && deleteProposalRef.current?.handle === proposal.handle) {
        deleteProposalRef.current = null;
        setDeleteProposal(null);
        setNotice("删除已取消。");
        setError(null);
      }
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      setError(messageFrom(result.reason, "删除计划取消失败。"));
    }
  }, [runExclusive]);

  async function confirmDelete() {
    const proposal = deleteProposalRef.current;
    if (proposal === null || busyRef.current) return;
    const lifecycle = lifecycleGeneration.current;
    const deletingNoteId = selectedRef.current?.id ?? null;
    const mutationId = crypto.randomUUID();
    const result = await runExclusive(async (isCurrent) => {
      const outcome = await retryTimedOut(() =>
        window.lovelyhawk.confirmNoteDelete(proposal.handle, mutationId));
      if (!outcome.verified) throw new Error("删除结果未通过独立验证。");
      if (isCurrent()) {
        noteGeneration.current += 1;
        deleteProposalRef.current = null;
        setDeleteProposal(null);
        clearSelected();
        setNotice("笔记已永久删除，并完成审计与结果验证。");
        setError(null);
        await loadList(queryRef.current);
      }
      return outcome;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      deleteProposalRef.current = null;
      setDeleteProposal(null);
      if (deletingNoteId !== null) {
        try {
          const persisted = await window.lovelyhawk.getNote(deletingNoteId);
          applySelected(persisted);
          await loadList(queryRef.current);
          setError(messageFrom(result.reason, "笔记仍存在；删除未完成。"));
        } catch (reloadReason: unknown) {
          if (reloadReason instanceof Error && reloadReason.message.includes("(note-not-found)")) {
            noteGeneration.current += 1;
            clearSelected();
            await loadList(queryRef.current);
            setNotice("删除响应未返回，但存储复核确认笔记已不存在。");
            setError(null);
          } else {
            await loadList(queryRef.current);
            setError("笔记删除结果未知，存储复核失败；请刷新后再操作。");
          }
        }
      } else {
        await loadList(queryRef.current);
        setError(messageFrom(result.reason, "笔记删除结果未知，已重新读取列表。"));
      }
    }
  }

  async function exportNotes(id: string | null) {
    if (busyRef.current || !(await saveCurrentRef.current())) return;
    const lifecycle = lifecycleGeneration.current;
    const result = await runExclusive(async (isCurrent) => {
      const exported = await window.lovelyhawk.exportNotes(id);
      if (!isCurrent()) return exported;
      await window.lovelyhawk.writeClipboard(exported.text);
      if (isCurrent()) {
        setNotice(`已复制 ${exported.noteCount} 条笔记的纯文本导出。`);
        setError(null);
      }
      return exported;
    });
    if (result.status === "failed" && lifecycle === lifecycleGeneration.current) {
      setError(messageFrom(result.reason, "笔记导出失败。"));
    }
  }

  const handleEditorBlur = useCallback((event: FocusEvent<HTMLDivElement>) => {
    const nextTarget = event.relatedTarget;
    if (nextTarget instanceof Node && pageRootRef.current?.contains(nextTarget)) return;
    void saveCurrentRef.current();
  }, []);

  useEffect(() => {
    if (deleteProposal === null) return;

    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    const background = pageRootRef.current?.closest(".app-frame");
    const backgroundHadInert = background?.hasAttribute("inert") ?? false;
    const previousAriaHidden = background?.getAttribute("aria-hidden") ?? null;

    cancelDeleteButtonRef.current?.focus({ preventScroll: true });
    background?.setAttribute("inert", "");
    background?.setAttribute("aria-hidden", "true");

    function handleDialogKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        if (!busyRef.current) {
          event.preventDefault();
          void cancelDeleteProposal();
        }
        return;
      }
      if (event.key !== "Tab") return;

      const dialog = dialogRef.current;
      if (dialog === null) return;
      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      );
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const activeElement = document.activeElement;
      if (event.shiftKey && (activeElement === first || !dialog.contains(activeElement))) {
        event.preventDefault();
        last?.focus();
      } else if (!event.shiftKey && (activeElement === last || !dialog.contains(activeElement))) {
        event.preventDefault();
        first?.focus();
      }
    }

    document.addEventListener("keydown", handleDialogKeyDown);
    return () => {
      document.removeEventListener("keydown", handleDialogKeyDown);
      if (background !== null && background !== undefined) {
        if (!backgroundHadInert) background.removeAttribute("inert");
        if (previousAriaHidden === null) {
          background.removeAttribute("aria-hidden");
        } else {
          background.setAttribute("aria-hidden", previousAriaHidden);
        }
      }
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [cancelDeleteProposal, deleteProposal?.handle]);

  return (
    <section className="page notes-page" ref={pageRootRef}>
      <header className="page-heading notes-heading">
        <div>
          <h1>笔记</h1>
          <p>笔记保存在程序目录下的数据文件夹，随便携版一起迁移。</p>
        </div>
        <div className="notes-heading-actions">
          <button type="button" className="secondary-button" disabled={busy} onClick={() => void exportNotes(null)}>导出全部</button>
          <button type="button" disabled={busy} onClick={() => void createNote()}>新建笔记</button>
        </div>
      </header>

      {error !== null ? <TransientNotice source="笔记" message={error ?? ""} severity="error"><div className="notes-notice error" role="alert">{error}</div></TransientNotice> : null}
      {notice !== null ? <TransientNotice source="笔记" message={notice ?? ""} severity="info"><div className="notes-notice" role="status">{notice}</div></TransientNotice> : null}

      <div className="notes-workbench">
        <aside className="notes-list-panel">
          <label className="notes-search">
            <SearchIcon />
            <input
              aria-label="搜索笔记"
              type="search"
              maxLength={256}
              value={query}
              disabled={busy}
              placeholder="搜索标题、正文或 #标签…"
              onChange={(event) => updateQuery(event.currentTarget.value)}
            />
          </label>
          <div className="notes-list-meta">
            <strong>{page.total} 条笔记</strong>
            <span>
              {loadingList ? "读取中…" : "便携存储"}
              <button
                type="button"
                aria-label="刷新笔记列表"
                title="刷新笔记列表"
                disabled={loadingList || busy}
                onClick={() => void loadList(queryRef.current)}
              >
                ↻
              </button>
            </span>
          </div>
          <div className="notes-list" aria-label="笔记列表" aria-busy={loadingList}>
            {page.items.map((note) => (
              <button
                type="button"
                className={selected?.id === note.id ? "note-row active" : "note-row"}
                key={note.id}
                disabled={busy}
                onClick={() => void openNote(note.id)}
              >
                <span className="note-row-heading">
                  <strong>{note.title}</strong>
                  <i aria-label={note.pinned ? "已置顶" : "未置顶"}>{note.pinned ? "◆" : "◇"}</i>
                </span>
                <span className="note-preview">{note.contentPreview || "空白笔记"}{note.contentTruncated ? "…" : ""}</span>
                <span className="note-row-footer">
                  <time>{formatNoteTimestamp(note.updatedAt)}</time>
                  <span>{note.tags.slice(0, 2).map((tag) => `#${tag}`).join("  ")}</span>
                </span>
              </button>
            ))}
            {!loadingList && page.items.length === 0 ? (
              <div className="notes-empty">{query.trim() === "" ? "还没有笔记。点右上角“新建笔记”开始记录。" : "没有匹配的笔记，换个关键词或 #标签 试试。"}</div>
            ) : null}
          </div>
          {page.hasMore ? (
            <button
              className="notes-load-more"
              type="button"
              disabled={loadingList || busy}
              onClick={() => void loadList(queryRef.current, page.items.length, true)}
            >
              加载更多
            </button>
          ) : null}
        </aside>

        <div
          className="notes-editor-panel"
          aria-busy={busy}
          onBlur={handleEditorBlur}
        >
          {selected === null ? (
            <div className="notes-editor-empty">
              <span>✎</span>
              <h2>开始记录调查线索</h2>
              <p>新建一条笔记，或从左侧选择已有记录。</p>
            </div>
          ) : (
            <>
              <div className="notes-editor-toolbar">
                <div className="notes-editor-status">
                  <span>{dirty ? "有未保存更改" : "所有更改已保存"}</span>
                  <small>{selected.id}</small>
                  <div className="notes-editor-times">
                    <time>创建 {formatNoteTimestamp(selected.createdAt)}</time>
                    <time>更新 {formatNoteTimestamp(selected.updatedAt)}</time>
                  </div>
                </div>
                <div>
                  <button type="button" disabled={busy} onClick={() => void togglePin(selected.id, selected.pinned)}>{selected.pinned ? "取消置顶" : "置顶"}</button>
                  <button type="button" disabled={busy} onClick={() => void exportNotes(selected.id)}>导出</button>
                  <button type="button" className="danger-button" disabled={busy} onClick={() => void requestDelete()}>删除</button>
                  <button type="button" className="primary-button" disabled={busy || !dirty} onClick={() => void saveCurrentRef.current()}>保存</button>
                </div>
              </div>
              <div className="notes-editor-fields">
                <input
                  className="note-title-input"
                  aria-label="笔记标题"
                  maxLength={256}
                  value={title}
                  readOnly={busy}
                  onChange={(event) => {
                    titleRef.current = event.currentTarget.value;
                    setTitle(event.currentTarget.value);
                  }}
                />
                <textarea
                  aria-label="笔记正文"
                  maxLength={1_048_576}
                  value={content}
                  readOnly={busy}
                  placeholder="开始记录…"
                  onChange={(event) => {
                    contentRef.current = event.currentTarget.value;
                    setContent(event.currentTarget.value);
                  }}
                />
                <div className="notes-tags">
                  <div className="notes-tag-list" aria-label="笔记标签">
                    {selected.tags.map((tag) => (
                      <span className="note-tag-chip" key={tag}>
                        <button
                          type="button"
                          className="note-tag-filter"
                          disabled={busy}
                          title={`筛选 #${tag}`}
                          onClick={() => updateQuery(`#${tag}`)}
                        >
                          #{tag}
                        </button>
                        <button
                          type="button"
                          className="note-tag-remove"
                          disabled={busy}
                          aria-label={`移除标签 ${tag}`}
                          title="移除标签"
                          onClick={() => void removeTag(tag)}
                        >
                          ×
                        </button>
                      </span>
                    ))}
                  </div>
                  <form
                    onSubmit={(event) => {
                      event.preventDefault();
                      void addTag();
                    }}
                  >
                    <input
                      aria-label="新标签"
                      maxLength={64}
                      value={tagDraft}
                      disabled={busy}
                      placeholder="添加标签"
                      onChange={(event) => setTagDraft(event.currentTarget.value)}
                    />
                    <button type="submit" disabled={busy || tagDraft.trim() === ""}>添加</button>
                  </form>
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {deleteProposal !== null
        ? createPortal(
            <div className="dialog-backdrop" role="presentation">
              <section
                className="danger-dialog"
                ref={dialogRef}
                role="dialog"
                aria-modal="true"
                aria-labelledby="note-delete-title"
                aria-describedby="note-delete-description note-delete-expiry"
                tabIndex={-1}
              >
                <span className="danger-dialog-icon" aria-hidden="true">!</span>
                <p className="eyebrow">危险操作</p>
                <h2 id="note-delete-title">永久删除这条笔记？</h2>
                <p id="note-delete-description">{deleteProposal.summary}</p>
                <small id="note-delete-expiry">本次确认将在 {planExpiryLabel(deleteProposal.expiresInSeconds)}后失效。</small>
                {error !== null ? <TransientNotice source="笔记" message={error ?? ""} severity="error"><p className="danger-dialog-error" role="alert">{error}</p></TransientNotice> : null}
                <div>
                  <button ref={cancelDeleteButtonRef} type="button" disabled={busy} onClick={() => void cancelDeleteProposal()}>取消</button>
                  <button type="button" className="danger-confirm" disabled={busy} onClick={() => void confirmDelete()}>确认永久删除</button>
                </div>
              </section>
            </div>,
            document.body,
          )
        : null}
    </section>
  );
});

function messageFrom(reason: unknown, fallback: string): string {
  return errorText(reason, fallback);
}

function isBackendTimeout(reason: unknown): boolean {
  return reason instanceof Error && reason.message === "The backend request timed out.";
}

function shouldReconcileSave(reason: unknown): boolean {
  return isBackendTimeout(reason) || (
    reason instanceof Error && reason.message.includes("(notes-revision-conflict)")
  );
}
