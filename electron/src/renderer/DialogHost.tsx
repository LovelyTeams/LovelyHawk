import { useEffect, useRef, useState } from "react";

import {
  MAX_PROMPT_VALUE_BYTES,
  boundDialogText,
  resolveDialog,
  type AppDialog,
  type DialogAction,
  type DialogOutcome,
} from "./dialog-state";
import "./dialog-host.css";
import { useModalScrim } from "./modal-scrim";

export interface DialogHostProps {
  dialog: AppDialog;
  busy?: boolean;
  onResolve(outcome: DialogOutcome): void;
}

export function DialogHost({ dialog, busy = false, onResolve }: DialogHostProps) {
  useModalScrim();
  const [promptValue, setPromptValue] = useState(
    dialog.kind === "prompt" ? dialog.value : "",
  );
  const backdropRef = useRef<HTMLDivElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const safeButtonRef = useRef<HTMLButtonElement>(null);
  const promptValueRef = useRef(promptValue);
  const busyRef = useRef(busy);
  const onResolveRef = useRef(onResolve);
  promptValueRef.current = promptValue;
  busyRef.current = busy;
  onResolveRef.current = onResolve;

  useEffect(() => {
    setPromptValue(dialog.kind === "prompt" ? dialog.value : "");
  }, [dialog]);

  useEffect(() => {
    const backdrop = backdropRef.current;
    const parent = backdrop?.parentElement ?? null;
    const siblings = parent === null
      ? []
      : Array.from(parent.children)
          .filter(
            (element): element is HTMLElement =>
              element instanceof HTMLElement && element !== backdrop,
          )
          .map((element) => ({
            element,
            inert: element.inert,
            ariaHidden: element.getAttribute("aria-hidden"),
          }));
    for (const { element } of siblings) {
      element.inert = true;
      element.setAttribute("aria-hidden", "true");
    }
    const previousFocus = document.activeElement instanceof HTMLElement
      ? document.activeElement
      : null;
    safeButtonRef.current?.focus({ preventScroll: true });
    function keydown(event: KeyboardEvent) {
      if (busyRef.current) return;
      if (event.key === "Escape") {
        event.preventDefault();
        dispatch({ type: "cancel", dialogId: dialog.id });
        return;
      }
      if (event.key === "Enter" && dialog.kind !== "dangerous") {
        const target = event.target;
        if (!(target instanceof HTMLButtonElement)) {
          event.preventDefault();
          if (dialog.kind === "alert") {
            dispatch({ type: "dismiss-alert", dialogId: dialog.id });
          } else if (dialog.kind === "confirm") {
            dispatch({ type: "approve-confirm", dialogId: dialog.id });
          } else {
            dispatch({
              type: "submit-prompt",
              dialogId: dialog.id,
              value: promptValueRef.current,
            });
          }
          return;
        }
      }
      if (event.key !== "Tab") return;
      const host = dialogRef.current;
      if (host === null) return;
      const focusable = Array.from(host.querySelectorAll<HTMLElement>(
        'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
      ));
      const index = focusable.indexOf(document.activeElement as HTMLElement);
      const boundary = index < 0 ||
        (event.shiftKey ? index === 0 : index === focusable.length - 1);
      if (!boundary || focusable.length === 0) return;
      event.preventDefault();
      (event.shiftKey ? focusable.at(-1) : focusable[0])?.focus();
    }
    document.addEventListener("keydown", keydown);
    return () => {
      document.removeEventListener("keydown", keydown);
      for (const { element, inert, ariaHidden } of siblings) {
        element.inert = inert;
        if (ariaHidden === null) element.removeAttribute("aria-hidden");
        else element.setAttribute("aria-hidden", ariaHidden);
      }
      if (previousFocus?.isConnected) previousFocus.focus({ preventScroll: true });
    };
  }, [dialog]);

  function dispatch(action: DialogAction) {
    const outcome = resolveDialog(dialog, action);
    if (outcome !== null) onResolveRef.current(outcome);
  }

  const dangerous = dialog.kind === "dangerous";
  return (
    <div ref={backdropRef} className="dialog-host-backdrop">
      <section
        ref={dialogRef}
        className={dangerous ? "dialog-host is-dangerous" : "dialog-host"}
        role={dangerous ? "alertdialog" : "dialog"}
        aria-modal="true"
        aria-labelledby="dialog-host-title"
        aria-describedby="dialog-host-message"
        tabIndex={-1}
      >
        <p className="dialog-host-eyebrow">
          {dangerous ? "DANGEROUS OPERATION" : dialog.kind === "confirm" ? "CONFIRM" : "LOVELYRES"}
        </p>
        <h2 id="dialog-host-title">{dialog.title}</h2>
        <div id="dialog-host-message" className="dialog-host-message">
          {dialog.kind === "dangerous" ? dialog.summary : dialog.message}
        </div>
        {dialog.kind === "prompt" ? (
          <label>
            <span>{dialog.label}</span>
            <input
              type="text"
              value={promptValue}
              disabled={busy}
              onChange={(event) => setPromptValue(
                boundDialogText(event.currentTarget.value, MAX_PROMPT_VALUE_BYTES),
              )}
            />
          </label>
        ) : null}
        <footer>
          {dialog.kind !== "alert" ? (
            <button
              ref={safeButtonRef}
              type="button"
              disabled={busy}
              onClick={() => dispatch({ type: "cancel", dialogId: dialog.id })}
            >
              取消
            </button>
          ) : null}
          {dialog.kind === "alert" ? (
            <button
              ref={safeButtonRef}
              type="button"
              disabled={busy}
              onClick={() => dispatch({ type: "dismiss-alert", dialogId: dialog.id })}
            >
              知道了
            </button>
          ) : dialog.kind === "confirm" ? (
            <button
              type="button"
              className="dialog-host-primary"
              disabled={busy}
              onClick={() => dispatch({ type: "approve-confirm", dialogId: dialog.id })}
            >
              {dialog.confirmLabel}
            </button>
          ) : dialog.kind === "prompt" ? (
            <button
              type="button"
              disabled={busy}
              onClick={() => dispatch({
                type: "submit-prompt",
                dialogId: dialog.id,
                value: promptValue,
              })}
            >
              确定
            </button>
          ) : (
            <button
              type="button"
              className="dialog-host-danger"
              disabled={busy}
              onClick={() => dispatch({
                type: "approve-dangerous",
                dialogId: dialog.id,
                confirmationKey: dialog.confirmationKey,
              })}
            >
              {busy ? "正在验证…" : "确认危险操作"}
            </button>
          )}
        </footer>
      </section>
    </div>
  );
}
