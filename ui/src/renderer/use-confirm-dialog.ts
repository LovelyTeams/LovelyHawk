import { useCallback, useRef, useState } from "react";

import {
  createDialog,
  nextDialogId,
  type AppDialog,
  type DialogOutcome,
} from "./dialog-state";

export interface ConfirmDialogController {
  /** The dialog to render, or null when nothing is being asked. */
  dialog: AppDialog | null;
  /** Resolves to true only when the user explicitly confirms. */
  ask: (title: string, message: string, confirmLabel?: string) => Promise<boolean>;
  resolve: (outcome: DialogOutcome) => void;
}

/**
 * In-app replacement for `window.confirm`. The renderer must never open a
 * system-level dialog: those block the process, cannot be styled or themed,
 * and are invisible to the CDP acceptance probes. Every question fails closed —
 * a superseded, cancelled, or malformed request resolves to false.
 */
export function useConfirmDialog(): ConfirmDialogController {
  const [dialog, setDialog] = useState<AppDialog | null>(null);
  const sequenceRef = useRef(0);
  const resolverRef = useRef<((confirmed: boolean) => void) | null>(null);

  const ask = useCallback(
    (title: string, message: string, confirmLabel?: string) =>
      new Promise<boolean>((resolve) => {
        const { sequence, id } = nextDialogId(sequenceRef.current);
        sequenceRef.current = sequence;
        const next = createDialog(id, confirmLabel === undefined
          ? { kind: "confirm", title, message }
          : { kind: "confirm", title, message, confirmLabel });
        if (next === null) {
          resolve(false);
          return;
        }
        const superseded = resolverRef.current;
        resolverRef.current = resolve;
        superseded?.(false);
        setDialog(next);
      }),
    [],
  );

  const resolve = useCallback((outcome: DialogOutcome) => {
    setDialog(null);
    const resolver = resolverRef.current;
    resolverRef.current = null;
    resolver?.(outcome.kind === "confirmed");
  }, []);

  return { dialog, ask, resolve };
}
