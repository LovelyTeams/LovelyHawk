export const MAX_DIALOG_TITLE_BYTES = 256;
export const MAX_DIALOG_MESSAGE_BYTES = 8 * 1_024;
export const MAX_PROMPT_VALUE_BYTES = 4 * 1_024;
export const MAX_CONFIRMATION_KEY_BYTES = 128;

export type DialogRequest =
  | { kind: "alert"; title: string; message: string }
  | { kind: "confirm"; title: string; message: string; confirmLabel?: string }
  | {
      kind: "prompt";
      title: string;
      message: string;
      label: string;
      initialValue: string;
    }
  | {
      kind: "dangerous";
      title: string;
      summary: string;
      confirmationKey: string;
    };

export type AppDialog =
  | { id: string; kind: "alert"; title: string; message: string }
  | { id: string; kind: "confirm"; title: string; message: string; confirmLabel: string }
  | {
      id: string;
      kind: "prompt";
      title: string;
      message: string;
      label: string;
      value: string;
    }
  | {
      id: string;
      kind: "dangerous";
      title: string;
      summary: string;
      confirmationKey: string;
    };

export type DialogAction =
  | { type: "dismiss-alert"; dialogId: string }
  | { type: "approve-confirm"; dialogId: string }
  | { type: "submit-prompt"; dialogId: string; value: string }
  | { type: "cancel"; dialogId: string }
  | { type: "approve-dangerous"; dialogId: string; confirmationKey: string };

export type DialogOutcome =
  | { kind: "alert-dismissed"; dialogId: string }
  | { kind: "confirmed"; dialogId: string }
  | { kind: "prompt-submitted"; dialogId: string; value: string }
  | { kind: "cancelled"; dialogId: string }
  | { kind: "dangerous-approved"; dialogId: string; confirmationKey: string };

const encoder = new TextEncoder();

export function nextDialogId(previous: number): { sequence: number; id: string } {
  const sequence = previous >= Number.MAX_SAFE_INTEGER ? 1 : Math.max(0, previous) + 1;
  return { sequence, id: `dialog-${sequence}` };
}

export function createDialog(id: string, request: DialogRequest): AppDialog | null {
  if (!/^dialog-[1-9][0-9]*$/u.test(id)) return null;
  const title = boundDialogText(request.title, MAX_DIALOG_TITLE_BYTES);
  if (title.trim() === "") return null;
  switch (request.kind) {
    case "alert":
      return {
        id,
        kind: request.kind,
        title,
        message: boundDialogText(request.message, MAX_DIALOG_MESSAGE_BYTES),
      };
    case "confirm":
      return {
        id,
        kind: request.kind,
        title,
        message: boundDialogText(request.message, MAX_DIALOG_MESSAGE_BYTES),
        confirmLabel: boundDialogText(request.confirmLabel ?? "确定", MAX_DIALOG_TITLE_BYTES),
      };
    case "prompt":
      return {
        id,
        kind: request.kind,
        title,
        message: boundDialogText(request.message, MAX_DIALOG_MESSAGE_BYTES),
        label: boundDialogText(request.label, MAX_DIALOG_TITLE_BYTES),
        value: boundDialogText(request.initialValue, MAX_PROMPT_VALUE_BYTES),
      };
    case "dangerous": {
      const confirmationKey = validateConfirmationKey(request.confirmationKey);
      if (confirmationKey === null) return null;
      return {
        id,
        kind: request.kind,
        title,
        summary: boundDialogText(request.summary, MAX_DIALOG_MESSAGE_BYTES),
        confirmationKey,
      };
    }
  }
}

export function resolveDialog(
  dialog: AppDialog,
  action: DialogAction,
): DialogOutcome | null {
  if (dialog.id !== action.dialogId) return null;
  if (action.type === "cancel") {
    return { kind: "cancelled", dialogId: dialog.id };
  }
  if (dialog.kind === "alert" && action.type === "dismiss-alert") {
    return { kind: "alert-dismissed", dialogId: dialog.id };
  }
  if (dialog.kind === "confirm" && action.type === "approve-confirm") {
    return { kind: "confirmed", dialogId: dialog.id };
  }
  if (dialog.kind === "prompt" && action.type === "submit-prompt") {
    return {
      kind: "prompt-submitted",
      dialogId: dialog.id,
      value: boundDialogText(action.value, MAX_PROMPT_VALUE_BYTES),
    };
  }
  if (
    dialog.kind === "dangerous" &&
    action.type === "approve-dangerous" &&
    action.confirmationKey === dialog.confirmationKey
  ) {
    return {
      kind: "dangerous-approved",
      dialogId: dialog.id,
      confirmationKey: dialog.confirmationKey,
    };
  }
  return null;
}

export function boundDialogText(value: string, maximumBytes: number): string {
  if (encoder.encode(value).byteLength <= maximumBytes) return value;
  let result = "";
  let bytes = 0;
  for (const character of value) {
    const length = encoder.encode(character).byteLength;
    if (bytes + length > maximumBytes) break;
    result += character;
    bytes += length;
  }
  return result;
}

function validateConfirmationKey(value: string): string | null {
  return value.length > 0 &&
    encoder.encode(value).byteLength <= MAX_CONFIRMATION_KEY_BYTES &&
    /^[A-Za-z0-9-]+$/u.test(value)
    ? value
    : null;
}
