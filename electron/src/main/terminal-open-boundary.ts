import { isTerminalSelectionCopyText } from "../shared/terminal-contract.js";

const TERMINAL_OPEN_FAILURE = "Unable to open the bound SSH terminal.";

export function isTerminalSelectionCopyRequest(
  terminalIsOpen: boolean,
  values: unknown[],
): values is [string] {
  return terminalIsOpen && values.length === 1 && isTerminalSelectionCopyText(values[0]);
}

export async function openTerminalWithFailureCleanup<T>(
  open: () => Promise<T>,
  closeContext: () => Promise<void>,
): Promise<T> {
  try {
    return await open();
  } catch {
    await closeContext().catch(() => undefined);
    throw new Error(TERMINAL_OPEN_FAILURE);
  }
}
