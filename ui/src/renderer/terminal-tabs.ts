import type {
  TerminalApi,
  TerminalClosed,
  TerminalSessionApi,
} from "../shared/terminal-contract";

/** One tab's shell, plus the number the host gave it once it opened. */
export interface TerminalTabSession extends TerminalSessionApi {
  readonly tab: string | null;
}

/**
 * One tab's shell over the window's API.
 *
 * The window's first tab opens the window's own shell; later tabs open beside
 * it. Once open, every call names the tab the host gave back, and closing
 * closes only that tab — the terminal view and its controller never learn
 * there are other tabs, and the window stays until its last tab goes.
 */
export function terminalTabSession(api: TerminalApi, first: boolean): TerminalTabSession {
  let tab: string | null = null;
  const opened = (): string => {
    if (tab === null) throw new Error("这个终端标签页还没有打开。");
    return tab;
  };
  return {
    get tab() {
      return tab;
    },
    async open(columns, rows) {
      if (tab !== null) throw new Error("Invalid terminal open request.");
      const result = await (first ? api.open(columns, rows) : api.openTab(columns, rows));
      tab = result.tab;
      return { columns: result.columns, rows: result.rows };
    },
    poll: (maximumEvents, maximumBytes) => api.poll(opened(), maximumEvents, maximumBytes),
    input: (bytesBase64) => api.input(opened(), bytesBase64),
    resize: (columns, rows) => api.resize(opened(), columns, rows),
    search: (query, caseSensitive, regex, maximumResults) =>
      api.search(opened(), query, caseSensitive, regex, maximumResults),
    async close(): Promise<TerminalClosed> {
      // A tab that never opened holds nothing on the host to close.
      if (tab === null) return { closed: true };
      return api.closeTab(tab);
    },
  };
}
