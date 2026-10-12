import { describe, expect, it } from "vitest";

import type { CommandHistoryListPage, CommandHistoryRecord } from "../shared/command-history-contract";
import {
  type CommandHistoryState,
  commandHistoryReducer,
  initialCommandHistoryState,
} from "./command-history-state";

const page: CommandHistoryListPage = {
  total: 1,
  offset: 0,
  hasMore: false,
  items: [{
    id: "command-1", title: "Inspect", commandPreview: "uname", commandTruncated: false,
    outputPreview: "Linux", outputTruncated: false, timestamp: 1, exitCode: 0,
    status: "succeeded", risk: "read-only", origin: "recorded-command", source: "test",
  }],
};

const detail: CommandHistoryRecord = {
  id: "command-1", title: "Inspect", command: "uname", output: "Linux", timestamp: 1,
  exitCode: 0, status: "succeeded", risk: "read-only", origin: "recorded-command", source: "test", rerunnable: false,
};

describe("command history reducer", () => {
  it("drops late list results after the binding scope changes", () => {
    let state = commandHistoryReducer(initialCommandHistoryState, { type: "scope-changed", scope: "binding-a" });
    state = commandHistoryReducer(state, { type: "list-started", scope: "binding-a", request: 1 });
    state = commandHistoryReducer(state, { type: "scope-changed", scope: "binding-b" });
    expect(commandHistoryReducer(state, { type: "list-loaded", scope: "binding-a", request: 1, page })).toBe(state);
  });

  it("drops stale detail and replay results after selection changes", () => {
    let state: CommandHistoryState = {
      ...initialCommandHistoryState,
      scope: "binding-a",
      selectedId: "command-1",
    };
    state = commandHistoryReducer(state, { type: "detail-started", scope: "binding-a", request: 2, id: "command-1" });
    state = commandHistoryReducer(state, { type: "record-selected", id: "command-2" });
    expect(commandHistoryReducer(state, {
      type: "detail-loaded", scope: "binding-a", request: 2, id: "command-1", record: detail,
    })).toBe(state);
  });

  it("keeps the shown record when its own row is picked again", () => {
    let state: CommandHistoryState = {
      ...initialCommandHistoryState,
      scope: "binding-a",
      selectedId: "command-1",
    };
    state = commandHistoryReducer(state, { type: "detail-started", scope: "binding-a", request: 2, id: "command-1" });
    state = commandHistoryReducer(state, {
      type: "detail-loaded", scope: "binding-a", request: 2, id: "command-1", record: detail,
    });
    // The detail only reloads when the selection changes, so clearing it here
    // used to leave the panel blank.
    expect(commandHistoryReducer(state, { type: "record-selected", id: "command-1" })).toBe(state);
    expect(state.record).toEqual(detail);
  });

  it("preserves selection when refreshed page still contains the record", () => {
    let state: CommandHistoryState = {
      ...initialCommandHistoryState,
      scope: "binding-a",
      selectedId: "command-1",
      listRequest: 3,
    };
    state = commandHistoryReducer(state, { type: "list-loaded", scope: "binding-a", request: 3, page });
    expect(state.selectedId).toBe("command-1");
  });
});
