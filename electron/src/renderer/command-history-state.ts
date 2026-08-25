import type {
  CommandHistoryListPage,
  CommandHistoryMutationProposal,
  CommandHistoryRecord,
  CommandReplayIntent,
} from "../shared/command-history-contract";

type LoadStatus = "idle" | "loading" | "ready" | "error";

export interface CommandHistoryState {
  scope: string | null;
  query: string;
  offset: number;
  listStatus: LoadStatus;
  page: CommandHistoryListPage | null;
  selectedId: string | null;
  detailStatus: LoadStatus;
  record: CommandHistoryRecord | null;
  replayStatus: LoadStatus;
  replayIntent: CommandReplayIntent | null;
  replayRequest: number | null;
  proposalRequest: number | null;
  proposal: CommandHistoryMutationProposal | null;
  error: string | null;
  listRequest: number | null;
  detailRequest: number | null;
}

export const initialCommandHistoryState: CommandHistoryState = {
  scope: null,
  query: "",
  offset: 0,
  listStatus: "idle",
  page: null,
  selectedId: null,
  detailStatus: "idle",
  record: null,
  replayStatus: "idle",
  replayIntent: null,
  replayRequest: null,
  proposalRequest: null,
  proposal: null,
  error: null,
  listRequest: null,
  detailRequest: null,
};

export type CommandHistoryAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "query-changed"; query: string }
  | { type: "page-selected"; offset: number }
  | { type: "record-selected"; id: string }
  | { type: "list-started"; scope: string; request: number }
  | { type: "list-loaded"; scope: string; request: number; page: CommandHistoryListPage }
  | { type: "list-failed"; scope: string; request: number; error: string }
  | { type: "detail-started"; scope: string; request: number; id: string }
  | { type: "detail-loaded"; scope: string; request: number; id: string; record: CommandHistoryRecord }
  | { type: "detail-failed"; scope: string; request: number; id: string; error: string }
  | { type: "replay-started"; scope: string; request: number; id: string }
  | { type: "replay-loaded"; scope: string; request: number; id: string; intent: CommandReplayIntent }
  | { type: "replay-failed"; scope: string; request: number; id: string; error: string }
  | { type: "proposal-started"; scope: string; request: number }
  | { type: "proposal-loaded"; scope: string; request: number; proposal: CommandHistoryMutationProposal }
  | { type: "proposal-failed"; scope: string; request: number; error: string }
  | { type: "proposal-closed" };

export function commandHistoryReducer(
  state: CommandHistoryState,
  action: CommandHistoryAction,
): CommandHistoryState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...initialCommandHistoryState, scope: action.scope };
    case "query-changed":
      return { ...state, query: action.query, offset: 0, page: null, selectedId: null, record: null, error: null };
    case "page-selected":
      return { ...state, offset: action.offset, page: null, selectedId: null, record: null, error: null };
    case "record-selected":
      return { ...state, selectedId: action.id, record: null, detailStatus: "idle", replayIntent: null };
    case "list-started":
      if (action.scope !== state.scope) return state;
      return { ...state, listStatus: "loading", listRequest: action.request, error: null };
    case "list-loaded": {
      if (action.scope !== state.scope || action.request !== state.listRequest) return state;
      const selectedId = state.selectedId !== null && action.page.items.some((item) => item.id === state.selectedId)
        ? state.selectedId
        : action.page.items[0]?.id ?? null;
      return { ...state, listStatus: "ready", listRequest: null, page: action.page, selectedId };
    }
    case "list-failed":
      if (action.scope !== state.scope || action.request !== state.listRequest) return state;
      return { ...state, listStatus: "error", listRequest: null, error: action.error };
    case "detail-started":
      if (action.scope !== state.scope || action.id !== state.selectedId) return state;
      return { ...state, detailStatus: "loading", detailRequest: action.request, record: null };
    case "detail-loaded":
      if (action.scope !== state.scope || action.request !== state.detailRequest || action.id !== state.selectedId) return state;
      return { ...state, detailStatus: "ready", detailRequest: null, record: action.record };
    case "detail-failed":
      if (action.scope !== state.scope || action.request !== state.detailRequest || action.id !== state.selectedId) return state;
      return { ...state, detailStatus: "error", detailRequest: null, error: action.error };
    case "replay-started":
      if (action.scope !== state.scope || action.id !== state.selectedId) return state;
      return { ...state, replayStatus: "loading", replayIntent: null, replayRequest: action.request };
    case "replay-loaded":
      if (action.scope !== state.scope || action.request !== state.replayRequest || action.id !== state.selectedId) return state;
      return { ...state, replayStatus: "ready", replayIntent: action.intent, replayRequest: null };
    case "replay-failed":
      if (action.scope !== state.scope || action.request !== state.replayRequest || action.id !== state.selectedId) return state;
      return { ...state, replayStatus: "error", replayRequest: null, error: action.error };
    case "proposal-started":
      if (action.scope !== state.scope) return state;
      return { ...state, proposalRequest: action.request, error: null };
    case "proposal-loaded":
      if (action.scope !== state.scope || action.request !== state.proposalRequest) return state;
      return { ...state, proposalRequest: null, proposal: action.proposal };
    case "proposal-failed":
      if (action.scope !== state.scope || action.request !== state.proposalRequest) return state;
      return { ...state, proposalRequest: null, error: action.error };
    case "proposal-closed":
      return { ...state, proposal: null, proposalRequest: null };
  }
}
