import type {
  AiHistoryListPage,
  AiHistoryMutationProposal,
  AiHistoryRecord,
} from "../shared/ai-history-contract";

export type AiHistoryLoadStatus = "idle" | "loading" | "ready" | "error";

export interface AiHistoryState {
  query: string;
  offset: number;
  listStatus: AiHistoryLoadStatus;
  page: AiHistoryListPage | null;
  listRequest: number;
  selectedId: string | null;
  detailStatus: AiHistoryLoadStatus;
  record: AiHistoryRecord | null;
  detailRequest: number;
  error: string | null;
  proposal: AiHistoryMutationProposal | null;
  proposalRequest: number;
}

export type AiHistoryAction =
  | { type: "query-changed"; query: string }
  | { type: "page-selected"; offset: number }
  | { type: "list-started"; request: number }
  | { type: "list-loaded"; request: number; page: AiHistoryListPage }
  | { type: "list-failed"; request: number; error: string }
  | { type: "record-selected"; id: string }
  | { type: "detail-started"; request: number; id: string }
  | { type: "detail-loaded"; request: number; id: string; record: AiHistoryRecord }
  | { type: "detail-failed"; request: number; id: string; error: string }
  | { type: "proposal-started"; request: number }
  | { type: "proposal-loaded"; request: number; proposal: AiHistoryMutationProposal }
  | { type: "proposal-failed"; request: number; error: string }
  | { type: "proposal-closed" };

export function createAiHistoryState(): AiHistoryState {
  return {
    query: "",
    offset: 0,
    listStatus: "idle",
    page: null,
    listRequest: 0,
    selectedId: null,
    detailStatus: "idle",
    record: null,
    detailRequest: 0,
    error: null,
    proposal: null,
    proposalRequest: 0,
  };
}

export function aiHistoryReducer(state: AiHistoryState, action: AiHistoryAction): AiHistoryState {
  switch (action.type) {
    case "query-changed":
      return action.query === state.query
        ? state
        : { ...state, query: action.query, offset: 0, page: null, listStatus: "idle", error: null };
    case "page-selected":
      return action.offset === state.offset
        ? state
        : { ...state, offset: action.offset, page: null, listStatus: "idle", error: null };
    case "list-started":
      return { ...state, listRequest: action.request, listStatus: "loading", error: null };
    case "list-loaded": {
      if (action.request !== state.listRequest) return state;
      const selectedId = state.selectedId !== null &&
        action.page.items.some((item) => item.id === state.selectedId)
        ? state.selectedId
        : (action.page.items[0]?.id ?? null);
      return {
        ...state,
        listStatus: "ready",
        page: action.page,
        selectedId,
        detailStatus: selectedId === state.selectedId ? state.detailStatus : "idle",
        record: selectedId === state.selectedId ? state.record : null,
        error: null,
      };
    }
    case "list-failed":
      return action.request === state.listRequest
        ? { ...state, listStatus: "error", page: null, error: action.error }
        : state;
    case "record-selected":
      return action.id === state.selectedId
        ? state
        : { ...state, selectedId: action.id, detailStatus: "idle", record: null, error: null };
    case "detail-started":
      return action.id === state.selectedId
        ? { ...state, detailRequest: action.request, detailStatus: "loading", record: null, error: null }
        : state;
    case "detail-loaded":
      return action.request === state.detailRequest && action.id === state.selectedId &&
        action.record.id === action.id
        ? { ...state, detailStatus: "ready", record: action.record, error: null }
        : state;
    case "detail-failed":
      return action.request === state.detailRequest && action.id === state.selectedId
        ? { ...state, detailStatus: "error", record: null, error: action.error }
        : state;
    case "proposal-started":
      return { ...state, proposalRequest: action.request, error: null };
    case "proposal-loaded":
      return action.request === state.proposalRequest
        ? { ...state, proposal: action.proposal, error: null }
        : state;
    case "proposal-failed":
      return action.request === state.proposalRequest
        ? { ...state, proposal: null, error: action.error }
        : state;
    case "proposal-closed":
      return state.proposal === null ? state : { ...state, proposal: null };
  }
}
