import type {
  ApplicationLogFilter,
  ApplicationLogSnapshot,
} from "../shared/application-log-contract";

type LoadStatus = "idle" | "loading" | "ready" | "error";

export interface ApplicationLogState {
  status: LoadStatus;
  request: number | null;
  filter: ApplicationLogFilter;
  snapshot: ApplicationLogSnapshot | null;
  error: string | null;
}

export const initialApplicationLogState: ApplicationLogState = {
  status: "idle",
  request: null,
  filter: { minimumLevel: null, search: "" },
  snapshot: null,
  error: null,
};

export type ApplicationLogAction =
  | { type: "filter-changed"; filter: ApplicationLogFilter }
  | { type: "load-started"; request: number }
  | { type: "load-completed"; request: number; snapshot: ApplicationLogSnapshot }
  | { type: "load-failed"; request: number; error: string }
  | { type: "buffer-cleared"; generation: number };

export function applicationLogReducer(
  state: ApplicationLogState,
  action: ApplicationLogAction,
): ApplicationLogState {
  switch (action.type) {
    case "filter-changed":
      return action.filter.minimumLevel === state.filter.minimumLevel &&
          action.filter.search === state.filter.search
        ? state
        : { ...state, filter: action.filter, error: null };
    case "load-started":
      return { ...state, status: "loading", request: action.request, error: null };
    case "load-completed":
      if (action.request !== state.request) return state;
      return {
        ...state,
        status: "ready",
        request: null,
        snapshot: action.snapshot,
        error: null,
      };
    case "load-failed":
      if (action.request !== state.request) return state;
      return { ...state, status: "error", request: null, error: action.error };
    case "buffer-cleared":
      return {
        ...state,
        status: state.snapshot === null ? "idle" : "ready",
        request: null,
        snapshot: state.snapshot === null ? null : {
          ...state.snapshot,
          totalBuffered: 0,
          totalMatched: 0,
          displayed: 0,
          generation: action.generation,
          entries: [],
        },
        error: null,
      };
  }
}
