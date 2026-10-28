import type {
  DisposalReportContent,
  DisposalReportPreviewFormat,
  DisposalReportSnapshot,
} from "../shared/disposal-report-contract";

type LoadStatus = "idle" | "loading" | "ready" | "error";

export interface DisposalReportState {
  scope: string | null;
  reportStatus: LoadStatus;
  reportRequest: number | null;
  report: DisposalReportSnapshot | null;
  preview: DisposalReportPreviewFormat;
  contentStatus: LoadStatus;
  contentRequest: number | null;
  content: DisposalReportContent | null;
  error: string | null;
}

export const initialDisposalReportState: DisposalReportState = {
  scope: null,
  reportStatus: "idle",
  reportRequest: null,
  report: null,
  preview: "summary",
  contentStatus: "idle",
  contentRequest: null,
  content: null,
  error: null,
};

export type DisposalReportAction =
  | { type: "scope-changed"; scope: string | null }
  | { type: "report-started"; scope: string; request: number }
  | { type: "report-loaded"; scope: string; request: number; report: DisposalReportSnapshot }
  | { type: "report-failed"; scope: string; request: number; error: string }
  | { type: "preview-selected"; preview: DisposalReportPreviewFormat }
  | { type: "content-started"; scope: string; request: number; handle: string; format: DisposalReportPreviewFormat }
  | { type: "content-loaded"; scope: string; request: number; handle: string; content: DisposalReportContent }
  | { type: "content-failed"; scope: string; request: number; handle: string; error: string };

export function disposalReportReducer(
  state: DisposalReportState,
  action: DisposalReportAction,
): DisposalReportState {
  switch (action.type) {
    case "scope-changed":
      return action.scope === state.scope ? state : { ...initialDisposalReportState, scope: action.scope };
    case "report-started":
      if (action.scope !== state.scope) return state;
      return { ...state, reportStatus: "loading", reportRequest: action.request, error: null };
    case "report-loaded":
      if (action.scope !== state.scope || action.request !== state.reportRequest) return state;
      return {
        ...state,
        reportStatus: "ready",
        reportRequest: null,
        report: action.report,
        content: null,
        contentStatus: "idle",
        error: null,
      };
    case "report-failed":
      if (action.scope !== state.scope || action.request !== state.reportRequest) return state;
      return { ...state, reportStatus: "error", reportRequest: null, report: null, error: action.error };
    case "preview-selected":
      // Re-selecting the shown format keeps its text: nothing would load it
      // again, so clearing it here left the preview blank.
      if (action.preview === state.preview) return state;
      return { ...state, preview: action.preview, content: null, contentStatus: "idle", error: null };
    case "content-started":
      if (action.scope !== state.scope || state.report?.handle !== action.handle || state.preview !== action.format) return state;
      return { ...state, contentStatus: "loading", contentRequest: action.request, content: null, error: null };
    case "content-loaded":
      if (action.scope !== state.scope || action.request !== state.contentRequest ||
        state.report?.handle !== action.handle || action.content.format !== state.preview) return state;
      return { ...state, contentStatus: "ready", contentRequest: null, content: action.content };
    case "content-failed":
      if (action.scope !== state.scope || action.request !== state.contentRequest || state.report?.handle !== action.handle) return state;
      return { ...state, contentStatus: "error", contentRequest: null, error: action.error };
  }
}
