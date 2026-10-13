import { useEffect, useState } from "react";

import type { PublicLogEntry } from "../shared/log-analysis-read-contract";
import {
  LOG_RULE_LIMITS,
  type LogRuleHit,
  type LogRuleMatches,
  type LogRuleSeverity,
  type LogRulesRequest,
  type LogRulesResponse,
} from "../shared/log-rules-contract";

export interface LogRulesApi {
  logRules(request: LogRulesRequest): Promise<LogRulesResponse>;
}

/** What the saved rules said about one set of lines. */
export interface LogRuleHits {
  hits: readonly (LogRuleHit | null)[];
  ruleCount: number;
  /** True when matching could not be done; the lines are then shown unmarked. */
  failed: boolean;
}

export function logRuleSeverityLabel(severity: LogRuleSeverity): string {
  switch (severity) {
    case "low": return "低";
    case "medium": return "中";
    case "high": return "高";
    case "critical": return "严重";
  }
}

const encoder = new TextEncoder();

/**
 * The text a rule is matched against: the line as the target wrote it, cut to
 * the matching bound. A rule whose match lies past the cut does not fire on
 * that line, which only lines longer than 16 KiB can run into.
 */
export function logRuleLine(entry: PublicLogEntry): string {
  const text = entry.rawText !== ""
    ? entry.rawText
    : [entry.timestamp, entry.level, entry.service, entry.message].filter((part) => part !== "").join(" ");
  if (encoder.encode(text).byteLength <= LOG_RULE_LIMITS.maximumMatchLineBytes) return text;
  let cut = text.slice(0, LOG_RULE_LIMITS.maximumMatchLineBytes);
  while (encoder.encode(cut).byteLength > LOG_RULE_LIMITS.maximumMatchLineBytes) cut = cut.slice(0, -64);
  return cut;
}

/**
 * Matches lines a page already read against the saved rules, in batches the
 * backend takes, and answers only for those lines and that version of the
 * rules — a result for an older page or older rules is never shown.
 */
export function useLogRuleHits(
  api: LogRulesApi,
  entries: readonly PublicLogEntry[] | null,
  rulesVersion: number,
): LogRuleHits | null {
  const [state, setState] = useState<{
    entries: readonly PublicLogEntry[];
    version: number;
    result: LogRuleHits;
  } | null>(null);

  useEffect(() => {
    if (entries === null || entries.length === 0) return undefined;
    let live = true;
    void (async () => {
      const hits: (LogRuleHit | null)[] = [];
      let ruleCount = 0;
      try {
        for (let start = 0; start < entries.length; start += LOG_RULE_LIMITS.maximumMatchLines) {
          const lines = entries.slice(start, start + LOG_RULE_LIMITS.maximumMatchLines).map(logRuleLine);
          const answer = await api.logRules({ action: "match", lines }) as LogRuleMatches;
          if (!live) return;
          hits.push(...answer.matches);
          ruleCount = answer.ruleCount;
          // No rules saved: the remaining batches would say the same.
          if (ruleCount === 0) break;
        }
        if (live) {
          setState({
            entries,
            version: rulesVersion,
            result: { hits: ruleCount === 0 ? entries.map(() => null) : hits, ruleCount, failed: false },
          });
        }
      } catch {
        if (live) setState({ entries, version: rulesVersion, result: { hits: entries.map(() => null), ruleCount: 0, failed: true } });
      }
    })();
    return () => {
      live = false;
    };
  }, [api, entries, rulesVersion]);

  return state !== null && state.entries === entries && state.version === rulesVersion ? state.result : null;
}

/** How many of these lines a rule marked. */
export function logRuleHitCount(hits: LogRuleHits | null): number {
  return hits === null ? 0 : hits.hits.filter((hit) => hit !== null).length;
}
