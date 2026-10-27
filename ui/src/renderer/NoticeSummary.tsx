import { createContext, useContext, useEffect, useRef, type ReactNode } from "react";
import { NotificationContext, NotificationOpenContext } from "./NotificationCenter";
import type { NotificationSeverity } from "./notification-state";

/** The identity belongs to the displayed snapshot, including when it is offline. */
export const NoticeScopeContext = createContext({ key: "", label: "" });

export function NoticeSummary({ source, messages, summary, severity = "warning", stamp = "", announce = true, inline = false, reportOnly = false, children }: {
  source: string; messages: readonly string[]; summary: string; severity?: NotificationSeverity | undefined;
  stamp?: string | undefined; announce?: boolean | undefined; inline?: boolean | undefined; reportOnly?: boolean; children?: ReactNode;
}) {
  const publish = useContext(NotificationContext);
  const open = useContext(NotificationOpenContext);
  const scope = useContext(NoticeScopeContext);
  const previous = useRef("");
  const body = messages.filter(Boolean).join("\n");
  // Stable across Activity hide/show. A new collection can report the same gap again.
  const identity = `${scope.key}\0${source}\0${stamp}\0${body}`;
  const report = () => {
    if (!publish || !body) return;
    const prefix = [scope.label, stamp ? `采集于 ${stamp}` : ""].filter(Boolean).join(" · ");
    // Keep each record within the center's text bound without losing later warnings.
    const parts: string[] = [];
    let part = prefix;
    for (const line of messages.filter(Boolean)) {
      for (let offset = 0; offset < line.length; offset += 2800) {
        const text = line.slice(offset, offset + 2800);
        if (part.length + text.length > 3500) { parts.push(part); part = prefix; }
        part += `${part ? "\n" : ""}${text}`;
      }
    }
    if (part) parts.push(part);
    parts.forEach((message, index) => publish(source, message, severity, `${scope.key}:${source}:${stamp}:${index}`));
  };
  useEffect(() => {
    if (publish && announce && body && previous.current !== identity) { previous.current = identity; report(); }
  }, [identity, announce, body, publish]); // report uses the current, immutable notice text
  if (!body || reportOnly) return null;
  // A modal's focus trap must not compete with the main notification dialog.
  // Its compact disclosure keeps details readable there; the same notice is also archived.
  return <div className={`notice-summary is-${severity}`} role={severity === "error" ? "alert" : undefined}>
    {publish && open && !inline ? <button type="button" className="notice-summary-link" aria-haspopup="dialog" onClick={() => { report(); open(); }}>{summary} <span aria-hidden="true">↗</span></button>
      : <details className="notice-summary-disclosure"><summary tabIndex={0}>{summary}</summary><ul>{messages.filter(Boolean).map((message, index) => <li key={index}>{message}</li>)}</ul></details>}
    {children}
  </div>;
}
