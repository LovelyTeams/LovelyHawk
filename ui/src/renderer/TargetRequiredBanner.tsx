import type { ReactNode } from "react";

import type { ConnectionSummary } from "../shared/contract";

export interface TargetRequiredBannerProps {
  pageTitle: string;
  /** What the page does, from its descriptor. */
  summary?: string;
  /** What the page shows once connected, from its descriptor. */
  sections?: readonly string[];
  icon?: ReactNode;
  connections: readonly ConnectionSummary[];
  onConnect: (connectionId: string | null, returnFocus: HTMLElement) => void;
}

const QUICK_CONNECTIONS = 3;

/** Most recently used first; never-used connections keep their saved order. */
export function quickConnections(connections: readonly ConnectionSummary[]): ConnectionSummary[] {
  return connections
    .map((connection, index) => ({ connection, index }))
    .sort((left, right) => {
      const a = left.connection.lastConnectedAt ?? "";
      const b = right.connection.lastConnectedAt ?? "";
      return a === b ? left.index - right.index : a < b ? 1 : -1;
    })
    .slice(0, QUICK_CONNECTIONS)
    .map(({ connection }) => connection);
}

/**
 * The whole page while it waits for a target: what it is for, what it will
 * show, and the way to connect, in one place. Pages used to add their own
 * "connect first" box under a banner saying the same thing; the page now stays
 * mounted but hidden until a target is connected (App.tsx), so its own state
 * and any unsaved edit are kept. Connecting still goes through the connection
 * manager, which owns the host-key and sign-in prompts.
 */
export function TargetRequiredBanner({ pageTitle, summary, sections = [], icon, connections, onConnect }: TargetRequiredBannerProps) {
  const recent = quickConnections(connections);
  return (
    <section className="content-connect-action" role="region" aria-label={`${pageTitle}：需要连接目标`}>
      <header className="content-connect-head">
        {icon === undefined ? null : <span className="content-connect-icon" aria-hidden="true">{icon}</span>}
        <div>
          <h1>{pageTitle}</h1>
          {summary === undefined || summary === "" ? null : <p>{summary}</p>}
        </div>
      </header>
      {sections.length === 0 ? null : (
        <div className="content-connect-features">
          <span>连接后可以使用</span>
          <ul>{sections.map((section) => <li key={section}>{section}</li>)}</ul>
        </div>
      )}
      <div className="content-connect-message">
        <strong>「{pageTitle}」需要先连接一台 SSH 目标</strong>
        <span>
          {recent.length === 0
            ? "还没有保存的连接，先新建一个。连接前不会对任何主机执行操作。"
            : "选择一个最近用过的连接，或打开连接管理。连接前会核对主机密钥，不会对主机执行任何操作。"}
        </span>
      </div>
      <div className="content-connect-buttons">
        <button
          type="button"
          className="content-connect-primary"
          data-testid="content-connect-target"
          onClick={(event) => onConnect(null, event.currentTarget)}
        >
          {recent.length === 0 ? "新建连接" : "连接目标"}
        </button>
        {recent.map((connection) => (
          <button
            key={connection.id}
            type="button"
            className="content-connect-recent"
            title={`${connection.username}@${connection.host}:${connection.port}`}
            onClick={(event) => onConnect(connection.id, event.currentTarget)}
          >
            {connection.name}
          </button>
        ))}
      </div>
    </section>
  );
}
