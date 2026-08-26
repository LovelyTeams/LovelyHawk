import type { ReactElement } from "react";

import type { ConnectionSummary } from "../shared/contract";
import type { ConnectionManagerIntent } from "./ConnectionManager";

export interface WelcomeViewProps {
  connections: ConnectionSummary[];
  /**
   * Every action opens the connection manager with an intent instead of acting
   * here: the SSH handshake, the editor, and the delete confirmation all stay
   * in the one place that already guards them.
   */
  onConnectionAction: (
    connectionId: string,
    intent: ConnectionManagerIntent,
    returnFocus: HTMLElement,
  ) => void;
  onCreateConnection: (returnFocus: HTMLElement) => void;
}

const ICON_PROPS = {
  viewBox: "0 0 16 16",
  width: 14,
  height: 14,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

function ConnectIcon() {
  return (
    <svg {...ICON_PROPS}>
      <path d="M6.6 9.4 4.4 11.6a2.6 2.6 0 0 1-3.7-3.7l2.2-2.2" />
      <path d="M9.4 6.6l2.2-2.2a2.6 2.6 0 0 1 3.7 3.7l-2.2 2.2" />
      <path d="M6.2 9.8l3.6-3.6" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg {...ICON_PROPS}>
      <path d="M2.4 5.2h11.2M2.4 10.8h11.2" />
      <circle cx="6" cy="5.2" r="1.8" />
      <circle cx="10.4" cy="10.8" r="1.8" />
    </svg>
  );
}

function DeleteIcon() {
  return (
    <svg {...ICON_PROPS}>
      <path d="M2.6 4.2h10.8" />
      <path d="M6.1 4.2V2.9h3.8v1.3" />
      <path d="M3.9 4.2 4.5 13a.9.9 0 0 0 .9.8h5.2a.9.9 0 0 0 .9-.8l.6-8.8" />
      <path d="M6.7 7v4M9.3 7v4" />
    </svg>
  );
}

const ACTIONS: readonly {
  intent: ConnectionManagerIntent;
  label: string;
  className: string;
  Icon: () => ReactElement;
}[] = [
  { intent: "connect", label: "连接", className: "is-connect", Icon: ConnectIcon },
  { intent: "edit", label: "设置", className: "is-edit", Icon: SettingsIcon },
  { intent: "delete", label: "删除", className: "is-delete", Icon: DeleteIcon },
];

/**
 * Disconnected landing view. It only reads bounded connection display data and
 * hands every action to the connection manager.
 */
export function WelcomeView({
  connections,
  onConnectionAction,
  onCreateConnection,
}: WelcomeViewProps) {
  return (
    <div className="page welcome-page" data-testid="welcome-view">
      {/* The banner that used to sit here said the product name back to the
          operator and cost a screenful. What it said that was worth keeping is
          one sentence, so it sits with the list it is about. */}
      <div className="section-heading">
        <div>
          <h2>已保存连接</h2>
          <p>
            先在连接管理中建立一个 SSH 连接，左侧的功能页会随目标一起启用。
            未连接目标时，所有远程采集与处置都保持关闭。
          </p>
        </div>
        <span>{connections.length}</span>
      </div>

      {connections.length === 0 ? (
        <div className="empty-state">
          <p>还没有保存任何连接。</p>
          <button
            type="button"
            className="welcome-create-button"
            onClick={(event) => onCreateConnection(event.currentTarget)}
          >
            新建连接
          </button>
        </div>
      ) : (
        <div className="connection-grid">
          {connections.map((connection) => (
            <div className="connection-card" key={connection.id}>
              <span className="connection-avatar" aria-hidden="true">
                {connection.name.slice(0, 1).toUpperCase()}
              </span>
              <div>
                <strong>{connection.name}</strong>
                <span>{connection.username}@{connection.host}:{connection.port}</span>
              </div>
              <div className="connection-card-actions">
                {ACTIONS.map(({ intent, label, className, Icon }) => (
                  <button
                    key={intent}
                    type="button"
                    className={className}
                    aria-label={`${label} ${connection.name}`}
                    title={label}
                    onClick={(event) => onConnectionAction(connection.id, intent, event.currentTarget)}
                  >
                    <Icon />
                    <span>{label}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
