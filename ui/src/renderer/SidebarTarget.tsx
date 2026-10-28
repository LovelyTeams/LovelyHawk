import type { SshTargetSummary } from "../shared/ssh-contract";

export interface SidebarTargetProps {
  target: SshTargetSummary | null;
  disconnecting: boolean;
  onConnect: (returnFocus: HTMLElement) => void;
  onOpenTerminal: () => void;
  onDisconnect: () => void;
  /** Shown here only while the status bar, its usual home, is hidden. */
  error?: string | null;
}

/**
 * Which machine every target page is looking at, kept at the top of the
 * navigation so it is never more than a glance away — and the one place to
 * connect, open its shell, or let it go.
 */
export function SidebarTarget({ target, disconnecting, onConnect, onOpenTerminal, onDisconnect, error = null }: SidebarTargetProps) {
  const alert = error === null ? null : <p className="sidebar-target-error" role="alert">{error}</p>;
  if (target === null) {
    return (
      <section className="sidebar-target is-idle" aria-label="当前目标" data-testid="sidebar-target">
        <div className="sidebar-target-state">
          <span className="status-dot idle" aria-hidden="true" />
          <span>未连接目标</span>
        </div>
        <p>连接一台主机后，左侧的采集与处置页面随之启用。</p>
        <button
          type="button"
          className="sidebar-target-primary"
          data-testid="sidebar-connect-target"
          onClick={(event) => onConnect(event.currentTarget)}
        >
          连接目标
        </button>
        {alert}
      </section>
    );
  }
  const label = `${target.username}@${target.host}:${target.port}`;
  return (
    <section className="sidebar-target" aria-label="当前目标" data-testid="sidebar-target">
      <div className="sidebar-target-state">
        <span className="status-dot" aria-hidden="true" />
        <span>已连接</span>
      </div>
      <strong title={label}>{label}</strong>
      <div className="sidebar-target-actions">
        <button type="button" data-testid="sidebar-open-terminal" onClick={onOpenTerminal}>终端</button>
        <button
          type="button"
          className="is-danger"
          data-testid="sidebar-disconnect-target"
          disabled={disconnecting}
          onClick={onDisconnect}
        >
          {disconnecting ? "断开中…" : "断开"}
        </button>
      </div>
      {alert}
    </section>
  );
}
