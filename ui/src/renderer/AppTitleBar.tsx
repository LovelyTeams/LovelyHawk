import { WindowControls } from "./WindowControls";

/**
 * Window-level actions rendered as icons in the custom title bar. They stay a
 * fixed, named set that the debug probe asserts exactly; the window's own
 * minimize/maximize/close buttons sit after them, in their own group.
 */
export interface AppTitleBarActions {
  onOpenConnections: (returnFocus: HTMLElement) => void;
  sshTerminalDisabled: boolean;
  onOpenSshTerminal: () => void;
  onOpenCommandHistory: (returnFocus: HTMLElement) => void;
  onOpenSettings: (returnFocus: HTMLElement) => void;
}

export interface AppTitleBarProps {
  section: string;
  backgroundHidden?: boolean;
  /** Omitted on the startup and failure screens, which have no app actions. */
  actions?: AppTitleBarActions;
}

const ICON_PROPS = {
  viewBox: "0 0 16 16",
  width: 15,
  height: 15,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.5,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
  "aria-hidden": true,
};

function ConnectionsIcon() {
  return (
    <svg {...ICON_PROPS}>
      <rect x="1.8" y="2.6" width="12.4" height="4.2" rx="1.4" />
      <rect x="1.8" y="9.2" width="12.4" height="4.2" rx="1.4" />
      <path d="M4.4 4.7h.01M4.4 11.3h.01" />
    </svg>
  );
}

function TerminalIcon() {
  return (
    <svg {...ICON_PROPS}>
      <rect x="1.8" y="2.8" width="12.4" height="10.4" rx="2" />
      <path d="m4.9 6.6 1.9 1.7-1.9 1.7" />
      <path d="M9.1 10.4h2.6" />
    </svg>
  );
}

function HistoryIcon() {
  return (
    <svg {...ICON_PROPS}>
      <path d="M8 4.8v3.4l2.2 1.3" />
      <path d="M2.6 8a5.4 5.4 0 1 0 1.7-3.9" />
      <path d="M2.3 2.9v2.5h2.5" />
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

export function AppTitleBar({ section, backgroundHidden = false, actions }: AppTitleBarProps) {
  return (
    <header
      className="window-titlebar"
      data-testid="window-titlebar"
      data-tauri-drag-region="deep"
      aria-label="窗口标题栏"
      aria-hidden={backgroundHidden ? true : undefined}
    >
      <div className="window-titlebar-brand">
        <img src="./logo.png" alt="" />
        <strong>LovelyHawk</strong>
        <span aria-hidden="true" />
        <small>{section}</small>
      </div>
      {actions === undefined ? null : (
        <div className="window-titlebar-actions">
          <button
            type="button"
            data-testid="open-connections"
            aria-label="连接管理"
            title="连接管理"
            onClick={(event) => actions.onOpenConnections(event.currentTarget)}
          >
            <ConnectionsIcon />
          </button>
          <button
            type="button"
            data-testid="open-ssh-terminal"
            aria-label="SSH 终端"
            title="SSH 终端"
            disabled={actions.sshTerminalDisabled}
            onClick={() => actions.onOpenSshTerminal()}
          >
            <TerminalIcon />
          </button>
          <button
            type="button"
            data-testid="open-command-history"
            aria-label="命令历史"
            title="命令历史"
            onClick={(event) => actions.onOpenCommandHistory(event.currentTarget)}
          >
            <HistoryIcon />
          </button>
          <button
            type="button"
            data-testid="open-settings"
            aria-label="设置"
            title="设置"
            onClick={(event) => actions.onOpenSettings(event.currentTarget)}
          >
            <SettingsIcon />
          </button>
        </div>
      )}
      <WindowControls />
    </header>
  );
}
