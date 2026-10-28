import type { ReactElement } from "react";

import type { ConnectionSummary, PageDescriptor } from "../shared/contract";
import type { ConnectionManagerIntent } from "./ConnectionManager";
import { NavIcon } from "./nav-icons";

export interface WelcomeViewProps {
  connections: ConnectionSummary[];
  /**
   * Why the saved connections could not be read, when they could not. The
   * list is then unknown, not empty, and must not be shown as empty.
   */
  connectionsError?: string | null;
  /** Pages that work with nothing connected, offered as a second way in. */
  offlinePages?: readonly PageDescriptor[];
  onNavigate?: (pageId: string) => void;
  onOpenWindowsIncident?: () => void;
  onOpenConnections?: (returnFocus: HTMLElement) => void;
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
  /** "Now", for how long ago a connection was last used; tests pin it. */
  now?: Date;
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

function ArrowIcon() {
  return (
    <svg {...ICON_PROPS}>
      <path d="M3 8h10M9 4l4 4-4 4" />
    </svg>
  );
}

function ServerIcon() {
  return (
    <svg {...ICON_PROPS} width={16} height={16}>
      <rect x="2.2" y="2.4" width="11.6" height="4.4" rx="1.2" />
      <rect x="2.2" y="9.2" width="11.6" height="4.4" rx="1.2" />
      <path d="M4.8 4.6h.01M4.8 11.4h.01" />
    </svg>
  );
}

/**
 * A terminal window with a plus badge and a few sparkles, drawn in the
 * theme's colours: decoration only, hidden from assistive technology.
 */
function StartIllustration() {
  return (
    <svg className="welcome-illustration" viewBox="0 0 240 120" width="240" height="120" aria-hidden="true">
      <path className="welcome-illustration-line" d="M18 86h56" />
      <circle className="welcome-illustration-dot" cx="64" cy="22" r="2.5" />
      <circle className="welcome-illustration-dot" cx="196" cy="70" r="3" />
      <path className="welcome-illustration-spark" d="M178 22l3 8 8 3-8 3-3 8-3-8-8-3 8-3z" />
      <rect className="welcome-illustration-back" x="84" y="14" width="84" height="20" rx="7" />
      <rect className="welcome-illustration-card" x="78" y="24" width="96" height="74" rx="12" />
      <path className="welcome-illustration-prompt" d="M100 52l10 8-10 8M118 70h20" />
      <circle className="welcome-illustration-badge" cx="172" cy="94" r="12" />
      <path className="welcome-illustration-plus" d="M172 88v12M166 94h12" />
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

/** Systems the connection step recognises by name; others are probed by capability. */
const RECOGNISED_SYSTEMS: readonly string[] = [
  "Debian", "Ubuntu", "RHEL", "Rocky", "AlmaLinux", "SUSE", "Alpine",
  "openEuler", "Anolis", "统信 UOS", "麒麟", "deepin",
];

const WINDOWS_CAPABILITIES: readonly string[] = [
  "主机总览",
  "基线配置",
  "进程查看",
  "网络连接",
  "启动项",
  "本地账户",
  "事件日志",
  "文件排查",
  "注册表",
];

/**
 * When a connection was last used, in the operator's own clock: today and
 * yesterday by name, this year by month and day, older ones by year.
 */
export function lastConnectedLabel(value: string | null, now: Date = new Date()): string {
  if (value === null) return "还没有连接过";
  const at = new Date(value);
  if (Number.isNaN(at.getTime())) return "时间无法识别";
  const pad = (part: number) => String(part).padStart(2, "0");
  const time = `${pad(at.getHours())}:${pad(at.getMinutes())}`;
  const day = (date: Date) => new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
  const days = Math.round((day(now) - day(at)) / 86_400_000);
  if (days === 0) return `今天 ${time}`;
  if (days === 1) return `昨天 ${time}`;
  if (at.getFullYear() === now.getFullYear()) return `${pad(at.getMonth() + 1)}-${pad(at.getDate())} ${time}`;
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
}

/** Most recently used first; never-used ones after, by name. */
export function welcomeConnectionOrder(connections: readonly ConnectionSummary[]): ConnectionSummary[] {
  const time = (connection: ConnectionSummary) => {
    const value = connection.lastConnectedAt === null ? Number.NaN : Date.parse(connection.lastConnectedAt);
    return Number.isNaN(value) ? Number.NEGATIVE_INFINITY : value;
  };
  return [...connections].sort((a, b) => time(b) - time(a) || a.name.localeCompare(b.name, "zh-CN"));
}

/**
 * Disconnected landing view. It only reads bounded connection display data and
 * hands every action to the connection manager.
 */
export function WelcomeView({
  connections,
  connectionsError = null,
  offlinePages = [],
  onNavigate,
  onOpenWindowsIncident,
  onOpenConnections,
  onConnectionAction,
  onCreateConnection,
  now,
}: WelcomeViewProps) {
  const ordered = welcomeConnectionOrder(connections);
  const enterWindows = () => {
    if (onOpenWindowsIncident !== undefined) {
      onOpenWindowsIncident();
    } else if (onNavigate !== undefined) {
      onNavigate("windows-incident");
    }
  };
  return (
    <div className="page welcome-page" data-testid="welcome-view">
      <div className="welcome-inner">
        <header className="welcome-hero">
          <img className="welcome-hero-logo" src="./logo.png" alt="" />
          <div>
            <p className="welcome-hero-title">LovelyHawk<span aria-hidden="true">.</span></p>
            <p className="welcome-hero-subtitle">Windows &amp; Linux 应急响应 / 运维工作台</p>
          </div>
        </header>

        <div className="welcome-platform-banner">
          <section
            className="welcome-card welcome-platform-card"
            aria-labelledby="welcome-windows-title"
          >
            <div className="welcome-platform-body">
              <div>
                <span className="welcome-platform-tag">独立工作台 · RDP 动态虚拟通道</span>
                <h2 id="welcome-windows-title">Windows 应急响应</h2>
                <p className="welcome-start-hint">
                  通过远程桌面虚拟通道连接被检 Windows 会话，进入独立的 Windows 应急响应工作台。
                </p>
                <ul className="welcome-systems welcome-windows-Caps" aria-label="Windows 应急响应功能">
                  {WINDOWS_CAPABILITIES.map((cap) => (
                    <li key={cap}>{cap}</li>
                  ))}
                </ul>
              </div>
              <div className="welcome-platform-cta">
                <button
                  type="button"
                  className="welcome-windows-button"
                  data-testid="welcome-enter-windows"
                  onClick={enterWindows}
                >
                  <span>进入 Windows 应急响应</span>
                  <ArrowIcon />
                </button>
              </div>
            </div>
          </section>
        </div>

        <div className="welcome-grid">
          <section className="welcome-card welcome-start" aria-labelledby="welcome-intro-title">
            <StartIllustration />
            <span className="welcome-platform-tag">Linux 应急响应模块 · SSH / SFTP</span>
            <h1 id="welcome-intro-title">开始一次应急响应</h1>
            <p className="welcome-start-label">能自动识别的系统</p>
            <ul className="welcome-systems" aria-label="能自动识别的系统">
              {RECOGNISED_SYSTEMS.map((system) => <li key={system}>{system}</li>)}
            </ul>
            <p className="welcome-start-hint">其他 Linux 也能连接，按探测到的工具和权限选择做法。</p>
            <div className="welcome-start-actions">
              <button
                type="button"
                className="welcome-create-button"
                onClick={(event) => onCreateConnection(event.currentTarget)}
              >
                <span>新建连接</span>
                <ArrowIcon />
              </button>
              {onOpenConnections === undefined ? null : (
                <button
                  type="button"
                  className="welcome-secondary-button"
                  data-testid="welcome-open-connections"
                  onClick={(event) => onOpenConnections(event.currentTarget)}
                >
                  管理与导入连接
                </button>
              )}
            </div>
          </section>

          <section className="welcome-card welcome-recent" aria-labelledby="welcome-recent-title">
            <header className="welcome-recent-head">
              <h2 id="welcome-recent-title">已保存连接</h2>
              <span>{connectionsError !== null ? "读取失败" : connections.length === 0 ? "还没有" : `共 ${connections.length} 个 · 最近连接的在前`}</span>
            </header>
            {connectionsError !== null ? (
              <div className="empty-state" role="alert">
                <p>{connectionsError}</p>
                <p className="empty-state-hint">其他不需要连接的工具仍可使用。处理好连接文件后，在连接管理中点“刷新”重新读取。</p>
              </div>
            ) : connections.length === 0 ? (
              <div className="empty-state">
                <ServerIcon />
                <p>还没有保存任何连接。</p>
                <p className="empty-state-hint">点左边的“新建连接”填写主机与账号，或在连接管理中导入已有的连接 JSON。</p>
              </div>
            ) : (
              <ul className="welcome-connection-list">
                {ordered.map((connection) => (
                  <li className="connection-card" key={connection.id}>
                    <span className="connection-avatar" aria-hidden="true"><ServerIcon /></span>
                    <div>
                      <strong>{connection.name}</strong>
                      <span>{connection.username}@{connection.host}:{connection.port}</span>
                      <small>{lastConnectedLabel(connection.lastConnectedAt, now)}</small>
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
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>

        {offlinePages.length === 0 || onNavigate === undefined ? null : (
          <section className="welcome-offline" aria-labelledby="welcome-offline-title"
            title="这些工具只读写本机数据，适合赛前准备、整理案件和查资料。">
            <h2 id="welcome-offline-title">不连接也能用</h2>
            <div className="welcome-tools">
              {offlinePages.map((page) => (
                <button
                  key={page.id}
                  type="button"
                  className="welcome-tool"
                  data-testid={`welcome-tool-${page.id}`}
                  title={page.summary}
                  onClick={() => onNavigate(page.id)}
                >
                  <span className="welcome-tool-icon"><NavIcon pageId={page.id} glyph={page.icon} /></span>
                  <span>{page.title}</span>
                </button>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
