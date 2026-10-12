import { useEffect, useState } from "react";

const ICON_PROPS = {
  viewBox: "0 0 12 12",
  width: 12,
  height: 12,
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.1,
  "aria-hidden": true,
};

/**
 * Minimize, maximize and close for a window without a system frame.
 *
 * Every window draws these at the right end of its own title bar. Closing the
 * main window still asks the page first (unsaved edits, running work), so the
 * close button is a request, not a guarantee. A child window with edits of
 * its own passes `onClose` to ask before it goes.
 */
export function WindowControls({ onClose }: { onClose?: () => void } = {}) {
  const chrome = typeof window === "undefined" ? undefined : window.lovelyhawkWindow;
  const [maximized, setMaximized] = useState(false);
  useEffect(() => chrome?.onMaximizedChange(setMaximized), [chrome]);
  if (chrome === undefined) return null;
  return (
    <div className="window-controls" role="group" aria-label="窗口控制" data-testid="window-controls">
      <button
        type="button"
        data-testid="window-minimize"
        aria-label="最小化"
        title="最小化"
        onClick={() => void chrome.minimize()}
      >
        <svg {...ICON_PROPS}><path d="M1.5 6h9" /></svg>
      </button>
      <button
        type="button"
        data-testid="window-maximize"
        aria-label={maximized ? "向下还原" : "最大化"}
        title={maximized ? "向下还原" : "最大化"}
        onClick={() => void chrome.toggleMaximize()}
      >
        {maximized ? (
          <svg {...ICON_PROPS}>
            <rect x="1.5" y="3.5" width="7" height="7" />
            <path d="M3.5 3.5V1.5h7v7H8.5" />
          </svg>
        ) : (
          <svg {...ICON_PROPS}><rect x="1.5" y="1.5" width="9" height="9" /></svg>
        )}
      </button>
      <button
        type="button"
        className="is-close"
        data-testid="window-close"
        aria-label="关闭窗口"
        title="关闭"
        onClick={() => (onClose === undefined ? void chrome.close() : onClose())}
      >
        <svg {...ICON_PROPS}><path d="m1.8 1.8 8.4 8.4M10.2 1.8l-8.4 8.4" /></svg>
      </button>
    </div>
  );
}
