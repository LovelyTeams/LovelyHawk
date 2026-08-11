import { activeTargetContext } from '../core/targetContext';
import { escapeHtml } from '../core/htmlEscape';
import { logger } from '../core/logger';
import { operationJournal } from '../core/operationJournal';
import {
  incidentCaseManager,
  type IncidentCase,
  type IOCType,
} from '../case/incidentCaseManager';
import { reportError } from '../utils/errorHandler';

const log = logger.module('CaseWorkspaceUI');

let overlay: HTMLElement | null = null;
let bodyElement: HTMLElement | null = null;
let keyHandler: ((event: KeyboardEvent) => void) | null = null;

const IOC_LABELS: Record<IOCType, string> = {
  ip: 'IP', domain: '域名', hash: '哈希', path: '路径', process: '进程', user: '账号', other: '其他',
};

function formatTime(timestamp: number): string {
  return new Date(timestamp).toLocaleString('zh-CN');
}

function targetLabel(incident: IncidentCase): string {
  const target = incident.lastTarget;
  return `${target.username}@${target.host}:${target.port} · ${target.hostKeyFingerprint}`;
}

export function renderCaseWorkspaceContent(incident: IncidentCase | null, cases: IncidentCase[] = []): string {
  if (!incident) {
    return `
      <div class="case-empty">
        <strong>尚未连接目标主机</strong>
        <span>连接并确认主机指纹后，LovelyRes 会为该目标创建隔离案件。</span>
      </div>`;
  }

  const caseOptions = cases.map(item => `
    <option value="${escapeHtml(item.id)}" ${item.id === incident.id ? 'selected' : ''}>
      ${escapeHtml(item.title)} · ${escapeHtml(formatTime(item.createdAt))}
    </option>`).join('');
  const iocs = incident.iocs.slice(0, 50).map(item => `
    <div class="case-list-row">
      <span class="case-kind">${escapeHtml(IOC_LABELS[item.type])}</span>
      <span class="case-row-main" title="${escapeHtml(item.value)}">${escapeHtml(item.value)}</span>
      <span class="case-row-meta">${escapeHtml(item.source)}</span>
    </div>`).join('') || '<div class="case-list-empty">暂无 IOC</div>';
  const evidence = incident.evidence.slice(0, 50).map(item => `
    <div class="case-list-row case-evidence-row">
      <span class="case-kind">${escapeHtml(item.kind)}</span>
      <span class="case-row-main" title="${escapeHtml(item.label)}">${escapeHtml(item.label)}</span>
      <span class="case-hash" title="SHA-256 ${escapeHtml(item.sha256)} · ${escapeHtml(item.hashScope)}">${escapeHtml(item.sha256.slice(0, 12))}…</span>
      <span class="case-row-meta">${escapeHtml(formatTime(item.collectedAt))}</span>
    </div>`).join('') || '<div class="case-list-empty">暂无证据</div>';
  const timeline = incident.timeline.slice(0, 80).map(item => `
    <div class="case-timeline-row">
      <span class="case-timeline-dot"></span>
      <div>
        <strong>${escapeHtml(item.title)}</strong>
        <small>${escapeHtml(formatTime(item.timestamp))} · ${escapeHtml(item.source)} · ${escapeHtml(item.target.sessionId)}</small>
      </div>
    </div>`).join('');

  return `
    <div class="case-summary">
      <div>
        <label for="case-selector">当前案件</label>
        <select id="case-selector">${caseOptions}</select>
      </div>
      <div class="case-target" title="${escapeHtml(targetLabel(incident))}">${escapeHtml(targetLabel(incident))}</div>
      <button type="button" class="modern-btn primary" data-case-action="capture-forensic">采集取证快照</button>
      <button type="button" class="modern-btn secondary" data-case-action="new-case">新建案件</button>
      <button type="button" class="modern-btn secondary" data-case-action="export">导出 JSON</button>
    </div>
    <div class="case-stats">
      <span><strong>${incident.iocs.length}</strong> IOC</span>
      <span><strong>${incident.evidence.length}</strong> 证据</span>
      <span><strong>${incident.timeline.length}</strong> 时间线事件</span>
      <span>更新于 ${escapeHtml(formatTime(incident.updatedAt))}</span>
    </div>
    <div class="case-capture-grid">
      <div class="case-capture-card">
        <h4>加入 IOC</h4>
        <div class="case-input-row">
          <select id="case-ioc-type">
            ${Object.entries(IOC_LABELS).map(([value, label]) => `<option value="${value}">${label}</option>`).join('')}
          </select>
          <input id="case-ioc-value" maxlength="2048" placeholder="IP、域名、哈希、路径、进程或账号">
          <button type="button" class="modern-btn primary" data-case-action="add-ioc">加入</button>
        </div>
      </div>
      <div class="case-capture-card">
        <h4>记录调查笔记</h4>
        <div class="case-input-row">
          <input id="case-note" maxlength="4096" placeholder="判断、待办、验证结果……">
          <button type="button" class="modern-btn primary" data-case-action="add-note">记录</button>
        </div>
      </div>
    </div>
    <div class="case-columns">
      <section><h4>IOC</h4><div class="case-scroll-list">${iocs}</div></section>
      <section><h4>证据清单</h4><div class="case-scroll-list">${evidence}</div></section>
      <section><h4>调查时间线</h4><div class="case-scroll-list">${timeline}</div></section>
    </div>
    <div class="case-integrity-note">
      “stored-preview”哈希覆盖案件中保存的预览内容；“external-artifact”才表示调用方提供的原始文件 SHA-256。
    </div>`;
}

function buildOverlay(): HTMLElement {
  const root = document.createElement('div');
  root.className = 'case-modal-overlay';
  root.innerHTML = `
    <div class="case-modal" role="dialog" aria-modal="true" aria-label="案件工作区">
      <header class="case-modal-header">
        <div><h3>案件工作区</h3><span>目标、IOC、证据与处置时间线</span></div>
        <button type="button" class="case-modal-close" data-case-action="close" aria-label="关闭">×</button>
      </header>
      <div class="case-modal-body">加载中…</div>
    </div>`;
  bodyElement = root.querySelector('.case-modal-body');
  root.addEventListener('click', event => {
    if (event.target === root) closeCaseWorkspace();
    const element = event.target instanceof Element ? event.target.closest<HTMLElement>('[data-case-action]') : null;
    if (element) void handleAction(element.dataset.caseAction || '', element);
  });
  root.addEventListener('change', event => {
    const select = event.target instanceof HTMLSelectElement && event.target.id === 'case-selector'
      ? event.target
      : null;
    if (!select) return;
    try {
      incidentCaseManager.selectCase(select.value);
      renderCurrent();
    } catch (error) {
      handleError(error, '切换案件');
    }
  });
  return root;
}

function renderCurrent(): void {
  if (!bodyElement) return;
  const target = activeTargetContext.get();
  if (!target) {
    bodyElement.innerHTML = renderCaseWorkspaceContent(null);
    return;
  }
  const incident = incidentCaseManager.getActiveCase() || incidentCaseManager.ensureActiveCase();
  incidentCaseManager.syncOperationEntries(operationJournal.list({ server: target.host }));
  const synced = incidentCaseManager.getActiveCase() || incident;
  bodyElement.innerHTML = renderCaseWorkspaceContent(synced, incidentCaseManager.getCasesForActiveTarget());
}

function downloadActiveCase(): void {
  const incident = incidentCaseManager.getActiveCase();
  if (!incident) throw new Error('当前目标没有活动案件');
  const content = incidentCaseManager.exportActiveCase();
  const blob = new Blob([content], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `LovelyRes-${incident.id}-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

async function handleAction(action: string, trigger?: HTMLElement): Promise<void> {
  try {
    if (action === 'close') {
      closeCaseWorkspace();
      return;
    }
    if (action === 'new-case') {
      incidentCaseManager.createCase();
      renderCurrent();
      window.showNotification?.('已为当前目标创建新案件', 'success');
      return;
    }
    if (action === 'export') {
      downloadActiveCase();
      window.showNotification?.('案件证据清单已导出', 'success');
      return;
    }
    if (action === 'capture-forensic') {
      const target = activeTargetContext.get();
      if (!target) throw new Error('请先连接目标主机');
      const button = trigger instanceof HTMLButtonElement ? trigger : null;
      const original = button?.textContent || '采集取证快照';
      if (button) button.disabled = true;
      try {
        const { forensicManager } = await import('../emergency/forensicManager');
        const snapshot = await forensicManager.captureSnapshot(target.host, (pct, label) => {
          if (button) button.textContent = `${pct}% · ${label}`;
        });
        forensicManager.exportSnapshot(snapshot);
        renderCurrent();
        window.showNotification?.(
          `取证快照已加入案件并导出 · ${snapshot.collection.completed}/${snapshot.collection.total} 项 · SHA-256 ${snapshot.sha256.slice(0, 12)}…`,
          snapshot.collection.failed ? 'warning' : 'success',
        );
      } finally {
        if (button) {
          button.disabled = false;
          button.textContent = original;
        }
      }
      return;
    }
    if (action === 'add-ioc') {
      const type = (document.getElementById('case-ioc-type') as HTMLSelectElement | null)?.value as IOCType;
      const input = document.getElementById('case-ioc-value') as HTMLInputElement | null;
      incidentCaseManager.addIOC(type || 'other', input?.value || '', 'case-workspace');
      renderCurrent();
      window.showNotification?.('IOC 已加入当前案件', 'success');
      return;
    }
    if (action === 'add-note') {
      const input = document.getElementById('case-note') as HTMLInputElement | null;
      await incidentCaseManager.addNote(input?.value || '');
      renderCurrent();
      window.showNotification?.('调查笔记已记录并生成证据哈希', 'success');
    }
  } catch (error) {
    handleError(error, action);
  }
}

function handleError(error: unknown, action: string): void {
  log.warn(`案件操作失败: ${action}`, error);
  reportError(error, { module: 'CaseWorkspaceUI', action, silent: true });
  window.showNotification?.(`案件操作失败：${error}`, 'error');
}

export function openCaseWorkspace(): void {
  if (!overlay) {
    overlay = buildOverlay();
    document.body.appendChild(overlay);
  }
  overlay.classList.add('visible');
  try { renderCurrent(); } catch (error) { handleError(error, '打开案件'); }
  if (!keyHandler) {
    keyHandler = event => {
      if (event.key === 'Escape') closeCaseWorkspace();
    };
    document.addEventListener('keydown', keyHandler);
  }
}

export function closeCaseWorkspace(): void {
  overlay?.classList.remove('visible');
  if (keyHandler) {
    document.removeEventListener('keydown', keyHandler);
    keyHandler = null;
  }
}
