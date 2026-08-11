import { activeTargetContext } from '../core/targetContext';
import { escapeHtml } from '../core/htmlEscape';
import { incidentCaseManager } from '../case/incidentCaseManager';
import { reportError } from '../utils/errorHandler';
import { showConfirm } from '../ui/confirmDialog';
import { getComplianceRules, generateComplianceSummary, type ComplianceRule } from './complianceRules';
import type { HardeningItem } from './detectionFixMapper';
import { quickDetectionManager, type DetectionReport } from './quickDetectionManager';

type QuickDetectionTab = 'detection' | 'results' | 'compliance' | 'fix-history' | 'hardening';
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low';
type HardeningStatus = 'unknown' | 'checking' | 'safe' | 'unsafe' | 'failed';

const severityLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};

function exactTargetLabel(): string {
  const target = activeTargetContext.get();
  return target
    ? `${target.username}@${target.host}:${target.port} · ${target.hostKeyFingerprint}`
    : '未连接';
}

function detailsText(value: unknown): string {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value, null, 2); } catch { return String(value); }
}

export function renderFindingCards(report: DetectionReport | null, filter: SeverityFilter): string {
  if (!report) {
    return '<div class="qd-empty">运行检测后，结果将在此显示</div>';
  }

  const cards: string[] = [];
  report.items.forEach((item, itemIndex) => {
    if (item.status === 'failed') {
      if (filter === 'all') {
        cards.push(`
          <div class="qd-finding-card severity-info">
            <div class="qd-finding-header">
              <span class="qd-severity-badge info">错误</span>
              <span class="qd-finding-title">${escapeHtml(item.name)}执行失败</span>
            </div>
            <div class="qd-finding-body"><div class="qd-finding-desc">该检测项没有返回可信结果，不参与通过判定。</div></div>
            <div class="qd-finding-actions"><button class="qd-action-btn" data-qd-action="reverify" data-item-index="${itemIndex}">重新检测</button></div>
          </div>`);
      }
      return;
    }

    (item.result?.findings || []).forEach((finding, findingIndex) => {
      if (filter !== 'all' && finding.severity !== filter) return;
      const actions = quickDetectionManager.getFixActions(item.id, finding.title);
      const actionButtons = actions.map((action, actionIndex) => `
        <button class="qd-action-btn primary" data-qd-action="fix-one"
          data-item-index="${itemIndex}" data-finding-index="${findingIndex}" data-fix-index="${actionIndex}">
          ${escapeHtml(action.title)}
        </button>`).join('');
      const detail = detailsText(finding.details);

      cards.push(`
        <div class="qd-finding-card severity-${finding.severity}" data-severity="${finding.severity}">
          <div class="qd-finding-header">
            <span class="qd-severity-badge ${finding.severity}">${severityLabels[finding.severity] || finding.severity}</span>
            <span class="qd-finding-title">${escapeHtml(finding.title)}</span>
            <span class="qd-fix-status pending" data-qd-fix-status>待处置</span>
          </div>
          <div class="qd-finding-body">
            <div class="qd-finding-desc">${escapeHtml(finding.description)}</div>
            ${finding.recommendation ? `<div class="qd-finding-desc">建议：${escapeHtml(finding.recommendation)}</div>` : ''}
          </div>
          ${detail ? `<div class="qd-finding-detail"><pre>${escapeHtml(detail)}</pre></div>` : ''}
          <div class="qd-finding-actions">
            ${actionButtons || '<span class="qd-muted">暂无自动修复，建议转入调查队列手工处置</span>'}
            <button class="qd-action-btn" data-qd-action="add-finding-to-case"
              data-item-index="${itemIndex}" data-finding-index="${findingIndex}">加入案件</button>
            <button class="qd-action-btn" data-qd-action="reverify" data-item-index="${itemIndex}">重新检测</button>
          </div>
        </div>`);
    });
  });

  if (cards.length === 0) {
    return `<div class="qd-empty">${filter === 'all' ? '未发现风险项' : '该级别暂无风险项'}</div>`;
  }
  return cards.join('');
}

class QuickDetectionPageController {
  private root: HTMLElement | null = null;
  private activeTab: QuickDetectionTab = 'detection';
  private filter: SeverityFilter = 'all';
  private complianceStandard: 'cis' | 'mlps2' = 'cis';
  private hardeningStatus = new Map<string, HardeningStatus>();

  initialize(): void {
    const root = document.querySelector<HTMLElement>('.qd-page');
    if (!root) return;
    if (this.root !== root) {
      this.root = root;
      root.addEventListener('click', this.handleClick);
      root.addEventListener('change', this.handleChange);
    }
    this.syncCheckCards();
    this.showTab(this.activeTab);
  }

  private handleClick = (event: Event): void => {
    const element = event.target instanceof Element ? event.target : null;
    if (!element || !this.root?.contains(element)) return;

    const tab = element.closest<HTMLElement>('[data-qd-tab]');
    if (tab?.dataset.qdTab) {
      this.showTab(tab.dataset.qdTab as QuickDetectionTab);
      return;
    }

    const action = element.closest<HTMLElement>('[data-qd-action]');
    if (action?.dataset.qdAction) {
      void this.handleAction(action).catch(error => {
        reportError(error, { module: 'QuickDetectionUI', action: action.dataset.qdAction || 'unknown' });
        window.showNotification?.(`操作失败: ${error}`, 'error');
      });
      return;
    }

    const item = element.closest<HTMLElement>('.qd-detection-item');
    if (item && !(element instanceof HTMLInputElement)) {
      const checkbox = item.querySelector<HTMLInputElement>('input[type="checkbox"]');
      if (checkbox) {
        checkbox.checked = !checkbox.checked;
        this.syncCheckCard(item, checkbox.checked);
      }
    }
  };

  private handleChange = (event: Event): void => {
    const checkbox = event.target instanceof HTMLInputElement
      ? event.target.closest<HTMLElement>('.qd-detection-item')?.querySelector<HTMLInputElement>('input[type="checkbox"]')
      : null;
    if (checkbox) {
      const item = checkbox.closest<HTMLElement>('.qd-detection-item');
      if (item) this.syncCheckCard(item, checkbox.checked);
    }
  };

  private async handleAction(element: HTMLElement): Promise<void> {
    switch (element.dataset.qdAction) {
      case 'full-scan':
        await this.runScan('selected', element);
        break;
      case 'competition-scan':
        await this.runScan('competition', element);
        break;
      case 'view-report':
        quickDetectionManager.viewReport();
        break;
      case 'cancel-scan':
        quickDetectionManager.cancelScan();
        break;
      case 'toggle-category':
        quickDetectionManager.toggleAllChecks(element.dataset.category as 'security' | 'competition' | 'performance');
        break;
      case 'filter':
        this.filter = (element.dataset.filter || 'all') as SeverityFilter;
        this.renderResults();
        break;
      case 'fix-one':
        await this.fixOne(element);
        break;
      case 'fix-all':
        await this.fixAll(element);
        break;
      case 'reverify':
        await this.reverify(element);
        break;
      case 'add-finding-to-case':
        await this.addFindingToCase(element);
        break;
      case 'compliance-standard':
        this.complianceStandard = element.dataset.standard === 'mlps2' ? 'mlps2' : 'cis';
        this.renderCompliance();
        break;
      case 'rollback-fix':
        await this.rollbackFix(element.dataset.entryId || '');
        break;
      case 'export-fix-history':
        this.exportFixHistory();
        break;
      case 'clear-fix-history':
        await this.clearFixHistory();
        break;
      case 'load-scan-history':
        this.loadScanHistory(element.dataset.reportId || '');
        break;
      case 'clear-scan-history':
        await quickDetectionManager.clearHistory();
        this.renderScanHistory();
        break;
      case 'check-all-hardening':
        await this.checkAllHardening();
        break;
      case 'fix-hardening':
        await this.fixHardening(element.dataset.itemId || '');
        break;
      case 'harden-all':
        await this.hardenAll();
        break;
    }
  }

  private showTab(tab: QuickDetectionTab): void {
    this.activeTab = tab;
    this.root?.querySelectorAll<HTMLElement>('[data-qd-tab]').forEach(button => {
      button.classList.toggle('active', button.dataset.qdTab === tab);
    });
    this.root?.querySelectorAll<HTMLElement>('.qd-tab-panel').forEach(panel => {
      panel.style.display = panel.id === `qd-tab-${tab}` ? '' : 'none';
    });
    if (tab === 'results') this.renderResults();
    if (tab === 'compliance') this.renderCompliance();
    if (tab === 'fix-history') this.renderFixHistory();
    if (tab === 'hardening') this.renderHardening();
  }

  private syncCheckCards(): void {
    this.root?.querySelectorAll<HTMLElement>('.qd-detection-item').forEach(item => {
      const checkbox = item.querySelector<HTMLInputElement>('input[type="checkbox"]');
      if (checkbox) this.syncCheckCard(item, checkbox.checked);
    });
  }

  private syncCheckCard(item: HTMLElement, selected: boolean): void {
    item.classList.toggle('selected', selected);
  }

  private async runScan(mode: 'selected' | 'competition', button: HTMLElement): Promise<void> {
    if (mode === 'selected' && !this.root?.querySelector('input[type="checkbox"]:checked')) {
      window.showNotification?.('请至少选择一个检测项', 'warning');
      return;
    }
    this.setBusy(button, true, '扫描中...');
    try {
      await (mode === 'competition'
        ? quickDetectionManager.startCompetitionScan()
        : quickDetectionManager.startFullScan());
      this.renderResults();
      this.renderCompliance();
      this.showTab('results');
    } finally {
      this.setBusy(button, false);
    }
  }

  private renderResults(): void {
    const list = this.root?.querySelector<HTMLElement>('#qd-results-list');
    if (!list) return;
    this.root?.querySelectorAll<HTMLElement>('[data-qd-action="filter"]').forEach(chip => {
      chip.classList.toggle('active', chip.dataset.filter === this.filter);
    });
    const report = quickDetectionManager.getCurrentReport();
    const completeness = report?.completeness;
    const statusLabel = report?.status === 'cancelled' ? '已取消'
      : report?.status === 'partial' ? '部分完成' : '已完成';
    const meta = report ? `<div class="qd-scan-meta">
      <strong>${report.mode === 'competition-triage' ? '首分钟摸底' : '自选扫描'} · ${statusLabel}</strong>
      <span>完整度 ${completeness?.processedPercent ?? 100}%</span>
      <span>有效 ${completeness?.completed ?? report.items.length}</span>
      <span>错误 ${completeness?.failed ?? 0}</span>
      <span>N/A ${completeness?.notApplicable ?? 0}</span>
      <span>${(report.totalDuration / 1000).toFixed(1)}s</span>
      ${report.timeBudgetMs ? `<span>预算 ${report.timeBudgetMs / 1000}s</span>` : ''}
    </div>` : '';
    list.innerHTML = meta + renderFindingCards(report, this.filter);
    this.renderScanHistory();
  }

  private renderScanHistory(): void {
    const list = this.root?.querySelector<HTMLElement>('#qd-scan-history-list');
    if (!list) return;
    const history = quickDetectionManager.getScanHistory();
    if (history.length === 0) {
      list.innerHTML = '<div class="qd-empty">暂无检测历史</div>';
      return;
    }
    list.innerHTML = history.map(report => {
      const sameTarget = Boolean(report.target && activeTargetContext.matches(report.target));
      const target = report.target
        ? `${report.target.username}@${report.target.host}:${report.target.port}`
        : '旧记录：无目标身份';
      const status = report.status === 'cancelled' ? '已取消' : report.status === 'partial' ? '部分完成' : '已完成';
      return `<div class="qd-fix-entry ${sameTarget ? 'success' : 'failed'}">
        <div class="qd-fix-entry-info">
          <div class="qd-fix-entry-title">${new Date(report.timestamp).toLocaleString('zh-CN')} · ${escapeHtml(status)}</div>
          <div class="qd-fix-entry-meta">${escapeHtml(target)} · ${report.items.length} 项 · ${(report.totalDuration / 1000).toFixed(1)}s</div>
          <div class="qd-fix-entry-diff">评分 ${report.overallScore} · 完整度 ${report.completeness?.processedPercent ?? 100}% · 严重/高危 ${report.summary.critical + report.summary.high}</div>
        </div>
        <button class="qd-action-btn" data-qd-action="load-scan-history" data-report-id="${escapeHtml(report.id)}" ${sameTarget ? '' : 'disabled title="目标不一致或旧记录缺少目标身份"'}>载入</button>
      </div>`;
    }).join('');
  }

  private loadScanHistory(reportId: string): void {
    if (!quickDetectionManager.selectHistoryReport(reportId)) {
      window.showNotification?.('历史报告目标与当前主机不一致，已阻止载入和处置', 'error');
      return;
    }
    this.renderResults();
    this.renderCompliance();
    window.showNotification?.('已载入当前目标的历史报告', 'success');
  }

  private async fixOne(button: HTMLElement): Promise<void> {
    const report = quickDetectionManager.getCurrentReport();
    const item = report?.items[Number(button.dataset.itemIndex)];
    const finding = item?.result?.findings[Number(button.dataset.findingIndex)];
    const def = item && finding
      ? quickDetectionManager.getFixActions(item.id, finding.title)[Number(button.dataset.fixIndex)]
      : undefined;
    if (!item || !finding || !def) throw new Error('修复动作已失效，请刷新检测结果');

    const confirmed = await showConfirm({
      title: `执行修复：${def.title}`,
      description: exactTargetLabel(),
      message: `${def.description}\n\n检测项：${item.name}\n发现：${finding.title}`,
      confirmText: '执行并复检', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;

    this.setBusy(button, true, '执行中...');
    const result = await quickDetectionManager.executeSingleFix(item.id, finding.title, def);
    if (result.success) await quickDetectionManager.reVerifyAndUpdate(item.id);
    this.setBusy(button, false);
    this.renderResults();
    this.renderCompliance();
    this.renderFixHistory();
    window.showNotification?.(result.success ? '修复已执行并完成复检' : `修复失败: ${result.output}`, result.success ? 'success' : 'error');
  }

  private async fixAll(button: HTMLElement): Promise<void> {
    this.setBusy(button, true, '批量修复中...');
    try {
      const results = await quickDetectionManager.executeAllFixes();
      const ids = new Set(results.filter(result => result.success).map(result => result.action.detectionItemId));
      for (const id of ids) await quickDetectionManager.reVerifyAndUpdate(id);
      this.renderResults();
      this.renderCompliance();
      this.renderFixHistory();
    } finally {
      this.setBusy(button, false);
    }
  }

  private async reverify(button: HTMLElement): Promise<void> {
    const item = quickDetectionManager.getCurrentReport()?.items[Number(button.dataset.itemIndex)];
    if (!item) return;
    this.setBusy(button, true, '检测中...');
    try {
      await quickDetectionManager.reVerifyAndUpdate(item.id);
      this.renderResults();
      this.renderCompliance();
    } finally {
      this.setBusy(button, false);
    }
  }

  private async addFindingToCase(button: HTMLElement): Promise<void> {
    const report = quickDetectionManager.getCurrentReport();
    if (!report?.target || !activeTargetContext.matches(report.target)) {
      throw new Error('检测报告目标与当前主机不一致，已阻止加入案件');
    }
    const item = report.items[Number(button.dataset.itemIndex)];
    const finding = item?.result?.findings[Number(button.dataset.findingIndex)];
    if (!item || !finding) throw new Error('检测发现已失效，请刷新结果');
    const evidence = await incidentCaseManager.addFinding({
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      recommendation: finding.recommendation,
      details: finding.details,
      source: `quick-detection:${item.id}`,
    });
    const incident = incidentCaseManager.getActiveCase();
    window.showNotification?.(`已加入案件 ${incident?.id || ''} · SHA-256 ${evidence.sha256.slice(0, 12)}…`, 'success');
  }

  private renderCompliance(): void {
    const container = this.root?.querySelector<HTMLElement>('#qd-compliance-content');
    if (!container) return;
    const report = quickDetectionManager.getCurrentReport();
    const resultMap = new Map<string, boolean>();
    report?.items.forEach(item => {
      if (item.status === 'completed' && item.result) resultMap.set(item.id, item.result.passed);
    });
    const rules = getComplianceRules(this.complianceStandard);
    const summary = generateComplianceSummary(this.complianceStandard, resultMap);
    container.innerHTML = `
      <div class="qd-compliance-toolbar">
        <div class="qd-filter-chips">
          <button class="qd-filter-chip ${this.complianceStandard === 'cis' ? 'active' : ''}" data-qd-action="compliance-standard" data-standard="cis">CIS Benchmark</button>
          <button class="qd-filter-chip ${this.complianceStandard === 'mlps2' ? 'active' : ''}" data-qd-action="compliance-standard" data-standard="mlps2">等保 2.0</button>
        </div>
        <strong>${summary.percent}%</strong>
        <span>通过 ${summary.passed} · 未通过 ${summary.failed} · 待检测 ${summary.pending}</span>
      </div>
      <div class="qd-compliance-list">${rules.map(rule => this.renderComplianceRule(rule, resultMap.get(rule.detectionItemId))).join('')}</div>`;
  }

  private renderComplianceRule(rule: ComplianceRule, passed: boolean | undefined): string {
    const state = passed === undefined ? 'pending' : passed ? 'passed' : 'failed';
    const label = passed === undefined ? '待检测' : passed ? '通过' : '未通过';
    return `<div class="qd-compliance-rule ${state}">
      <span class="qd-compliance-state">${label}</span>
      <div><strong>${escapeHtml(rule.clause)} · ${escapeHtml(rule.title)}</strong><p>${escapeHtml(rule.description)}</p></div>
      <span class="qd-severity-badge ${rule.severity}">${severityLabels[rule.severity]}</span>
    </div>`;
  }

  private renderFixHistory(): void {
    const list = this.root?.querySelector<HTMLElement>('#qd-fix-history-list');
    if (!list) return;
    const history = quickDetectionManager.getFixHistory();
    if (history.length === 0) {
      list.innerHTML = '<div class="qd-empty">暂无修复记录</div>';
      return;
    }
    list.innerHTML = history.map(entry => {
      const state = entry.rolledBack ? 'rolled-back' : entry.success ? 'success' : 'failed';
      const target = entry.target
        ? `${entry.target.username}@${entry.target.host}:${entry.target.port}`
        : '旧记录：无目标身份';
      const rollback = entry.success && entry.restoreCommand && !entry.rolledBack
        ? `<button class="qd-action-btn danger" data-qd-action="rollback-fix" data-entry-id="${escapeHtml(entry.id)}">回滚</button>`
        : '';
      return `<div class="qd-fix-entry ${state}">
        <div class="qd-fix-entry-info">
          <div class="qd-fix-entry-title">${escapeHtml(entry.fixTitle)}</div>
          <div class="qd-fix-entry-meta">${new Date(entry.timestamp).toLocaleString()} · ${escapeHtml(target)}</div>
          <div class="qd-fix-entry-diff">${escapeHtml(entry.beforeValue || '—')} → ${escapeHtml(entry.afterValue || '—')}</div>
        </div>${rollback}</div>`;
    }).join('');
  }

  private async rollbackFix(entryId: string): Promise<void> {
    const entry = quickDetectionManager.getFixHistory().find(item => item.id === entryId);
    if (!entry) return;
    const confirmed = await showConfirm({
      title: `回滚：${entry.fixTitle}`,
      description: exactTargetLabel(),
      message: `将执行恢复命令并验证目标身份。\n记录目标：${entry.target ? `${entry.target.username}@${entry.target.host}:${entry.target.port}` : '缺失'}`,
      confirmText: '确认回滚', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    const result = await quickDetectionManager.rollbackFix(entryId);
    window.showNotification?.(result.success ? '回滚成功' : result.output, result.success ? 'success' : 'error');
    this.renderFixHistory();
  }

  private exportFixHistory(): void {
    const history = quickDetectionManager.getFixHistory();
    const blob = new Blob([JSON.stringify(history, null, 2)], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `lovelyres-fix-history-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  private async clearFixHistory(): Promise<void> {
    const confirmed = await showConfirm({
      title: '清空修复历史', message: '将删除本机保存的全部修复记录，且不可恢复。',
      confirmText: '清空', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    quickDetectionManager.clearFixHistory();
    this.renderFixHistory();
  }

  private renderHardening(): void {
    const list = this.root?.querySelector<HTMLElement>('#qd-hardening-list');
    if (!list) return;
    const groups = new Map<string, HardeningItem[]>();
    for (const item of quickDetectionManager.getHardeningItems()) {
      const group = groups.get(item.group) || [];
      group.push(item);
      groups.set(item.group, group);
    }
    list.innerHTML = [...groups.entries()].map(([group, items]) => `
      <div><div class="qd-hardening-group-title">${escapeHtml(group)}</div><div class="qd-hardening-items">
        ${items.map(item => {
          const status = this.hardeningStatus.get(item.id) || 'unknown';
          const label = status === 'safe' ? '安全' : status === 'unsafe' ? '待加固' : status === 'checking' ? '检查中' : status === 'failed' ? '失败' : '未检查';
          return `<div class="qd-hardening-item" data-hardening-id="${escapeHtml(item.id)}">
            <span class="qd-hardening-status ${status}">${label}</span>
            <span class="qd-hardening-title">${escapeHtml(item.title)}</span>
            <button class="qd-hardening-fix-btn" data-qd-action="fix-hardening" data-item-id="${escapeHtml(item.id)}">加固并验证</button>
          </div>`;
        }).join('')}
      </div></div>`).join('');
  }

  private async checkAllHardening(): Promise<void> {
    const items = quickDetectionManager.getHardeningItems();
    items.forEach(item => this.hardeningStatus.set(item.id, 'checking'));
    this.renderHardening();
    let cursor = 0;
    const worker = async () => {
      while (cursor < items.length) {
        const item = items[cursor++];
        const safe = await quickDetectionManager.checkHardeningStatus(item);
        this.hardeningStatus.set(item.id, safe ? 'safe' : 'unsafe');
        this.renderHardening();
      }
    };
    await Promise.all(Array.from({ length: Math.min(3, items.length) }, worker));
  }

  private async fixHardening(itemId: string): Promise<void> {
    const item = quickDetectionManager.getHardeningItems().find(entry => entry.id === itemId);
    if (!item) return;
    const confirmed = await showConfirm({
      title: `快速加固：${item.title}`,
      description: exactTargetLabel(),
      message: `将执行以下命令并读回验证：\n\n${item.fixCommand}`,
      confirmText: '执行并验证', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    this.hardeningStatus.set(item.id, 'checking');
    this.renderHardening();
    const result = await quickDetectionManager.executeHardening(item);
    this.hardeningStatus.set(item.id, result.verified ? 'safe' : result.success ? 'unsafe' : 'failed');
    this.renderHardening();
    window.showNotification?.(result.verified ? '加固已执行并验证通过' : `加固未通过验证: ${result.output}`, result.verified ? 'success' : 'error');
  }

  private async hardenAll(): Promise<void> {
    await this.checkAllHardening();
    const items = quickDetectionManager.getHardeningItems()
      .filter(item => this.hardeningStatus.get(item.id) === 'unsafe')
      .sort((a, b) => a.priority - b.priority);
    if (items.length === 0) {
      window.showNotification?.('所有加固项均已通过检查', 'success');
      return;
    }
    const confirmed = await showConfirm({
      title: `批量执行 ${items.length} 项加固`,
      description: exactTargetLabel(),
      message: `将按顺序执行并逐项验证。SSH、防火墙或挂载参数变更可能导致当前会话断开。\n\n${items.map(item => `• ${item.title}`).join('\n')}`,
      confirmText: '确认批量加固', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    for (const item of items) {
      this.hardeningStatus.set(item.id, 'checking');
      this.renderHardening();
      const result = await quickDetectionManager.executeHardening(item);
      this.hardeningStatus.set(item.id, result.verified ? 'safe' : result.success ? 'unsafe' : 'failed');
      this.renderHardening();
      if (!result.success) break;
    }
  }

  private setBusy(element: HTMLElement, busy: boolean, text?: string): void {
    if (element instanceof HTMLButtonElement) element.disabled = busy;
    if (busy) {
      element.dataset.qdOriginalText = element.textContent || '';
      if (text) element.textContent = text;
    } else if (element.dataset.qdOriginalText !== undefined) {
      element.textContent = element.dataset.qdOriginalText;
      delete element.dataset.qdOriginalText;
    }
  }
}

export const quickDetectionPageController = new QuickDetectionPageController();
