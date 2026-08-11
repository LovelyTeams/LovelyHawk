/**
 * Baseline Quick Edit Page Manager
 * 管理基线配置的读取、编辑、保存流程
 */

import {
  baselineCategories,
  resolveForDistro,
  type BaselineCategory,
  type BaselineConfigItem,
} from './baselineConfigs';
import { SystemDetector, type SystemInfo } from '../utils/systemDetector';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';
import { statusIcon } from '../ui/iconMapping';
import { showAlert, showConfirm } from '../ui/confirmDialog';
import {
  checkQuickActionParam,
  buildQuickActionCommand,
  QUICK_ACTIONS_NEEDING_PARAM,
} from './quickActionCommands';
import { operationJournal } from '../core/operationJournal';
import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import { shq } from '../core/shellEscape';
import { reportError } from '../utils/errorHandler';
import { buildEditorBackupPath, contentSha256, validateEditableRemotePath } from './baselineFileEditor';
import { escapeHtml } from '../core/htmlEscape';

interface BaselineCommandReceipt {
  output: string;
  exitCode: number | null;
  timedOut: boolean;
  success: boolean;
}

interface ChangeHistoryEntry {
  timestamp: string;
  server: string;
  changes: Array<{ name: string; oldValue: string; newValue: string; itemId: string }>;
}

export class BaselineQuickEditManager {
  private eventsBound = false;
  private selectedCategoryId: string | null = null;
  private currentValues: Map<string, string> = new Map();
  private pendingChanges: Map<string, string> = new Map();
  private systemInfo: string = '';
  private detectedDistro: string = 'generic';  // 当前检测到的发行版 ID
  private detectedSystemInfo: SystemInfo | null = null;
  private debounceTimer: number | null = null;
  // 新增：文件编辑器状态
  private editorFilePath: string = '';
  private editorOriginalContent: string = '';
  private editorModified: boolean = false;
  private targetSessionId: string | null = null;

  async initialize(): Promise<void> {
    if (!this.eventsBound) {
      this.bindEvents();
      this.eventsBound = true;
    }

    const target = activeTargetContext.get();
    if (!target) {
      window.showNotification?.('没有已确认的活动 SSH 目标，请先连接服务器', 'warning');
      return;
    }
    if (this.targetSessionId !== target.sessionId) {
      const discardedUnsaved = this.resetTargetState();
      this.targetSessionId = target.sessionId;
      if (discardedUnsaved) {
        window.showNotification?.('目标会话已变化，已丢弃上一会话未应用的基线修改', 'warning');
      }
    }

    try {
      await this.detectSystem(target);
    } catch (error) {
      reportError(error, { module: 'BaselineQuickEdit', action: '初始化目标环境' });
    }
  }

  private resetTargetState(): boolean {
    const discardedUnsaved = this.pendingChanges.size > 0 || this.editorModified;
    this.selectedCategoryId = null;
    this.currentValues.clear();
    this.pendingChanges.clear();
    this.systemInfo = '';
    this.detectedDistro = 'generic';
    this.detectedSystemInfo = null;
    this.editorFilePath = '';
    this.editorOriginalContent = '';
    this.editorModified = false;
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    return discardedUnsaved;
  }

  // ─── 系统检测 ───

  private async detectSystem(target: TargetIdentity): Promise<void> {
    const badge = document.getElementById('bl-sys-name');
    try {
      const info = await SystemDetector.detectSystem();
      if (!activeTargetContext.matches(target)) throw new Error('系统检测期间活动目标已变化');
      this.detectedSystemInfo = info;
      this.detectedDistro = info.type;
      this.systemInfo = info.prettyName || info.name || 'Linux';
    } catch (error) {
      if (!activeTargetContext.matches(target)) throw error;
      // 回退到手动解析
      try {
        const output = await this.executeCommand('cat /etc/os-release 2>/dev/null | grep -E "^(PRETTY_NAME|ID)=" | head -2');
        if (!activeTargetContext.matches(target)) throw new Error('系统检测期间活动目标已变化');
        const nameMatch = output.match(/PRETTY_NAME="?([^"\n]+)"?/);
        const idMatch = output.match(/\nID="?([^"\n]+)"?/) || output.match(/^ID="?([^"\n]+)"?/);
        this.systemInfo = nameMatch ? nameMatch[1] : 'Linux';
        this.detectedDistro = idMatch ? idMatch[1].toLowerCase() : 'generic';
      } catch (fallbackError) {
        if (!activeTargetContext.matches(target)) throw fallbackError;
        this.systemInfo = 'Linux';
        this.detectedDistro = 'generic';
      }
    }
    // 显示发行版标识
    const pkgMgr = this.detectedSystemInfo?.packageManager || '';
    const initSys = this.detectedSystemInfo?.initSystem || '';
    const extra = [pkgMgr, initSys].filter(Boolean).join(' / ');
    if (badge) badge.textContent = this.systemInfo + (extra ? ` (${extra})` : '');
  }

  // ─── 事件绑定 ───

  private bindEvents(): void {
    document.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target.closest('#bl-btn-refresh')) {
        if (this.selectedCategoryId) this.loadCategoryValues(this.selectedCategoryId);
        return;
      }
      if (target.closest('#bl-btn-recommend-all')) {
        this.applyAllRecommended();
        return;
      }
      if (target.closest('#bl-btn-history')) {
        this.showHistory();
        return;
      }

      const actionEl = target.closest('[data-bl-action]') as HTMLElement;
      if (!actionEl) return;

      const action = actionEl.getAttribute('data-bl-action');
      const itemId = actionEl.getAttribute('data-bl-item-id') || '';
      const categoryId = actionEl.getAttribute('data-bl-category-id') || '';

      switch (action) {
        case 'select-category':
          this.selectCategory(categoryId);
          break;
        case 'apply-recommended':
          this.applyRecommended(itemId);
          break;
        case 'revert-item':
          this.revertItem(itemId);
          break;
        case 'cancel-all':
          this.cancelAllChanges();
          break;
        case 'apply-changes':
          this.applyChanges();
          break;
        case 'toggle-diff':
          this.toggleDiffPanel();
          break;
        // ── 新增模式切换 & 文件编辑 & 快捷操作 ──
        case 'switch-mode':
          this.switchMode(actionEl.getAttribute('data-bl-mode') as any);
          break;
        case 'open-file':
          this.openFile(actionEl.getAttribute('data-bl-filepath') || '');
          break;
        case 'open-custom-file': {
          const input = document.getElementById('bl-custom-path') as HTMLInputElement;
          if (input?.value.trim()) this.openFile(input.value.trim());
          break;
        }
        case 'save-file':
          this.saveCurrentFile();
          break;
        case 'reload-file':
          if (this.editorFilePath) this.openFile(this.editorFilePath);
          break;
        case 'exec-quick-action':
          this.executeQuickAction(actionEl.getAttribute('data-bl-qa-id') || '');
          break;
      }
    });

    // 表单控件变化
    document.addEventListener('change', (e) => {
      const target = e.target as HTMLElement;
      if (target.getAttribute('data-bl-action') !== 'change-value') return;
      const itemId = target.getAttribute('data-bl-item-id') || '';
      this.handleValueChange(itemId, target);
    });

    document.addEventListener('input', (e) => {
      const target = e.target as HTMLElement;
      if (target.id === 'bl-search-input' && target instanceof HTMLInputElement) {
        this.filterItems(target.value.trim().toLowerCase());
        return;
      }
      if (target.getAttribute('data-bl-action') !== 'change-value') return;
      if (target instanceof HTMLInputElement && (target.type === 'number' || target.type === 'text')) {
        const itemId = target.getAttribute('data-bl-item-id') || '';
        if (this.debounceTimer) clearTimeout(this.debounceTimer);
        this.debounceTimer = window.setTimeout(() => {
          this.handleValueChange(itemId, target);
        }, 300);
      }
    });

  }

  // ─── 分类选择 ───

  private async selectCategory(categoryId: string): Promise<void> {
    this.selectedCategoryId = categoryId;

    // 更新侧边栏激活状态
    document.querySelectorAll('.bl-group').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-bl-category') === categoryId);
    });

    await this.loadCategoryValues(categoryId);
  }

  // ─── 读取配置值 ───

  private async loadCategoryValues(categoryId: string): Promise<void> {
    const category = baselineCategories.find(c => c.id === categoryId);
    if (!category) return;
    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) {
      window.showNotification?.('没有已确认的活动 SSH 目标', 'warning');
      return;
    }

    const mainEl = document.getElementById('bl-main');
    if (!mainEl) return;

    // 显示加载状态
    mainEl.innerHTML = `
      <div class="bl-loading">
        <div class="bl-loading-spinner"></div>
        <div class="bl-loading-text">正在从服务器读取配置...</div>
      </div>
    `;

    try {
      // 批量读取所有配置项的当前值（使用发行版感知的命令）
      const commands = category.items.map(item => resolveForDistro(item, this.detectedDistro).readCommand);
      const results = await this.executeBatchCommands(commands, capturedTarget);
      if (!activeTargetContext.matches(capturedTarget)) throw new Error('读取配置期间活动目标已变化');

      // 解析结果
      for (let i = 0; i < category.items.length; i++) {
        const item = category.items[i];
        const output = results[i] || '';
        const regex = new RegExp(item.parseRegex, 'i');
        const match = output.match(regex);
        const value = match ? match[1].trim() : 'not set';
        this.currentValues.set(item.id, value);
      }

      // 渲染编辑器
      this.renderEditor(category);

      // 更新分类状态
      this.updateCategoryStatus(category);

    } catch (err) {
      mainEl.innerHTML = `
        <div class="bl-empty-state">
          <div class="bl-empty-title" style="color: var(--sev-critical-fg);">读取配置失败</div>
          <div class="bl-empty-desc">${escapeHtml(String(err))}</div>
        </div>
      `;
    }
  }

  // ─── 渲染编辑器 ───

  private renderEditor(category: BaselineCategory): void {
    const mainEl = document.getElementById('bl-main');
    if (!mainEl) return;

    const renderer = (window as any).app?.modernUIRenderer?.baselineRenderer;
    if (!renderer) return;

    mainEl.innerHTML = renderer.renderConfigEditor(category, this.currentValues, this.pendingChanges);
  }

  // ─── 值变更处理 ───

  private handleValueChange(itemId: string, el: HTMLElement): void {
    let value: string;

    if (el instanceof HTMLSelectElement) {
      value = el.value;
    } else if (el instanceof HTMLInputElement) {
      if (el.type === 'checkbox') {
        // 查找配置项确定值格式
        const item = this.findItem(itemId);
        if (item && (item.enumValues?.includes('0') || item.enumValues?.includes('1'))) {
          value = el.checked ? '1' : '0';
        } else {
          value = el.checked ? 'yes' : 'no';
        }
      } else {
        value = el.value;
      }
    } else {
      return;
    }

    const currentVal = this.currentValues.get(itemId);
    if (value === currentVal) {
      this.pendingChanges.delete(itemId);
    } else {
      this.pendingChanges.set(itemId, value);
    }

    // 更新 UI
    this.updateItemUI(itemId);
    this.updateDiffBar();
  }

  // ─── 应用推荐值 ───

  private applyRecommended(itemId: string): void {
    const item = this.findItem(itemId);
    if (!item) return;

    this.pendingChanges.set(itemId, item.recommendedValue);

    // 刷新当前分类编辑器
    if (this.selectedCategoryId) {
      const category = baselineCategories.find(c => c.id === this.selectedCategoryId);
      if (category) this.renderEditor(category);
    }
    this.updateDiffBar();
  }

  private applyAllRecommended(): void {
    if (!this.selectedCategoryId) {
      window.showNotification?.('请先选择一个配置分类', 'warning');
      return;
    }

    const category = baselineCategories.find(c => c.id === this.selectedCategoryId);
    if (!category) return;

    for (const item of category.items) {
      // 跳过不适用推荐值的项
      if (['按需设置', '按需配置', '无 NOPASSWD 条目', '非默认端口'].includes(item.recommendedValue)) continue;
      const currentVal = this.currentValues.get(item.id);
      if (currentVal !== item.recommendedValue) {
        this.pendingChanges.set(item.id, item.recommendedValue);
      }
    }

    this.renderEditor(category);
    this.updateDiffBar();
    window.showNotification?.(`已将 ${category.title} 的配置项设为推荐值`, 'success');
  }

  // ─── 撤销 ───

  private revertItem(itemId: string): void {
    this.pendingChanges.delete(itemId);

    if (this.selectedCategoryId) {
      const category = baselineCategories.find(c => c.id === this.selectedCategoryId);
      if (category) this.renderEditor(category);
    }
    this.updateDiffBar();
  }

  private cancelAllChanges(): void {
    this.pendingChanges.clear();

    if (this.selectedCategoryId) {
      const category = baselineCategories.find(c => c.id === this.selectedCategoryId);
      if (category) this.renderEditor(category);
    }
    this.updateDiffBar();
  }

  // ─── 应用变更 ───

  private async applyChanges(): Promise<void> {
    if (this.pendingChanges.size === 0) {
      window.showNotification?.('没有待应用的变更', 'info');
      return;
    }

    // 构建变更摘要
    const changeList: Array<{ item: BaselineConfigItem; oldValue: string; newValue: string }> = [];
    for (const [itemId, newVal] of this.pendingChanges) {
      const item = this.findItem(itemId);
      if (!item) continue;
      const oldVal = this.currentValues.get(itemId) ?? '?';
      if (oldVal !== newVal) {
        changeList.push({ item, oldValue: oldVal, newValue: newVal });
      }
    }

    if (changeList.length === 0) {
      window.showNotification?.('没有实际需要变更的配置项', 'info');
      this.pendingChanges.clear();
      this.updateDiffBar();
      return;
    }

    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) {
      window.showNotification?.('请先连接并确认目标主机', 'error');
      return;
    }

    // SSH 防锁定检查
    const sshPortChange = changeList.find(c => c.item.id === 'ssh-port');
    const sshPasswordChange = changeList.find(c => c.item.id === 'ssh-password-auth' && c.newValue === 'no');
    if (sshPortChange) {
      const confirmed = await showConfirm({
        title: '危险操作警告',
        message: `您正在修改 SSH 端口 (${sshPortChange.oldValue} → ${sshPortChange.newValue})。\n\n如果防火墙未放行新端口，您可能会失去对服务器的访问！\n\n请确认已做好准备。`,
        confirmText: '我已确认',
        cancelText: '取消',
        dangerous: true,
        defaultFocus: 'cancel',
      });
      if (!confirmed) return;
    }

    if (sshPasswordChange) {
      const confirmed = await showConfirm({
        title: '注意',
        message: '您正在关闭 SSH 密码认证。请确保已配置密钥认证，否则可能无法登录服务器。',
        confirmText: '已配置密钥',
        cancelText: '取消',
        dangerous: true,
        defaultFocus: 'cancel',
      });
      if (!confirmed) return;
    }

    // 确认对话框
    const summary = changeList.map(c => `  ${c.item.name}: ${c.oldValue} → ${c.newValue}`).join('\n');
    const confirmed = await showConfirm({
      title: '确认应用变更',
      message: `目标：${capturedTarget.username}@${capturedTarget.host}:${capturedTarget.port}\n指纹：${capturedTarget.hostKeyFingerprint}\n\n即将修改以下 ${changeList.length} 项配置：\n\n${summary}\n\n将在修改前自动备份原文件。`,
      confirmText: '应用变更',
      cancelText: '取消',
      dangerous: true,
      defaultFocus: 'cancel',
    });
    if (!confirmed) return;

    // 执行备份 + 写入
    const applyBtn = document.getElementById('bl-btn-apply') as HTMLButtonElement;
    if (applyBtn) {
      applyBtn.disabled = true;
      applyBtn.textContent = '应用中...';
    }

    try {
      if (!activeTargetContext.matches(capturedTarget)) throw new Error('确认后活动目标已变化，已停止应用');
      const fileBackups = new Map<string, { backupPath: string; beforeHash: string }>();
      const newlyCreatedFiles = new Set<string>();
      const batchTimestamp = Date.now();
      const resolvedItems = changeList.map(change => ({
        change,
        resolved: resolveForDistro(change.item, this.detectedDistro),
      }));

      const candidateFiles = new Set(resolvedItems.map(item => item.resolved.filePath));
      for (const candidate of candidateFiles) {
        if (!/^\/(etc|boot|home|opt|var\/opt)(\/|$)/.test(candidate) || /[*?\[\]{}$~]/.test(candidate)) continue;
        let path: string;
        try { path = validateEditableRemotePath(candidate); } catch { continue; }
        const kind = await this.executeCommand(`if [ -f ${shq(path)} ]; then echo FILE; elif [ -e ${shq(path)} ]; then echo OTHER; else echo MISSING; fi`);
        if (kind.trim() === 'MISSING') {
          newlyCreatedFiles.add(path);
          continue;
        }
        if (kind.trim() !== 'FILE') continue;
        const hashCommand = `(sha256sum -- ${shq(path)} 2>/dev/null || busybox sha256sum ${shq(path)} 2>/dev/null) | awk '{print $1}'`;
        const beforeHash = (await this.executeCommand(hashCommand)).trim();
        if (!/^[a-f0-9]{64}$/i.test(beforeHash)) throw new Error(`无法计算 ${path} 的备份前哈希`);
        const backupPath = `${path}.lovelyres.batch.${batchTimestamp}`;
        await this.executeCommand(`cp -p -- ${shq(path)} ${shq(backupPath)}`);
        const backupHash = (await this.executeCommand(`(sha256sum -- ${shq(backupPath)} 2>/dev/null || busybox sha256sum ${shq(backupPath)} 2>/dev/null) | awk '{print $1}'`)).trim();
        if (backupHash !== beforeHash) throw new Error(`${path} 的备份读回校验失败`);
        fileBackups.set(path, { backupPath, beforeHash });
      }

      const writeReceipts: BaselineCommandReceipt[] = [];
      const verifyReceipts: BaselineCommandReceipt[] = [];
      const verifiedItemIds = new Set<string>();
      for (const { change, resolved } of resolvedItems) {
        if (!activeTargetContext.matches(capturedTarget)) throw new Error('应用期间活动目标已变化，已停止后续变更');
        const writeReceipt = await this.executeCommandResult(resolved.writeCommand(change.newValue));
        writeReceipts.push(writeReceipt);
        if (!writeReceipt.success) {
          verifyReceipts.push({ output: '写入失败，未验证', exitCode: null, timedOut: false, success: false });
          continue;
        }
        const verifyReceipt = await this.executeCommandResult(resolved.readCommand);
        verifyReceipts.push(verifyReceipt);
        if (!verifyReceipt.success) continue;
        const match = verifyReceipt.output.match(new RegExp(change.item.parseRegex, 'i'));
        if (match?.[1]?.trim() === change.newValue) verifiedItemIds.add(change.item.id);
      }

      const failCount = changeList.length - verifiedItemIds.size;
      const fullyRestorable = resolvedItems.every(item =>
        fileBackups.has(item.resolved.filePath) || newlyCreatedFiles.has(item.resolved.filePath));
      const restoreCommands = [
        ...[...fileBackups.entries()].map(([path, backup]) => `cp -p -- ${shq(backup.backupPath)} ${shq(path)}`),
        ...[...newlyCreatedFiles].map(path => `rm -f -- ${shq(path)}`),
      ];
      const restoreChecks = [
        ...[...fileBackups.entries()].map(([path, backup]) =>
          `[ "$(sha256sum -- ${shq(path)} 2>/dev/null | awk '{print $1}')" = ${shq(backup.beforeHash)} ]`),
        ...[...newlyCreatedFiles].map(path => `[ ! -e ${shq(path)} ]`),
      ];
      const firstFailed = writeReceipts.find(receipt => !receipt.success);
      operationJournal.record({
        source: 'baseline', server: capturedTarget.host, target: capturedTarget,
        title: `批量应用 ${changeList.length} 项基线配置`,
        command: resolvedItems.map(item => item.resolved.writeCommand(item.change.newValue)).join('\n'),
        restoreCommand: fullyRestorable && restoreCommands.length ? restoreCommands.join(' && ') : undefined,
        restoreVerifyCommand: fullyRestorable && restoreChecks.length ? `${restoreChecks.join(' && ')} && echo RESTORE_OK` : undefined,
        restoreVerifyExpected: fullyRestorable && restoreChecks.length ? 'RESTORE_OK' : undefined,
        beforeValue: changeList.map(change => `${change.item.name}=${change.oldValue}`).join('; '),
        afterValue: changeList.map(change => `${change.item.name}=${change.newValue}`).join('; '),
        backupInfo: `${fullyRestorable ? '完整可回滚' : '仅部分文件有备份，整批不可一键回滚'}：${[...fileBackups.values()].map(item => `${item.backupPath} (${item.beforeHash})`).join('; ') || '无常规文件备份'}`,
        output: writeReceipts.map((receipt, index) => `${changeList[index].item.name}: ${receipt.output}`).join('\n'),
        exitCode: firstFailed?.exitCode ?? 0, timedOut: Boolean(firstFailed?.timedOut),
        verifyCommand: resolvedItems.map(item => item.resolved.readCommand).join('\n'),
        verifyOutput: verifyReceipts.map((receipt, index) => `${changeList[index].item.name}: ${receipt.output}`).join('\n'),
        verified: failCount === 0, success: failCount === 0,
      });

      if (failCount === 0) {
        window.showNotification?.(`${changeList.length} 项配置已应用并读回验证`, 'success');
      } else {
        window.showNotification?.(`${changeList.length - failCount}/${changeList.length} 项已验证，${failCount} 项失败或不一致`, 'warning');
      }

      // 检查是否需要重启服务
      const services = new Set<string>();
      const restartCommands = new Map<string, string>();
      for (const c of changeList) {
        const resolved = resolveForDistro(c.item, this.detectedDistro);
        if (c.item.restartService && resolved.restartCommand) {
          services.add(c.item.restartService);
          restartCommands.set(c.item.restartService, resolved.restartCommand);
        }
      }

      if (services.size > 0 && failCount === 0) {
        const serviceNames = Array.from(services).join(', ');
        const restartConfirmed = await showConfirm({
          title: '重启服务',
          message: `以下服务需要重启才能使配置生效：\n\n${serviceNames}\n\n是否立即重启？`,
          confirmText: '重启服务',
          cancelText: '稍后手动重启',
          dangerous: true,
          defaultFocus: 'cancel',
        });

        if (restartConfirmed) {
          const cmds = Array.from(restartCommands.values());
          const restartReceipts: BaselineCommandReceipt[] = [];
          for (const command of cmds) restartReceipts.push(await this.executeCommandResult(command));
          const restarted = restartReceipts.every(receipt => receipt.success);
          operationJournal.record({
            source: 'baseline', server: capturedTarget.host, target: capturedTarget,
            title: `重启基线相关服务：${serviceNames}`, command: cmds.join('\n'),
            output: restartReceipts.map(receipt => receipt.output).join('\n'),
            exitCode: restartReceipts.find(receipt => !receipt.success)?.exitCode ?? 0,
            timedOut: restartReceipts.some(receipt => receipt.timedOut), success: restarted,
          });
          window.showNotification?.(restarted ? `服务 ${serviceNames} 已重启` : `服务 ${serviceNames} 重启未全部成功`, restarted ? 'success' : 'error');
        }
      }

      // 保存历史
      const appliedChanges = changeList.filter(change => verifiedItemIds.has(change.item.id));
      if (appliedChanges.length) this.saveHistory(appliedChanges);

      // 只提交读回验证通过的状态，失败项保留待处理。
      for (const c of appliedChanges) {
        this.currentValues.set(c.item.id, c.newValue);
        this.pendingChanges.delete(c.item.id);
      }

      // 刷新编辑器
      if (this.selectedCategoryId) {
        const category = baselineCategories.find(cat => cat.id === this.selectedCategoryId);
        if (category) {
          this.renderEditor(category);
          this.updateCategoryStatus(category);
        }
      }
      this.updateDiffBar();

    } catch (err) {
      reportError(err, { module: 'Baseline', action: '应用基线变更', silent: true });
      window.showNotification?.(`应用变更失败: ${err}`, 'error');
    } finally {
      if (applyBtn) {
        applyBtn.disabled = false;
        applyBtn.textContent = '应用并保存';
      }
    }
  }

  // ─── UI 更新 ───

  private updateItemUI(itemId: string): void {
    const itemEl = document.querySelector(`[data-bl-item-id="${itemId}"].bl-config-item`) as HTMLElement;
    if (!itemEl) return;

    const isModified = this.pendingChanges.has(itemId);
    itemEl.classList.toggle('bl-modified', isModified);
  }

  private updateDiffBar(): void {
    const diffBar = document.getElementById('bl-diff-bar');
    const diffTitle = document.getElementById('bl-diff-title');
    const diffList = document.getElementById('bl-diff-list');

    // 计算实际变更数（排除值相同的）
    let realChangeCount = 0;
    for (const [itemId, newVal] of this.pendingChanges) {
      if (this.currentValues.get(itemId) !== newVal) realChangeCount++;
    }

    if (realChangeCount === 0) {
      if (diffBar) diffBar.style.display = 'none';
      return;
    }

    if (diffBar) diffBar.style.display = '';
    if (diffTitle) diffTitle.textContent = `待应用变更 (${realChangeCount}项)`;

    if (diffList) {
      const renderer = (window as any).app?.modernUIRenderer?.baselineRenderer;
      if (renderer) {
        diffList.innerHTML = renderer.renderDiffItems(this.pendingChanges, this.currentValues);
      }
    }
  }

  private toggleDiffPanel(): void {
    const diffBar = document.getElementById('bl-diff-bar');
    const diffContent = document.getElementById('bl-diff-content');
    if (!diffBar || !diffContent) return;

    const isExpanded = diffBar.classList.toggle('expanded');
    diffContent.style.display = isExpanded ? '' : 'none';
  }

  private updateCategoryStatus(category: BaselineCategory): void {
    const statusEl = document.getElementById(`bl-status-${category.id}`);
    if (!statusEl) return;

    let nonCompliantCount = 0;
    for (const item of category.items) {
      const val = this.currentValues.get(item.id) ?? '';
      const skipRecommended = ['按需设置', '按需配置', '无 NOPASSWD 条目', '非默认端口'];
      if (val && val !== 'not set' && val !== 'unknown' && val !== '...' && !skipRecommended.includes(item.recommendedValue) && val !== item.recommendedValue) {
        nonCompliantCount++;
      }
    }

    if (nonCompliantCount > 0) {
      statusEl.innerHTML = `<span style="color: var(--sev-high-fg); font-weight: 600;">${nonCompliantCount}</span>`;
    } else {
      statusEl.innerHTML = `<span style="color: var(--sev-success-fg);">${statusIcon('success', { size: 16 })}</span>`;
    }
  }

  // ─── 搜索过滤 ───

  private filterItems(query: string): void {
    const items = document.querySelectorAll('.bl-config-item');
    items.forEach(el => {
      const itemEl = el as HTMLElement;
      if (!query) {
        itemEl.style.display = '';
        return;
      }

      const nameEl = itemEl.querySelector('.bl-item-name');
      const descEl = itemEl.querySelector('.bl-item-desc');
      const name = (nameEl?.textContent || '').toLowerCase();
      const desc = (descEl?.textContent || '').toLowerCase();
      const match = name.includes(query) || desc.includes(query);
      itemEl.style.display = match ? '' : 'none';
    });
  }

  // ─── 变更历史 ───

  private getHistoryKey(): string {
    const server = (window as any).app?.stateManager?.getState()?.currentServer || 'unknown';
    return `bl-history-${server}`;
  }

  private saveHistory(changeList: Array<{ item: BaselineConfigItem; oldValue: string; newValue: string }>): void {
    try {
      const key = this.getHistoryKey();
      const history: ChangeHistoryEntry[] = JSON.parse(localStorage.getItem(key) || '[]');
      const server = (window as any).app?.stateManager?.getState()?.currentServer || 'unknown';

      history.unshift({
        timestamp: new Date().toLocaleString('zh-CN'),
        server,
        changes: changeList.map(c => ({
          name: c.item.name,
          oldValue: c.oldValue,
          newValue: c.newValue,
          itemId: c.item.id,
        })),
      });

      // 最多保留 100 条
      if (history.length > 100) history.length = 100;
      localStorage.setItem(key, JSON.stringify(history));
    } catch (e) {
      // localStorage 在隐私模式或配额已满时可能抛错, 仅记日志
      console.warn('[Baseline] 保存历史失败:', e);
    }
  }

  private async showHistory(): Promise<void> {
    const key = this.getHistoryKey();
    const history: ChangeHistoryEntry[] = JSON.parse(localStorage.getItem(key) || '[]');

    const renderer = (window as any).app?.modernUIRenderer?.baselineRenderer;
    if (!renderer) return;

    const content = renderer.renderHistoryModal(history);

    // 创建弹窗
    const overlay = document.createElement('div');
    overlay.className = 'bl-history-overlay';
    overlay.innerHTML = `
      <div class="bl-history-modal">
        <div class="bl-history-modal-header">
          <span class="bl-history-modal-title">变更历史</span>
          <button class="bl-history-modal-close" id="bl-history-close">&times;</button>
        </div>
        <div class="bl-history-modal-body">${content}</div>
      </div>
    `;

    document.body.appendChild(overlay);

    // 关闭事件
    const close = () => { overlay.remove(); };
    overlay.querySelector('#bl-history-close')?.addEventListener('click', close);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) close();
    });
    document.addEventListener('keydown', function handler(e) {
      if (e.key === 'Escape') { close(); document.removeEventListener('keydown', handler); }
    });
  }

  // ─── SSH 命令执行 ───

  private async executeCommand(command: string): Promise<string> {
    const result = await this.executeCommandResult(command);
    if (!result.success) {
      throw new Error(`${result.timedOut ? '命令执行超时' : `命令退出码 ${result.exitCode ?? '未知'}`}${result.output ? `: ${result.output}` : ''}`);
    }
    return result.output;
  }

  private async executeCommandResult(command: string): Promise<BaselineCommandReceipt> {
    const withTimeout = <T>(p: Promise<T>, ms = 30000): Promise<T> => {
      return new Promise<T>((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('执行超时')), ms);
        p.then(v => { clearTimeout(t); resolve(v); }, e => { clearTimeout(t); reject(e); });
      });
    };

    const result: any = await withTimeout(
      invokeTargetBoundSSH('ssh_execute_command_direct', { command }),
    );
    const output = typeof result?.output === 'string'
      ? result.output
      : typeof result?.stdout === 'string' ? result.stdout : '';
    const exitCode = typeof result?.exit_code === 'number' ? result.exit_code : null;
    const timedOut = result?.timed_out === true;
    return { output, exitCode, timedOut, success: !timedOut && exitCode === 0 };
  }

  private async executeBatchCommands(
    commands: string[],
    capturedTarget: TargetIdentity,
  ): Promise<Array<string | null>> {
    const results: Array<string | null> = [];
    for (const cmd of commands) {
      if (!activeTargetContext.matches(capturedTarget)) {
        throw new Error('批量读取期间活动目标已变化');
      }
      try {
        results.push(await this.executeCommand(cmd));
      } catch (error) {
        if (!activeTargetContext.matches(capturedTarget)) throw error;
        reportError(error, { module: 'Baseline', action: '批量执行命令', silent: true });
        results.push(null);
      }
    }
    return results;
  }

  // ─── 工具 ───

  private findItem(itemId: string): BaselineConfigItem | undefined {
    for (const cat of baselineCategories) {
      const item = cat.items.find(i => i.id === itemId);
      if (item) return item;
    }
    return undefined;
  }

  // ═══════════════════════════════════════════
  //  新增：模式切换 / 文件编辑 / 快捷操作
  // ═══════════════════════════════════════════

  private switchMode(mode: 'form' | 'editor' | 'actions'): void {
    // 更新 tab 激活
    document.querySelectorAll('.bl-mode-tab').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-bl-mode') === mode);
    });

    const mainEl = document.getElementById('bl-main');
    if (!mainEl) return;

    const renderer = (window as any).app?.modernUIRenderer?.baselineRenderer;
    if (!renderer) return;

    const diffBar = document.getElementById('bl-diff-bar');

    if (mode === 'form') {
      // 恢复表单模式
      if (diffBar) diffBar.style.display = this.pendingChanges.size > 0 ? '' : 'none';
      if (this.selectedCategoryId) {
        const cat = baselineCategories.find(c => c.id === this.selectedCategoryId);
        if (cat) { this.renderEditor(cat); return; }
      }
      mainEl.innerHTML = `
        <div class="bl-empty-state">
          <div class="bl-empty-title">选择一个配置分类</div>
          <div class="bl-empty-desc">从左侧选择需要编辑的配置分类</div>
        </div>
      `;
    } else if (mode === 'editor') {
      if (diffBar) diffBar.style.display = 'none';
      mainEl.innerHTML = renderer.renderFileEditorPanel(
        this.editorFilePath || undefined,
        this.editorFilePath ? this.editorOriginalContent : undefined,
        false,
        this.editorModified,
      );
      if (this.editorFilePath) this.setupEditorLineNumbers();
    } else if (mode === 'actions') {
      if (diffBar) diffBar.style.display = 'none';
      mainEl.innerHTML = renderer.renderQuickActionsPanel();
    }
  }

  // ─── 文件编辑 ───

  private async openFile(filePath: string): Promise<void> {
    const mainEl = document.getElementById('bl-main');
    const renderer = (window as any).app?.modernUIRenderer?.baselineRenderer;
    if (!mainEl || !renderer) return;
    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) {
      window.showNotification?.('没有已确认的活动 SSH 目标', 'warning');
      return;
    }

    try {
      filePath = validateEditableRemotePath(filePath);
    } catch (error) {
      window.showNotification?.(`无法打开文件：${error}`, 'error');
      return;
    }

    // 更新自定义路径输入
    const pathInput = document.getElementById('bl-custom-path') as HTMLInputElement;
    if (pathInput) pathInput.value = filePath;

    // 显示加载
    this.editorFilePath = filePath;
    mainEl.innerHTML = renderer.renderFileEditorPanel(filePath, undefined, true, false);

    // 更新选中状态
    document.querySelectorAll('.bl-file-chip').forEach(el => {
      el.classList.toggle('active', el.getAttribute('data-bl-filepath') === filePath);
    });

    try {
      const details = await invokeTargetBoundSSH<{ file_type: string; size: number }>('sftp_get_file_details', { path: filePath });
      if (!activeTargetContext.matches(capturedTarget)) throw new Error('读取文件期间活动目标已变化');
      if (details.file_type !== 'file') throw new Error(`仅允许编辑常规文件，当前类型：${details.file_type}`);
      if (details.size > 2 * 1024 * 1024) throw new Error('文件超过 2 MiB，为避免截断覆盖已阻止打开');
      const content = await invokeTargetBoundSSH<string>('sftp_read_file', { path: filePath, maxBytes: 2 * 1024 * 1024 });
      if (!activeTargetContext.matches(capturedTarget)) throw new Error('读取文件期间活动目标已变化');

      this.editorOriginalContent = content;
      this.editorModified = false;
      mainEl.innerHTML = renderer.renderFileEditorPanel(filePath, content, false, false);
      this.setupEditorLineNumbers();

    } catch (err) {
      if (!activeTargetContext.matches(capturedTarget)) {
        this.editorFilePath = '';
        this.editorOriginalContent = '';
        this.editorModified = false;
        window.showNotification?.('读取文件期间目标已变化，已丢弃结果', 'error');
        return;
      }
      mainEl.innerHTML = renderer.renderFileEditorPanel(filePath, `读取文件失败: ${err}`, false, false);
    }
  }

  private setupEditorLineNumbers(): void {
    const textarea = document.getElementById('bl-file-textarea') as HTMLTextAreaElement;
    const lineNumbers = document.getElementById('bl-line-numbers');
    if (!textarea || !lineNumbers) return;

    const updateLineNumbers = () => {
      const lines = textarea.value.split('\n').length;
      lineNumbers.innerHTML = Array.from({ length: lines }, (_, i) => `<div>${i + 1}</div>`).join('');
    };

    updateLineNumbers();

    textarea.addEventListener('input', () => {
      updateLineNumbers();
      this.editorModified = textarea.value !== this.editorOriginalContent;
      const saveBtn = document.getElementById('bl-file-save-btn') as HTMLButtonElement;
      if (saveBtn) saveBtn.disabled = !this.editorModified;
      // 更新修改标记
      const badge = document.querySelector('.bl-file-editor-toolbar .bl-modified-badge');
      if (badge) (badge as HTMLElement).style.display = this.editorModified ? '' : 'none';
    });

    textarea.addEventListener('scroll', () => {
      lineNumbers.scrollTop = textarea.scrollTop;
    });

    // Ctrl+S 保存
    textarea.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        this.saveCurrentFile();
      }
      // Tab 缩进
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        textarea.value = textarea.value.substring(0, start) + '    ' + textarea.value.substring(end);
        textarea.selectionStart = textarea.selectionEnd = start + 4;
        textarea.dispatchEvent(new Event('input'));
      }
    });
  }

  private async saveCurrentFile(): Promise<void> {
    const textarea = document.getElementById('bl-file-textarea') as HTMLTextAreaElement;
    if (!textarea || !this.editorFilePath) return;

    let path: string;
    try { path = validateEditableRemotePath(this.editorFilePath); }
    catch (error) {
      window.showNotification?.(`保存失败：${error}`, 'error');
      return;
    }
    const newContent = textarea.value;
    const target = activeTargetContext.get();
    if (!target) {
      window.showNotification?.('请先连接并确认目标主机', 'error');
      return;
    }
    const confirmed = await showConfirm({
      title: '备份并保存配置文件',
      message: `目标：${target.username}@${target.host}:${target.port}\n指纹：${target.hostKeyFingerprint}\n\n文件：${path}\n\n将原子写入并读回校验，原文件保留为独立备份。`,
      confirmText: '保存并验证', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
    });
    if (!confirmed) return;
    const saveBtn = document.getElementById('bl-file-save-btn') as HTMLButtonElement;
    if (saveBtn) { saveBtn.disabled = true; saveBtn.textContent = '保存中...'; }

    try {
      const backupPath = buildEditorBackupPath(path);
      const beforeHash = await contentSha256(this.editorOriginalContent);
      const afterHash = await contentSha256(newContent);
      const receipt = await invokeTargetBoundSSH<{
        backup_path: string; bytes_written: number; preserved_permissions?: number;
      }>('sftp_atomic_write_file', { path, backupPath, content: newContent });
      let readBackHash = '';
      let verified = false;
      let verifyError = '';
      try {
        const readBack = await invokeTargetBoundSSH<string>('sftp_read_file', { path, maxBytes: 2 * 1024 * 1024 });
        readBackHash = await contentSha256(readBack);
        verified = readBack === newContent && readBackHash === afterHash;
      } catch (error) {
        verifyError = String(error);
      }
      operationJournal.record({
        source: 'baseline', server: target.host, target,
        title: `编辑配置文件 ${path}`,
        command: `SFTP atomic write ${path}`,
        restoreCommand: `cp -p -- ${shq(receipt.backup_path)} ${shq(path)}`,
        restoreVerifyCommand: `sha256sum -- ${shq(path)} | awk '{print $1}'`,
        restoreVerifyExpected: beforeHash,
        beforeValue: beforeHash, afterValue: afterHash,
        backupInfo: `${receipt.backup_path} · 保留权限 ${receipt.preserved_permissions ?? 'unknown'}`,
        output: `后端事务写入并逐字节验证 ${receipt.bytes_written} bytes`, exitCode: 0, timedOut: false,
        verifyCommand: `SFTP independent read-back ${path}`, verifyOutput: readBackHash || verifyError,
        verified, success: true,
      });
      if (!verified) throw new Error(`独立读回验证未通过，后端事务验证已通过且原文件备份仍保留${verifyError ? `：${verifyError}` : ''}`);

      this.editorOriginalContent = newContent;
      this.editorModified = false;
      window.showNotification?.(`${this.editorFilePath} 已保存（已备份原文件）`, 'success');

    } catch (err) {
      reportError(err, { module: 'Baseline', action: '保存配置文件', silent: true });
      window.showNotification?.(`保存失败: ${err}`, 'error');
    } finally {
      if (saveBtn) { saveBtn.disabled = false; saveBtn.textContent = '备份并保存'; }
    }
  }

  // ─── 快捷操作 ───

  private async executeQuickAction(actionId: string): Promise<void> {
    const paramInput = document.getElementById(`bl-qa-input-${actionId}`) as HTMLInputElement;
    const param = paramInput?.value?.trim() || '';

    // 参数校验与命令生成都在 quickActionCommands.ts（纯函数，有单测覆盖）。
    // 这些命令以 root 在靶机执行，是全项目风险最高的拼接点，务必保持二者同源。
    const check = checkQuickActionParam(actionId, param);
    if (!check.ok) {
      window.showNotification?.(check.hint, check.reason === 'missing' ? 'warning' : 'error');
      paramInput?.focus();
      return;
    }

    const built = buildQuickActionCommand(actionId, param, this.detectedDistro);
    if (!built) { window.showNotification?.('未知操作', 'error'); return; }
    const { cmd, desc, dangerous } = built;
    const readOnlyActions = new Set([
      'who-online', 'query-user-chage', 'query-ssh-version', 'query-kernel', 'query-login-defs',
      'query-user-sudo-log', 'query-malicious-ports', 'query-suspicious-users', 'query-all-listening',
    ]);
    const mutating = !readOnlyActions.has(actionId);
    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) {
      window.showNotification?.('请先连接并确认目标主机', 'error');
      return;
    }

    // 所有状态变更都确认；破坏性动作使用危险样式并默认聚焦取消。
    if (mutating) {
      const ok = await showConfirm({
        title: '确认执行',
        message: `目标：${capturedTarget.username}@${capturedTarget.host}:${capturedTarget.port}\n指纹：${capturedTarget.hostKeyFingerprint}\n\n${desc}\n\n命令: ${cmd}`,
        confirmText: '执行',
        cancelText: '取消',
        dangerous: Boolean(dangerous),
        defaultFocus: 'cancel',
      });
      if (!ok) return;
    }

    // 执行
    const execBtn = document.querySelector(`[data-bl-action="exec-quick-action"][data-bl-qa-id="${actionId}"]`) as HTMLButtonElement;
    if (execBtn) { execBtn.disabled = true; execBtn.textContent = '执行中...'; }

    try {
      if (!activeTargetContext.matches(capturedTarget)) throw new Error('确认后活动目标已变化，已停止执行');
      const receipt = await this.executeCommandResult(cmd);
      if (mutating) {
        operationJournal.record({
          source: 'baseline', server: capturedTarget.host, target: capturedTarget,
          title: desc, command: cmd, output: receipt.output,
          exitCode: receipt.exitCode, timedOut: receipt.timedOut, success: receipt.success,
        });
      }
      if (!receipt.success) throw new Error(`${receipt.timedOut ? '执行超时' : `退出码 ${receipt.exitCode ?? '未知'}`}: ${receipt.output}`);
      const output = receipt.output;
      window.showNotification?.(`${desc} — 完成`, 'success');

      // 对于有输出的命令（如 who-online），显示结果
      // 查询类操作展示结果
      const showResultActions = ['who-online', 'query-user-chage', 'query-ssh-version', 'query-kernel',
        'query-login-defs', 'query-user-sudo-log', 'query-malicious-ports', 'query-suspicious-users', 'query-all-listening'];
      if (output.trim() && showResultActions.includes(actionId)) {
        await showAlert({ title: desc, message: output.substring(0, 2000), type: 'info' });
      }
    } catch (err) {
      reportError(err, { module: 'Baseline', action: `快捷操作 ${actionId}`, silent: true });
      window.showNotification?.(`${desc} — 失败: ${err}`, 'error');
    } finally {
      if (execBtn) {
        execBtn.disabled = false;
        execBtn.textContent = (QUICK_ACTIONS_NEEDING_PARAM as readonly string[]).includes(actionId) ? '执行' : '一键执行';
      }
    }
  }
}
