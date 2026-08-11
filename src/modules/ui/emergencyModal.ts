

import { logger } from '../core/logger';
import { activeTargetContext } from '../core/targetContext';
/** 正式包 drop 掉 console，诊断信息只有进 logger 才留得下来（状态栏「日志」按钮可导出） */
const log = logger.module('EmergencyModal');
// EmergencyResultModal - 显示命令执行结果（命令 + 输出 + 搜索高亮）

import * as IconPark from '@icon-park/svg'
import { CommandHistoryManager, type CommandHistoryItem } from '../utils/commandHistoryManager'
import { createIconHTML } from './iconMapping'
import { aiService } from '../ai/aiService'
import { commandOutputPrompt } from '../ai/aiPrompts'
import { createAICancelButton, renderAIMarkdown } from '../ai/aiOutput'
import { deriveMeta } from '../emergency/emergencyView'
import { executeEmergencyCommand } from '../emergency/commandExecution'
import { showConfirm } from './confirmDialog'

export class EmergencyResultModal {
  private modal: HTMLElement | null = null;
  private titleEl: HTMLElement | null = null;
  private commandEl: HTMLElement | null = null;
  private outputEl: HTMLElement | null = null;
  private searchInput: HTMLInputElement | null = null;
  private isVisible = false;
  private originalOutput = '';
  private commandText = '';
  private currentTitle = '';
  private isEditMode = false;
  private eventsBound = false;
  private keydownHandler: ((event: KeyboardEvent) => void) | null = null;

  constructor() {
    this.createModal();
    if (!this.eventsBound) {
      this.bindEvents();
      this.eventsBound = true;
    }
  }

  private createModal(): void {
    log.debug('创建 EmergencyResultModal DOM');
    const existing = document.getElementById('emergency-result-modal');
    if (existing) {
      log.debug('EmergencyResultModal 已存在，跳过创建');
      this.modal = existing;
      this.titleEl = document.getElementById('em-modal-title');
      this.commandEl = document.getElementById('em-modal-command');
      this.outputEl = document.getElementById('em-modal-content');
      this.searchInput = document.getElementById('em-modal-search') as HTMLInputElement | null;
      return;
    }

    const html = `
      <div id="emergency-result-modal" class="em-result-modal">
        <div class="em-modal-container">
          <div class="em-modal-header">
            <div class="em-modal-title-group">
              <span style="font-size:16px">${createIconHTML('📄', { size: 16 })}</span>
              <h3 id="em-modal-title" class="em-modal-title">命令输出</h3>
            </div>
            <div class="em-modal-actions">
              <input id="em-modal-search" type="text" class="em-modal-search" placeholder="在输出中搜索..." autocomplete="off">
              <button id="em-modal-ai-explain" class="modern-btn secondary" style="
                font-size: 12px;
                padding: 6px 10px;
                display: flex;
                align-items: center;
                gap: 6px;
              ">
                ${IconPark.Brain({ theme: 'outline', size: '16', fill: 'currentColor' })}
                <span>AI解释</span>
              </button>
              <button id="em-modal-copy" class="modern-btn secondary" style="font-size:12px; padding:6px 10px;">复制输出</button>
              <button id="em-modal-close" class="modern-btn secondary" style="font-size:12px; padding:6px 10px;">关闭</button>
            </div>
          </div>
          
          <div class="em-modal-body">
            <div class="em-modal-command-card">
              <div class="em-modal-command-header">
                <span class="em-modal-command-label">执行命令</span>
                <div class="em-modal-command-actions">
                  <button id="em-modal-edit-btn" class="modern-btn secondary" style="
                    font-size: 12px;
                    padding: 4px 8px;
                    display: flex;
                    align-items: center;
                    gap: 4px;
                  ">
                    ${IconPark.Edit({ theme: 'outline', size: '14', fill: 'currentColor' })}
                    <span>修改</span>
                  </button>
                  <button id="em-modal-execute-btn" class="modern-btn primary" style="
                    font-size: 12px;
                    padding: 4px 8px;
                    display: flex;
                    align-items: center;
                    gap: 4px;
                  ">
                    ${IconPark.Play({ theme: 'outline', size: '14', fill: 'currentColor' })}
                    <span>执行</span>
                  </button>
                </div>
              </div>
              <code id="em-modal-command" class="em-modal-command-code" contenteditable="false"></code>
            </div>

            <div class="em-modal-output-container">
              <div class="em-modal-output-scroll">
                <pre id="em-modal-content" class="em-modal-output-content"></pre>
              </div>
              
              <div id="em-modal-ai-explanation" class="em-modal-ai-box">
                <div class="em-modal-ai-header">
                  ${IconPark.Brain({ theme: 'outline', size: '18', fill: 'currentColor' })}
                  <span>AI解释</span>
                </div>
                <div id="em-modal-ai-explanation-content" class="em-modal-ai-content"></div>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', html);
    this.modal = document.getElementById('emergency-result-modal');
    this.titleEl = document.getElementById('em-modal-title');
    this.commandEl = document.getElementById('em-modal-command');
    this.outputEl = document.getElementById('em-modal-content');
    this.searchInput = document.getElementById('em-modal-search') as HTMLInputElement | null;
  }


  private bindEvents(): void {
    log.debug('绑定 EmergencyResultModal 事件监听器');

    document.getElementById('em-modal-close')?.addEventListener('click', () => this.hide());
    this.modal?.addEventListener('click', (event) => {
      if (event.target === this.modal) this.hide();
    });

    // 保存 keydown 处理器的引用，以便后续可以移除
    this.keydownHandler = (event: KeyboardEvent) => {
      if (!this.isVisible) return;
      if (event.key === 'Escape') this.hide();
    };
    document.addEventListener('keydown', this.keydownHandler);
    document.getElementById('em-modal-copy')?.addEventListener('click', () => {
      navigator.clipboard.writeText(this.originalOutput).then(() => {
        window.showNotification?.('命令输出已复制', 'success');
      }).catch((error) => {
        log.error('复制失败', error);
        window.showNotification?.('复制失败', 'error');
      });
    });

    // AI解释按钮
    document.getElementById('em-modal-ai-explain')?.addEventListener('click', () => {
      this.explainWithAI();
    });

    // 修改按钮
    document.getElementById('em-modal-edit-btn')?.addEventListener('click', () => {
      this.toggleEditMode();
    });

    // 执行按钮
    document.getElementById('em-modal-execute-btn')?.addEventListener('click', () => {
      this.executeCommand();
    });

    if (this.searchInput) {
      let timer: number | null = null;
      this.searchInput.addEventListener('input', () => {
        if (timer) window.clearTimeout(timer);
        const value = this.searchInput?.value ?? '';
        timer = window.setTimeout(() => {
          this.renderOutput(value.trim() || undefined);
        }, 150);
      });
    }
  }

  show(title: string, command: string, output: unknown): void {
    log.debug('\u2728 EmergencyResultModal.show', { title, hasModal: !!this.modal });
    if (!this.modal) {
      log.warn('EmergencyResultModal.show: modal 不存在，尝试重新创建');
      this.createModal();
      this.bindEvents();
      if (!this.modal) {
        log.error('EmergencyResultModal.show: 仍然无法创建 modal');
        return;
      }
    }

    this.originalOutput = this.normalizeOutput(output);
    this.commandText = command || '';
    this.currentTitle = title || '命令输出';
    this.isEditMode = false;

    if (this.titleEl) this.titleEl.textContent = this.currentTitle;
    if (this.commandEl) {
      this.commandEl.textContent = this.commandText || '（无命令）';
      this.commandEl.setAttribute('contenteditable', 'false');
      this.commandEl.classList.remove('editing');
    }
    if (this.searchInput) this.searchInput.value = '';

    // 重置AI解释区域
    const aiExplanationEl = document.getElementById('em-modal-ai-explanation');
    if (aiExplanationEl) {
      aiExplanationEl.style.display = 'none';
      const aiContentEl = document.getElementById('em-modal-ai-explanation-content');
      if (aiContentEl) aiContentEl.textContent = '';
    }

    // 更新编辑按钮文本
    const editBtn = document.getElementById('em-modal-edit-btn');
    if (editBtn) {
      editBtn.innerHTML = `${IconPark.Edit({ theme: 'outline', size: '14', fill: 'currentColor' })}<span>修改</span>`;
    }

    this.renderOutput();
    this.modal.style.display = 'flex';
    this.isVisible = true;
  }

  /** 命令历史的唯一重放入口；在展示和执行前再次校验目标与摘要。 */
  async replayHistoryItem(item: CommandHistoryItem): Promise<boolean> {
    try {
      const assessment = await CommandHistoryManager.assessReplay(item);
      if (!assessment.allowed) {
        window.showNotification?.(assessment.reason, 'warning');
        return false;
      }
      this.show(item.title, item.command, '准备重新执行已验证的历史命令…');
      return await this.executeCommand('command-history-replay');
    } catch (error) {
      log.error('校验历史命令失败', error);
      window.showNotification?.(`无法重新执行: ${error}`, 'error');
      return false;
    }
  }

  hide(): void {
    if (!this.modal) return;
    this.modal.style.display = 'none';
    this.isVisible = false;
  }

  private renderOutput(searchTerm?: string): void {
    if (!this.outputEl) return;
    const safe = this.escapeHtml(this.originalOutput);
    if (!safe) {
      this.outputEl.innerHTML = '';
      return;
    }
    if (!searchTerm || searchTerm.length === 0) {
      this.outputEl.innerHTML = safe;
      return;
    }
    const regex = new RegExp(this.escapeRegExp(searchTerm), 'gi');
    this.outputEl.innerHTML = safe.replace(regex, (match) => `<mark>${match}</mark>`);
  }

  private normalizeOutput(output: unknown): string {
    if (output == null) {
      return '';
    }
    if (typeof output === 'string') {
      return output;
    }
    if (typeof output === 'number' || typeof output === 'boolean') {
      return String(output);
    }
    if (output instanceof Uint8Array) {
      try {
        return new TextDecoder().decode(output);
      } catch (error) {
        log.warn('无法解码 Uint8Array 输出', error);
        return '[binary data]';
      }
    }
    try {
      return JSON.stringify(output, null, 2);
    } catch (error) {
      log.warn('无法序列化命令输出', error);
      return String(output);
    }
  }

  private escapeHtml(input: string): string {
    return (input || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  private escapeRegExp(input: string): string {
    return input.replace(/[-\^$*+?.()|[\]{}]/g, '\\$&');
  }

  /**
   * 切换编辑模式
   */
  private toggleEditMode(): void {
    this.isEditMode = !this.isEditMode;
    const commandEl = this.commandEl;
    const editBtn = document.getElementById('em-modal-edit-btn');

    if (!commandEl || !editBtn) return;

    if (this.isEditMode) {
      // 进入编辑模式
      commandEl.setAttribute('contenteditable', 'true');
      commandEl.classList.add('editing');
      commandEl.focus();
      editBtn.innerHTML = `${IconPark.Save({ theme: 'outline', size: '14', fill: 'currentColor' })}<span>保存</span>`;
      editBtn.classList.remove('secondary');
      editBtn.classList.add('primary');
    } else {
      // 退出编辑模式，保存修改
      commandEl.setAttribute('contenteditable', 'false');
      commandEl.classList.remove('editing');
      this.commandText = commandEl.textContent || '';
      editBtn.innerHTML = `${IconPark.Edit({ theme: 'outline', size: '14', fill: 'currentColor' })}<span>修改</span>`;
      editBtn.classList.remove('primary');
      editBtn.classList.add('secondary');

      window.showNotification?.('命令已更新', 'success');
    }
  }


  /**
   * 执行命令
   */
  private async executeCommand(source = 'emergency-modal'): Promise<boolean> {
    const commandEl = this.commandEl;
    if (!commandEl) return false;

    // 如果在编辑模式，先保存
    if (this.isEditMode) {
      this.toggleEditMode();
    }

    const command = commandEl.textContent?.trim() || '';
    if (!command) {
      window.showNotification?.('命令不能为空', 'warning');
      return false;
    }

    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) {
      window.showNotification?.('没有已确认的活动 SSH 目标，请先连接服务器', 'warning');
      return false;
    }

    const risk = deriveMeta(command);
    if (!risk.readonly) {
      const targetLabel = `${capturedTarget.username}@${capturedTarget.host}:${capturedTarget.port}`;
      const confirmed = await showConfirm({
        title: '确认执行可写命令',
        description: `目标指纹：${capturedTarget.hostKeyFingerprint}`,
        message: `精确目标：${targetLabel}\n\n命令：\n${command}`,
        confirmText: '在此目标执行',
        dangerous: true,
        defaultFocus: 'cancel',
      });
      if (!confirmed) return false;
      if (!activeTargetContext.matches(capturedTarget)) {
        window.showNotification?.('确认期间活动目标已变化，已阻止执行', 'error');
        return false;
      }
    }

    // 显示执行中状态
    const executeBtn = document.getElementById('em-modal-execute-btn');
    if (executeBtn) {
      executeBtn.textContent = '执行中...';
      (executeBtn as HTMLButtonElement).disabled = true;
    }

    try {
      const result = await executeEmergencyCommand({ command, timeoutSec: 120 });
      const output = result.output;
      const displayedCommand = result.command;
      const exitCode = result.exit_code;
      const timedOut = result.timed_out;

      // 更新显示
      this.originalOutput = output;
      this.commandText = displayedCommand;
      if (this.commandEl) this.commandEl.textContent = displayedCommand;
      this.renderOutput();

      // 隐藏AI解释（因为是新的输出）
      const aiExplanationEl = document.getElementById('em-modal-ai-explanation');
      if (aiExplanationEl) {
        aiExplanationEl.style.display = 'none';
      }

      // 保存到命令历史
      await CommandHistoryManager.saveCommand(displayedCommand, this.currentTitle, output, exitCode, source);

      if (timedOut) {
        window.showNotification?.('命令执行超时，输出已更新', 'warning');
      } else if (typeof exitCode === 'number' && exitCode !== 0) {
        window.showNotification?.(`命令执行完成，但退出码为 ${exitCode}`, output ? 'warning' : 'error');
      } else {
        window.showNotification?.('命令执行成功', 'success');
      }
      return result.success;
    } catch (error) {
      log.error('执行命令失败:', error);
      window.showNotification?.(`执行失败: ${error}`, 'error');
      return false;
    } finally {
      // 恢复按钮状态
      if (executeBtn) {
        executeBtn.innerHTML = `${IconPark.Play({ theme: 'outline', size: '14', fill: 'currentColor' })}<span>执行</span>`;
        (executeBtn as HTMLButtonElement).disabled = false;
      }
    }
  }

  /**
   * 使用AI解释当前内容
   */
  private async explainWithAI(): Promise<void> {

    const aiExplanationEl = document.getElementById('em-modal-ai-explanation');
    const aiContentEl = document.getElementById('em-modal-ai-explanation-content');

    if (!aiExplanationEl || !aiContentEl) return;

    // 显示AI解释区域
    aiExplanationEl.style.display = 'block';
    aiContentEl.textContent = 'AI正在分析...';

    // 取消按钮挂在 AI 区域头部；流注册成功后经 onStart 拿到 cancel 句柄
    const headerEl = aiExplanationEl.querySelector('.em-modal-ai-header');
    // 清掉上一轮可能残留的取消按钮（header 内唯一的 button 就是它）
    headerEl?.querySelector('button')?.remove();
    let cancelBtn: HTMLButtonElement | null = null;
    const removeCancelBtn = () => {
      cancelBtn?.remove();
      cancelBtn = null;
    };

    try {
      const prompt = commandOutputPrompt(this.currentTitle, this.commandText, this.originalOutput);

      // 清空"正在分析"提示
      aiContentEl.textContent = '';

      const { text } = await aiService.streamOpenAICompatible(
        prompt,
        // 流式期间用 textContent 纯文本增量更新（每 chunk 渲染 markdown 太贵）
        (chunk: string) => {
          aiContentEl.textContent += chunk;
        },
        {
          onStart: (cancel) => {
            if (!headerEl) return;
            cancelBtn = createAICancelButton(cancel);
            cancelBtn.style.cssText = 'margin-left: auto; font-size: 12px; padding: 4px 8px;';
            headerEl.appendChild(cancelBtn);
          },
        },
      );
      log.debug('AI生成的解释:', text);
      // 完成后一次性渲染 markdown
      renderAIMarkdown(aiContentEl, text);
    } catch (error) {
      if ((error as Error)?.name === 'AbortError') {
        aiContentEl.textContent += '\n\n（已取消生成）';
      } else {
        aiContentEl.textContent = `AI解释失败: ${error}\n\n提示：请在设置中配置AI，或者检查AI服务是否可用。`;
      }
    } finally {
      removeCancelBtn();
    }
  }
}
