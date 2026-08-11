/**
 * 修复执行引擎 — 备份 → 修复 → 验证 → 记录
 */

import type { FixActionDef } from './detectionFixMapper';
import { fixHistoryManager, type FixHistoryEntry } from './fixHistoryManager';
import { operationJournal } from '../core/operationJournal';
import { executeEmergencyCommand } from '../emergency/commandExecution';
import { shq } from '../core/shellEscape';

export type FixStatus = 'pending' | 'executing' | 'success' | 'failed' | 'rolled-back';

export interface FixAction {
  id: string;
  detectionItemId: string;
  findingTitle: string;
  def: FixActionDef;
  status: FixStatus;
  currentValue?: string;
  afterValue?: string;
  output?: string;
  error?: string;
}

export interface FixResult {
  action: FixAction;
  success: boolean;
  beforeValue?: string;
  afterValue?: string;
  output: string;
}

// 基线配置项解析后的可执行数据
export interface ResolvedBaselineItem {
  id: string;
  filePath: string;
  readCommand: string;
  writeCommand: (value: string) => string;
  parseRegex: string;
  backupCommand: string;
  restartCommand?: string;
  recommendedValue: string;
}

class FixExecutor {
  private server: string = '';

  setServer(server: string): void {
    this.server = server;
  }

  /** 执行单个修复动作 */
  async executeFix(
    action: FixAction,
    resolvedBaseline?: ResolvedBaselineItem,
    onStatus?: (action: FixAction) => void
  ): Promise<FixResult> {
    action.status = 'executing';
    onStatus?.(action);

    let output = '';
    let beforeValue = '';
    let afterValue = '';
    let backupInfo = '';
    let restoreCommand: string | undefined;
    let restoreVerifyCommand: string | undefined;
    let restoreVerifyPattern: string | undefined;
    let restoreExpectedValue: string | undefined;

    try {
      if (action.def.type === 'baseline' && resolvedBaseline) {
        // 1. 读取当前值
        const readOut = await this.exec(resolvedBaseline.readCommand);
        const match = new RegExp(resolvedBaseline.parseRegex).exec(readOut);
        beforeValue = match?.[1]?.trim() || readOut.trim();
        action.currentValue = beforeValue;

        // 2. 确定性备份：路径进入 receipt，回滚不再靠猜时间戳
        const backupPath = `${resolvedBaseline.filePath}.lovelyres.${Date.now()}.${action.id}.bak`;
        const backupState = await this.exec(
          `if [ -e ${shq(resolvedBaseline.filePath)} ]; then cp -p -- ${shq(resolvedBaseline.filePath)} ${shq(backupPath)} && printf present; else printf absent; fi`,
        );
        const originalPresent = backupState.trim().endsWith('present');
        backupInfo = originalPresent ? backupPath : '原文件不存在';
        const restoreFile = originalPresent
          ? `cp -p -- ${shq(backupPath)} ${shq(resolvedBaseline.filePath)}`
          : `rm -f -- ${shq(resolvedBaseline.filePath)}`;
        restoreCommand = resolvedBaseline.restartCommand
          ? `${restoreFile} && ${resolvedBaseline.restartCommand}`
          : restoreFile;
        restoreVerifyCommand = originalPresent
          ? resolvedBaseline.readCommand
          : `test ! -e ${shq(resolvedBaseline.filePath)} && echo absent`;
        restoreVerifyPattern = originalPresent ? resolvedBaseline.parseRegex : '(absent)';
        restoreExpectedValue = originalPresent ? beforeValue : 'absent';

        // 3. 写入推荐值
        const writeCmd = resolvedBaseline.writeCommand(action.def.recommendedValue || resolvedBaseline.recommendedValue);
        output = await this.exec(writeCmd);

        // 4. 重启服务 (如需)
        if (resolvedBaseline.restartCommand) {
          output += '\n' + await this.exec(resolvedBaseline.restartCommand);
        }

        // 5. 读回验证
        const verifyOut = await this.exec(resolvedBaseline.readCommand);
        const verifyMatch = new RegExp(resolvedBaseline.parseRegex).exec(verifyOut);
        if (!verifyMatch?.[1]) {
          throw new Error(`读回验证失败，无法解析配置项 ${resolvedBaseline.id}`);
        }
        afterValue = verifyMatch[1].trim();
        action.afterValue = afterValue;
        const expected = (action.def.recommendedValue || resolvedBaseline.recommendedValue).trim();
        if (afterValue.replace(/\s+/g, ' ').toLowerCase() !== expected.replace(/\s+/g, ' ').toLowerCase()) {
          throw new Error(`读回验证不一致：期望 ${expected}，实际 ${afterValue}`);
        }

      } else if (action.def.type === 'command' && action.def.command) {
        output = await this.exec(action.def.command);

      } else if (action.def.type === 'snippet') {
        throw new Error(`代码片段 ${action.def.snippetId} 需要在安全速查页面人工确认后执行`);
      }

      action.status = 'success';
      action.output = output;
      onStatus?.(action);

      // 记录到历史
      fixHistoryManager.addEntry({
        detectionItemId: action.detectionItemId,
        findingTitle: action.findingTitle,
        fixTitle: action.def.title,
        type: action.def.type,
        baselineItemId: action.def.baselineItemId,
        beforeValue,
        afterValue,
        backupInfo,
        restoreCommand,
        restoreVerifyCommand,
        restoreVerifyPattern,
        restoreExpectedValue,
        command: action.def.command,
        output,
        success: true,
        server: this.server,
      });
      // 桥接到统一操作日志，使检测修复也出现在"快照与回滚中心"
      operationJournal.record({
        source: action.def.type === 'baseline' ? 'baseline' : 'detection-fix',
        server: this.server,
        title: action.def.title,
        command: action.def.command || (resolvedBaseline ? resolvedBaseline.writeCommand(action.def.recommendedValue || resolvedBaseline.recommendedValue) : ''),
        beforeValue,
        afterValue,
        backupInfo,
        restoreCommand,
        output,
        success: true,
      });

      return { action, success: true, beforeValue, afterValue, output };

    } catch (e: any) {
      action.status = 'failed';
      action.error = String(e);
      action.output = String(e);
      onStatus?.(action);

      fixHistoryManager.addEntry({
        detectionItemId: action.detectionItemId,
        findingTitle: action.findingTitle,
        fixTitle: action.def.title,
        type: action.def.type,
        baselineItemId: action.def.baselineItemId,
        beforeValue,
        afterValue,
        backupInfo,
        restoreCommand,
        restoreVerifyCommand,
        restoreVerifyPattern,
        restoreExpectedValue,
        command: action.def.command,
        output: String(e),
        success: false,
        server: this.server,
      });
      operationJournal.record({
        source: action.def.type === 'baseline' ? 'baseline' : 'detection-fix',
        server: this.server,
        title: action.def.title,
        command: action.def.command || (resolvedBaseline ? resolvedBaseline.writeCommand(action.def.recommendedValue || resolvedBaseline.recommendedValue) : ''),
        beforeValue,
        afterValue,
        backupInfo,
        restoreCommand,
        output: String(e),
        success: false,
      });

      return { action, success: false, output: String(e) };
    }
  }

  /** 批量执行修复，按 priority 排序，同服务的 restart 去重 */
  async executeBatch(
    actions: FixAction[],
    resolvedBaselines: Map<string, ResolvedBaselineItem>,
    onStatus?: (action: FixAction) => void,
    onProgress?: (completed: number, total: number) => void,
  ): Promise<FixResult[]> {
    const sorted = [...actions].sort((a, b) => a.def.priority - b.def.priority);
    const results: FixResult[] = [];
    const restarted = new Set<string>();

    for (let i = 0; i < sorted.length; i++) {
      const action = sorted[i];
      const baseline = action.def.baselineItemId ? resolvedBaselines.get(action.def.baselineItemId) : undefined;

      // 去重 restart: 如果后续还有同服务的修复，先不重启
      if (baseline?.restartCommand && action.def.requiresRestart) {
        const hasMore = sorted.slice(i + 1).some(a => a.def.requiresRestart === action.def.requiresRestart);
        if (hasMore) {
          // 暂时去掉 restart，最后一个同服务的修复再重启
          const noRestart = { ...baseline, restartCommand: undefined };
          const r = await this.executeFix(action, noRestart, onStatus);
          results.push(r);
        } else {
          // 最后一个同服务的修复，执行重启
          if (!restarted.has(action.def.requiresRestart)) {
            const r = await this.executeFix(action, baseline, onStatus);
            results.push(r);
            restarted.add(action.def.requiresRestart);
          } else {
            const noRestart = { ...baseline, restartCommand: undefined };
            const r = await this.executeFix(action, noRestart, onStatus);
            results.push(r);
          }
        }
      } else {
        const r = await this.executeFix(action, baseline, onStatus);
        results.push(r);
      }

      onProgress?.(i + 1, sorted.length);
    }

    return results;
  }

  /** 回滚一个历史条目 */
  async rollback(entry: FixHistoryEntry): Promise<{ success: boolean; output: string }> {
    return fixHistoryManager.rollback(entry.id);
  }

  /** SSH 命令执行 */
  private async exec(cmd: string): Promise<string> {
    try {
      const result = await executeEmergencyCommand({ command: cmd });
      if (!result.success) throw new Error(`${result.message}${result.output ? `: ${result.output}` : ''}`);
      return result.output;
    } catch (e) {
      throw new Error(`命令执行失败: ${e}`);
    }
  }
}

export const fixExecutor = new FixExecutor();
