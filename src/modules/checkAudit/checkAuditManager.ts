/**
 * Check 审计管理器 (Check专武)
 * 劫持系统命令记录 check 脚本行为，逆向分析 check 逻辑
 */

import { invokeTargetBoundSSH } from '../core/targetBoundSSH';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { showConfirm } from '../ui/confirmDialog';
import { operationJournal } from '../core/operationJournal';
import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import { shq } from '../core/shellEscape';
import { logger } from '../core/logger';
import { reportError } from '../utils/errorHandler';

// ──── 类型 ────

export type CaTab = 'hijack' | 'audit-log' | 'analysis' | 'quick-fix';
export type HijackStatus = 'original' | 'hijacked' | 'missing' | 'checking';

export interface HijackCommand {
  name: string;
  path: string;
  status: HijackStatus;
  origPath: string;
  custom: boolean;
  journalEntryId?: string;
}

export interface AuditLogEntry {
  timestamp: string;
  command: string;
  args: string;
  user: string;
  pid: number;
  ppid: number;
  caller: string;
  raw: string;
}

export interface CheckCycle {
  command: string;
  args: string;
  intervalSeconds: number | null;
  count: number;
  lastSeen: string;
  category: string;
}

export interface FixSuggestion {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  checkCommand: string;
  fixCommand: string;
  category: string;
}

// ──── 常量 ────

const LOG_PATH = '/tmp/.cmd_audit.log';
// 默认只劫持 check 脚本最常用的：读文件 + shell 解释器 + 网络请求
const DEFAULT_COMMANDS = [
  'cat', 'head', 'tail', 'more', 'less',   // 读文件
  'grep', 'awk', 'sed',                     // 文本处理
  'bash', 'sh',                             // shell 解释器
  'curl', 'wget',                           // 网络请求
  'mysql', 'redis-cli', 'psql', 'mongo',    // 数据库客户端
];
const SUSPICIOUS_RE = [
  /flag/i, /\/etc\/passwd/, /\/etc\/shadow/, /\.ssh/,
  /secret/i, /token/i, /password/i, /key[_.]?file/i,
];
const LOG_LINE_RE = /^\[(.+?)\] CMD=(\S+) ARGS=(.*?) USER=(\S+) PID=(\d+) PPID=(\d+) CALLER=(.*)$/;
const COMMAND_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$/;
const log = logger.module('CheckAudit');

interface AuditCommandResult {
  output: string;
  exitCode: number | null;
  timedOut: boolean;
  success: boolean;
}

export interface HijackCommandPlan {
  origPath: string;
  backupCommand: string;
  writeCommand: string;
  verifyCommand: string;
  functionalVerifyCommand: string;
  restoreCommand: string;
  restoreVerifyCommand: string;
}

export function isValidAbsoluteCommandPath(path: string): boolean {
  return path.length > 1 && path.length <= 4096
    && path.startsWith('/')
    && !path.split('/').includes('..')
    && /^\/[A-Za-z0-9._+@%/:=-]+$/.test(path);
}

function privileged(command: string, isRoot: boolean): string {
  return isRoot ? command : `sudo ${command /* shell-safe: 完整命令的操作数已逐项 shq() */}`;
}

function buildWrapperContent(name: string, origPath: string): string {
  const isShell = ['bash', 'sh'].includes(name);
  const shebang = isShell ? '#!' + origPath : '#!/bin/bash';
  return [
    shebang,
    'ORIG=' + shq(origPath),
    'LOG=' + shq(LOG_PATH),
    "TS=$(date '+%Y-%m-%d %H:%M:%S')",
    'CALLER=$(ps -o comm= $PPID 2>/dev/null)',
    'echo "[$TS] CMD=' + name + ' ARGS=$* USER=$(whoami) PID=$$ PPID=$PPID CALLER=$CALLER" >> $LOG',
    'exec "$ORIG" "$@"',
  ].join('\n');
}

export function buildHijackCommandPlan(name: string, path: string, isRoot: boolean): HijackCommandPlan {
  if (!COMMAND_NAME_RE.test(name)) throw new Error('命令名不合法');
  if (!isValidAbsoluteCommandPath(path)) throw new Error('系统命令路径不合法');
  const origPath = path + '_orig';
  const wrapper = buildWrapperContent(name, origPath);
  const bytes = new TextEncoder().encode(wrapper);
  const b64 = btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''));
  const innerWrite = `printf %s ${shq(b64)} | base64 -d > ${shq(path)} && chmod +x -- ${shq(path)}`;
  return {
    origPath,
    backupCommand: privileged(`cp -n -- ${shq(path)} ${shq(origPath)}`, isRoot),
    writeCommand: privileged(`/bin/sh -c ${shq(innerWrite)}`, isRoot),
    verifyCommand: `file -- ${shq(path)} 2>/dev/null`,
    functionalVerifyCommand: `${shq(path)} --help </dev/null >/dev/null 2>&1; code=$?; [ "$code" -le 2 ] && echo WRAPPER_OK`,
    restoreCommand: privileged(`mv -- ${shq(origPath)} ${shq(path)}`, isRoot),
    restoreVerifyCommand: `file -- ${shq(path)} 2>/dev/null | grep -vqE 'script|text|ASCII' && [ ! -e ${shq(origPath)} ] && echo ORIGINAL_OK`,
  };
}

// ──── 管理器 ────

class CheckAuditManager {
  private isRoot = false;
  private currentTab: CaTab = 'hijack';
  private commands: HijackCommand[] = [];
  private logEntries: AuditLogEntry[] = [];
  private cycles: CheckCycle[] = [];
  private suggestions: FixSuggestion[] = [];

  private initialized = false;
  private eventsBound = false;
  private loading = false;
  private autoRefreshTimer: number | null = null;
  private autoRefreshEnabled = false;
  private refreshInterval = 5000;

  // ──── 生命周期 ────

  initialize(): void {
    if (!this.initialized) {
      this.bindEvents();
      this.initialized = true;
    }
    (window as any).__caManager = this;
    this.initCommands();
    this.renderContent();
    if (sshConnectionManager.isConnected()) {
      // 检测当前用户是否为 root
      this.exec('id -u').then(out => {
        this.isRoot = out.trim() === '0';
      });
      this.detectStatuses();
    }
  }

  deactivate(): void {
    this.stopAutoRefresh();
  }

  // ──── 事件 ────

  private bindEvents(): void {
    if (this.eventsBound) return;
    this.eventsBound = true;

    document.addEventListener('click', (e) => {
      const t = (e.target as HTMLElement).closest('[data-ca-action]') as HTMLElement;
      if (!t) return;
      const action = t.getAttribute('data-ca-action') || '';
      const param = t.getAttribute('data-ca-param') || '';

      switch (action) {
        case 'switch-tab': this.switchTab(param as CaTab); break;
        case 'refresh': this.detectStatuses(); break;
        case 'deploy-cmd': this.deployHijack(param); break;
        case 'restore-cmd': this.restoreCommand(param); break;
        case 'deploy-all': this.deployAll(); break;
        case 'restore-all': this.restoreAll(); break;
        case 'add-custom': this.addCustomCommand(); break;
        case 'remove-custom': this.removeCustomCommand(param); break;
        case 'refresh-log': this.refreshLog(); break;
        case 'toggle-auto': this.toggleAutoRefresh(); break;
        case 'set-interval': this.setRefreshInterval(parseInt(param)); break;
        case 'clear-log': this.clearLog(); break;
        case 'export-log': this.exportLog(); break;
        case 'run-analysis': this.runAnalysis(); break;
        case 'copy-cmd': this.copyText(param); break;
      }
    });
  }

  private switchTab(tab: CaTab): void {
    this.currentTab = tab;
    document.querySelectorAll('.ca-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelector(`[data-ca-action="switch-tab"][data-ca-param="${tab}"]`)?.classList.add('active');
    if (tab === 'audit-log' && this.logEntries.length === 0) this.refreshLog();
    this.renderContent();
  }

  // ──── SSH ────

  private async exec(cmd: string): Promise<string> {
    return (await this.execResult(cmd)).output;
  }

  private async execResult(cmd: string): Promise<AuditCommandResult> {
    const capturedTarget = activeTargetContext.get();
    try {
      const r = await invokeTargetBoundSSH('ssh_execute_command_direct', { command: cmd }) as any;
      const exitCode = typeof r?.exit_code === 'number' ? r.exit_code : null;
      const timedOut = r?.timed_out === true;
      return {
        output: r?.output || '', exitCode, timedOut,
        success: !timedOut && exitCode === 0,
      };
    } catch (e) {
      if (capturedTarget && !activeTargetContext.matches(capturedTarget)) throw e;
      log.warn('SSH 命令失败', e);
      reportError(e, { module: 'CheckAudit', action: '执行 SSH 命令', silent: true });
      return { output: String(e), exitCode: null, timedOut: false, success: false };
    }
  }

  private assertTarget(target: TargetIdentity): void {
    if (!activeTargetContext.matches(target)) {
      throw new Error(`核查审计期间目标已变化，已停止后续动作；原目标 ${target.username}@${target.host}:${target.port}`);
    }
  }

  // ──── 命令劫持 ────

  private initCommands(): void {
    if (this.commands.length > 0) return;
    this.commands = DEFAULT_COMMANDS.map(name => ({
      name, path: '', status: 'checking' as HijackStatus, origPath: '', custom: false,
    }));
  }

  async detectStatuses(): Promise<void> {
    this.loading = true;
    this.renderContent();
    const batchSize = 5;
    for (let i = 0; i < this.commands.length; i += batchSize) {
      const batch = this.commands.slice(i, i + batchSize);
      const names = batch.map(c => shq(c.name)).join(' ');
      const out = await this.exec(
        `for cmd in ${names /* shell-safe: 每个命令名均已由 shq() 包裹 */}; do p=$(which "$cmd" 2>/dev/null); if [ -z "$p" ]; then echo "$cmd|MISSING|"; elif file "$p" 2>/dev/null | grep -qE "script|text"; then echo "$cmd|HIJACKED|$p"; else echo "$cmd|ORIGINAL|$p"; fi; done`
      );
      out.split('\n').filter(Boolean).forEach(line => {
        const parts = line.split('|');
        if (parts.length < 2) return;
        const [cname, status, path] = parts;
        const cmd = this.commands.find(c => c.name === cname);
        if (cmd) {
          cmd.status = (status === 'HIJACKED' ? 'hijacked' : status === 'ORIGINAL' ? 'original' : 'missing') as HijackStatus;
          cmd.path = path || '';
          cmd.origPath = path ? path + '_orig' : '';
        }
      });
    }
    this.loading = false;
    this.renderContent();
  }

  async deployHijack(name: string, skipConfirm = false): Promise<void> {
    const cmd = this.commands.find(c => c.name === name);
    if (!cmd || !cmd.path) {
      window.showNotification?.(`命令 ${name} 路径未知，无法劫持`, 'warning');
      return;
    }
    if (cmd.status === 'hijacked') {
      window.showNotification?.(`${name} 已处于劫持状态`, 'info');
      return;
    }
    if (cmd.status === 'missing') {
      window.showNotification?.(`${name} 未安装，跳过`, 'warning');
      return;
    }
    if (!COMMAND_NAME_RE.test(name) || !isValidAbsoluteCommandPath(cmd.path)) {
      window.showNotification?.(`${name} 的命令名或系统路径不合法，已阻止替换`, 'error');
      return;
    }
    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) throw new Error('请先连接并确认目标主机');

    // 劫持会用 wrapper 替换系统命令,尤其 bash/sh/cat 等基础命令一旦 wrapper 异常可能影响整机,必须二次确认
    if (!skipConfirm) {
      const confirmed = await showConfirm({
        title: '部署命令劫持',
        message: `目标：${capturedTarget.username}@${capturedTarget.host}:${capturedTarget.port}\n指纹：${capturedTarget.hostKeyFingerprint}\n\n确定要劫持系统命令 "${name}"(${cmd.path})？\n\n将用 wrapper 脚本替换该命令以记录 check 脚本行为,原文件备份为 ${cmd.path}_orig。\n\n若为 bash/sh/cat 等基础命令,wrapper 异常可能影响整机命令执行,请确认已了解风险。`,
        dangerous: true,
        defaultFocus: 'cancel',
      });
      if (!confirmed) return;
    }
    this.assertTarget(capturedTarget);

    const plan = buildHijackCommandPlan(name, cmd.path, this.isRoot);
    const { origPath, backupCommand, writeCommand, verifyCommand, functionalVerifyCommand, restoreCommand, restoreVerifyCommand } = plan;
    this.showOutput(`正在部署 ${name} 劫持...\n路径: ${cmd.path}\n备份: ${origPath}`);

    // 步骤 1: 备份原始二进制
    const backupResult = await this.execResult(backupCommand);
    this.assertTarget(capturedTarget);

    // 验证备份
    const bkCheck = await this.exec(`[ -f ${shq(origPath)} ] && echo "BK_OK"`);
    this.assertTarget(capturedTarget);
    if (!bkCheck.includes('BK_OK')) {
      this.showOutput(`备份失败，无法继续\n输出: ${backupResult.output}\n\n请确认:\n1. 当前身份: ${this.isRoot ? 'root' : '非root'}\n2. 目标目录是否可写`);
      window.showNotification?.(`${name} 备份失败`, 'error');
      return;
    }

    // 步骤 2: 生成 wrapper 并写入
    // 劫持 bash/sh 时，写入命令本身不能依赖被劫持的 shell
    // 所以统一用 /usr/bin/env + 已备份的原始 bash 来执行
    const writeResult = await this.execResult(writeCommand);
    this.assertTarget(capturedTarget);

    // 步骤 3: 验证写入
    const verify = await this.exec(verifyCommand);
    this.assertTarget(capturedTarget);
    const isScript = /script|text|ASCII/.test(verify);

    // 步骤 4: 验证 wrapper 能正常工作（用 --help 或无参数快速测试）
    const testResult = isScript ? await this.execResult(functionalVerifyCommand) : null;
    this.assertTarget(capturedTarget);
    const testOk = Boolean(testResult?.success && testResult.output.includes('WRAPPER_OK'));

    if (writeResult.success && isScript && testOk) {

      cmd.status = 'hijacked';
      cmd.origPath = origPath;
      const receipt = operationJournal.record({
        source: 'check-audit', server: capturedTarget.host, target: capturedTarget,
        title: `部署 ${name} 命令审计 wrapper`,
        command: `${backupCommand}\n${writeCommand}`,
        restoreCommand, restoreVerifyCommand, restoreVerifyExpected: 'ORIGINAL_OK',
        backupInfo: origPath, output: writeResult.output,
        exitCode: writeResult.exitCode, timedOut: writeResult.timedOut,
        verifyCommand: `${verifyCommand}\n${functionalVerifyCommand}`,
        verifyOutput: `${verify}\n${testResult?.output || ''}`, verified: true, success: true,
      });
      cmd.journalEntryId = receipt.id;
      this.showOutput(`${name} 劫持部署成功\n\n备份: ${origPath}\nWrapper: ${cmd.path}\n验证: file → ${verify.trim()}\n功能测试: 通过\n${writeResult.output}`);
      window.showNotification?.(`${name} 劫持成功`, 'success');
    } else {
      // 写入失败，恢复原始
      this.assertTarget(capturedTarget);
      const restoreResult = await this.execResult(restoreCommand);
      const restoreVerify = await this.exec(restoreVerifyCommand);
      this.assertTarget(capturedTarget);
      const restored = restoreResult.success && restoreVerify.includes('ORIGINAL_OK');
      operationJournal.record({
        source: 'check-audit', server: capturedTarget.host, target: capturedTarget,
        title: `部署 ${name} 命令审计 wrapper 失败${restored ? '（已自动恢复）' : '（恢复未确认）'}`,
        command: `${backupCommand}\n${writeCommand}`,
        restoreCommand: restored ? undefined : restoreCommand,
        restoreVerifyCommand: restored ? undefined : restoreVerifyCommand,
        restoreVerifyExpected: restored ? undefined : 'ORIGINAL_OK',
        backupInfo: origPath, output: writeResult.output,
        exitCode: writeResult.exitCode, timedOut: writeResult.timedOut,
        verifyCommand: `${verifyCommand}\n${functionalVerifyCommand}`,
        verifyOutput: `${verify}\n${testResult?.output || ''}`, verified: false, success: false,
      });
      this.showOutput(`${name} wrapper 写入或功能验证失败，${restored ? '已自动恢复原始文件' : '自动恢复未通过验证，请立即人工检查'}\n\nfile 输出: ${verify}\n写入输出: ${writeResult.output}`);
      window.showNotification?.(`${name} 劫持失败，${restored ? '已恢复' : '恢复未确认'}`, 'error');
    }
    this.renderContent();
  }

  async restoreCommand(name: string, skipConfirm = false): Promise<void> {
    const cmd = this.commands.find(c => c.name === name);
    if (!cmd || !cmd.path) return;

    if (!COMMAND_NAME_RE.test(name) || !isValidAbsoluteCommandPath(cmd.path)) {
      window.showNotification?.(`${name} 的命令名或系统路径不合法，已阻止恢复`, 'error');
      return;
    }
    const plan = buildHijackCommandPlan(name, cmd.path, this.isRoot);
    const origPath = cmd.origPath || plan.origPath;
    const capturedTarget = activeTargetContext.get();
    if (!capturedTarget) throw new Error('请先连接并确认目标主机');
    if (!skipConfirm) {
      const confirmed = await showConfirm({
        title: `恢复系统命令：${name}`,
        message: `目标：${capturedTarget.username}@${capturedTarget.host}:${capturedTarget.port}\n指纹：${capturedTarget.hostKeyFingerprint}\n\n将用备份 ${origPath} 覆盖 ${cmd.path}，并读回验证原始二进制。`,
        confirmText: '恢复并验证', cancelText: '取消', dangerous: true, defaultFocus: 'cancel',
      });
      if (!confirmed) return;
    }
    this.assertTarget(capturedTarget);

    // 先检查备份文件是否存在
    const backupCheck = await this.exec(`[ -f ${shq(origPath)} ] && echo "EXISTS"`);
    this.assertTarget(capturedTarget);
    if (!backupCheck.includes('EXISTS')) {
      // 备份可能用别的后缀，尝试查找
      const slash = cmd.path.lastIndexOf('/');
      const dir = slash > 0 ? cmd.path.slice(0, slash) : '.';
      const base = slash >= 0 ? cmd.path.slice(slash + 1) : cmd.path;
      const search = await this.exec(`find ${shq(dir)} -maxdepth 1 -type f \( -name ${shq(`${base}_orig*`)} -o -name ${shq(`${base}.bak*`)} \) -print 2>/dev/null | head -5`);
      this.assertTarget(capturedTarget);
      if (search.trim()) {
        this.showOutput(`标准备份 ${origPath} 不存在，但找到以下备份:\n${search}\n\n请手动选择恢复，例如:\n${this.isRoot ? '' : 'sudo '}mv "${search.split('\\n')[0].trim()}" "${cmd.path}"`);
      } else {
        this.showOutput(`恢复失败: 未找到任何备份文件\n\n已搜索:\n  ${origPath}\n  ${cmd.path}_orig*\n  ${cmd.path}.bak*\n\n可能原因:\n1. 从未部署过劫持\n2. 备份已被删除`);
      }
      window.showNotification?.(`${name} 恢复失败: 未找到备份`, 'error');
      return;
    }

    const restoreCommand = cmd.origPath === plan.origPath || !cmd.origPath
      ? plan.restoreCommand
      : privileged(`mv -- ${shq(origPath)} ${shq(cmd.path)}`, this.isRoot);
    const restoreResult = await this.execResult(restoreCommand);
    this.assertTarget(capturedTarget);
    const verifyCommand = `file -- ${shq(cmd.path)} 2>/dev/null | grep -vqE 'script|text|ASCII' && [ ! -e ${shq(origPath)} ] && echo ORIGINAL_OK`;
    const verifyResult = await this.execResult(verifyCommand);
    this.assertTarget(capturedTarget);
    const restored = restoreResult.success && verifyResult.success && verifyResult.output.includes('ORIGINAL_OK');
    operationJournal.record({
      source: 'check-audit', server: capturedTarget.host, target: capturedTarget,
      title: `恢复 ${name} 原始系统命令`, command: restoreCommand,
      output: restoreResult.output, exitCode: restoreResult.exitCode, timedOut: restoreResult.timedOut,
      verifyCommand, verifyOutput: verifyResult.output, verified: restored, success: restored,
    });
    if (restored) {
      cmd.status = 'original';
      if (cmd.journalEntryId) operationJournal.markRolledBack(cmd.journalEntryId);
      this.showOutput(`${name} 已恢复为原始二进制`);
      window.showNotification?.(`${name} 已恢复`, 'success');
    } else {
      this.showOutput(`${name} 恢复失败或读回验证未通过:\n${restoreResult.output}\n${verifyResult.output}`);
      window.showNotification?.(`${name} 恢复失败`, 'error');
    }
    this.renderContent();
  }

  async deployAll(): Promise<void> {
    const targets = this.commands.filter(c => c.status === 'original' && c.path);
    if (targets.length === 0) { window.showNotification?.('没有可部署的命令', 'info'); return; }

    // 批量劫持只确认一次,随后循环时 skipConfirm 避免逐条打扰
    const confirmed = await showConfirm({
      title: '批量部署命令劫持',
      message: `确定要一次性劫持 ${targets.length} 个系统命令(${targets.map(c => c.name).join(', ')})？\n\n每个命令都会被 wrapper 替换、原文件备份为 *_orig。\n\n其中含 bash/sh/cat 等基础命令,wrapper 异常可能影响整机命令执行。`,
      dangerous: true,
      defaultFocus: 'cancel',
    });
    if (!confirmed) return;

    for (const cmd of targets) {
      await this.deployHijack(cmd.name, true);
    }
    window.showNotification?.(`已部署 ${targets.length} 个命令`, 'success');
  }

  async restoreAll(): Promise<void> {
    const targets = this.commands.filter(c => c.status === 'hijacked');
    if (targets.length === 0) { window.showNotification?.('没有已劫持的命令', 'info'); return; }
    for (const cmd of targets) {
      await this.restoreCommand(cmd.name, true);
    }
    window.showNotification?.(`已恢复 ${targets.length} 个命令`, 'success');
  }

  addCustomCommand(): void {
    const input = document.getElementById('ca-custom-input') as HTMLInputElement;
    if (!input) return;
    const name = input.value.trim();
    if (!name || !COMMAND_NAME_RE.test(name) || this.commands.find(c => c.name === name)) {
      const message = !name ? '请输入命令名'
        : !COMMAND_NAME_RE.test(name) ? '命令名仅允许字母、数字、点、下划线、加号和连字符'
          : '命令已存在';
      window.showNotification?.(message, 'warning');
      return;
    }
    this.commands.push({ name, path: '', status: 'checking', origPath: '', custom: true });
    input.value = '';
    this.detectStatuses();
  }

  removeCustomCommand(name: string): void {
    this.commands = this.commands.filter(c => !(c.name === name && c.custom));
    this.renderContent();
  }

  // ──── 审计日志 ────

  async refreshLog(): Promise<void> {
    const raw = await this.exec(`tail -500 ${shq(LOG_PATH)} 2>/dev/null`);
    this.logEntries = [];
    raw.split('\n').filter(Boolean).forEach(line => {
      const m = LOG_LINE_RE.exec(line);
      if (m) {
        this.logEntries.push({
          timestamp: m[1], command: m[2], args: m[3].trim(),
          user: m[4], pid: parseInt(m[5]), ppid: parseInt(m[6]),
          caller: m[7].trim(), raw: line,
        });
      }
    });
    this.renderContent();
  }

  toggleAutoRefresh(): void {
    this.autoRefreshEnabled = !this.autoRefreshEnabled;
    if (this.autoRefreshEnabled) {
      this.autoRefreshTimer = window.setInterval(() => this.refreshLog(), this.refreshInterval);
    } else {
      this.stopAutoRefresh();
    }
    this.renderContent();
  }

  private stopAutoRefresh(): void {
    if (this.autoRefreshTimer) { clearInterval(this.autoRefreshTimer); this.autoRefreshTimer = null; }
    this.autoRefreshEnabled = false;
  }

  setRefreshInterval(ms: number): void {
    this.refreshInterval = ms;
    if (this.autoRefreshEnabled) {
      this.stopAutoRefresh();
      this.autoRefreshEnabled = true;
      this.autoRefreshTimer = window.setInterval(() => this.refreshLog(), ms);
    }
  }

  async clearLog(): Promise<void> {
    await this.exec(`: > ${shq(LOG_PATH)}`);
    this.logEntries = [];
    this.renderContent();
    window.showNotification?.('日志已清空', 'success');
  }

  exportLog(): void {
    const text = this.logEntries.map(e => e.raw).join('\n');
    navigator.clipboard.writeText(text).catch(() => {});
    window.showNotification?.('日志已复制到剪贴板', 'success');
  }

  private isSuspicious(entry: AuditLogEntry): boolean {
    const full = `${entry.command} ${entry.args}`;
    return SUSPICIOUS_RE.some(re => re.test(full));
  }

  private computeStats(): { total: number; cmdCounts: [string, number][]; suspiciousCount: number } {
    const map = new Map<string, number>();
    let sus = 0;
    for (const e of this.logEntries) {
      map.set(e.command, (map.get(e.command) || 0) + 1);
      if (this.isSuspicious(e)) sus++;
    }
    const cmdCounts = [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    return { total: this.logEntries.length, cmdCounts, suspiciousCount: sus };
  }

  // ──── Check 分析 ────

  async runAnalysis(): Promise<void> {
    if (this.logEntries.length === 0) await this.refreshLog();
    if (this.logEntries.length === 0) { window.showNotification?.('审计日志为空，请先部署劫持', 'warning'); return; }

    // 按 cmd+args 分组
    const groups = new Map<string, AuditLogEntry[]>();
    for (const e of this.logEntries) {
      const key = `${e.command}|${e.args}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(e);
    }

    this.cycles = [];
    groups.forEach((entries, key) => {
      if (entries.length < 2) return;
      const [cmd, args] = key.split('|');
      const interval = this.detectPeriod(entries.map(e => e.timestamp));
      const category = this.classifyCommand(cmd, args);
      this.cycles.push({
        command: cmd, args: args || '',
        intervalSeconds: interval,
        count: entries.length,
        lastSeen: entries[entries.length - 1].timestamp,
        category,
      });
    });

    this.cycles.sort((a, b) => b.count - a.count);
    this.generateSuggestions();
    this.currentTab = 'analysis';
    document.querySelectorAll('.ca-tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelector('[data-ca-param="analysis"]')?.classList.add('active');
    this.renderContent();
  }

  private detectPeriod(timestamps: string[]): number | null {
    if (timestamps.length < 3) return null;
    const times = timestamps.map(t => new Date(t).getTime()).filter(t => !isNaN(t));
    if (times.length < 3) return null;
    const intervals: number[] = [];
    for (let i = 1; i < times.length; i++) intervals.push((times[i] - times[i - 1]) / 1000);
    const avg = intervals.reduce((s, v) => s + v, 0) / intervals.length;
    if (avg <= 0) return null;
    const withinTolerance = intervals.every(iv => Math.abs(iv - avg) / avg < 0.3);
    return withinTolerance ? Math.round(avg) : null;
  }

  private classifyCommand(cmd: string, args: string): string {
    if (['cat', 'grep', 'find', 'ls', 'head', 'tail'].includes(cmd) && args.includes('/')) return 'file-read';
    if (['systemctl', 'service', 'ss', 'netstat'].includes(cmd)) return 'service-check';
    if (['curl', 'wget'].includes(cmd)) return 'network';
    if (['mysql', 'redis-cli', 'psql', 'mongo'].includes(cmd)) return 'database';
    return 'process';
  }

  private generateSuggestions(): void {
    this.suggestions = [];
    for (const c of this.cycles) {
      const s = this.cycleToSuggestion(c);
      if (s) this.suggestions.push(s);
    }
  }

  private cycleToSuggestion(c: CheckCycle): FixSuggestion | null {
    const id = `fix-${c.command}-${this.suggestions.length}`;
    const command = this.commands.some(item => item.name === c.command) && COMMAND_NAME_RE.test(c.command)
      ? c.command
      : 'false';
    if (c.category === 'file-read' && c.args) {
      const path = c.args.split(/\s+/).find(part => part.startsWith('/')) || '';
      if (!path) return null;
      return {
        id, severity: 'critical', category: 'file',
        title: `确保文件 ${path} 存在且内容正确`,
        description: `Check 脚本${c.intervalSeconds ? `每 ${c.intervalSeconds} 秒` : ''}使用 ${c.command} 读取此文件`,
        checkCommand: `ls -la -- ${shq(path)}`,
        fixCommand: `ls -la -- ${shq(path)} && ${command /* shell-safe: 来自当前白名单命令目录 */} -- ${shq(path)} | head -5`,
      };
    }
    if (c.category === 'network') {
      const urlMatch = c.args.match(/https?:\/\/\S+/);
      const url = urlMatch ? urlMatch[0] : c.args;
      return {
        id, severity: 'critical', category: 'network',
        title: `确保 ${url} 可访问`,
        description: `Check 脚本${c.intervalSeconds ? `每 ${c.intervalSeconds} 秒` : ''}请求此 URL`,
        checkCommand: `curl -sI -- ${shq(url)} | head -5`,
        fixCommand: `curl -sI -- ${shq(url)} | head -5`,
      };
    }
    if (c.category === 'service-check') {
      const svc = c.args.replace(/status\s*/i, '').trim().split(/\s+/)[0] || '';
      const safeService = /^[A-Za-z0-9@_.:-]+$/.test(svc) ? svc : '';
      return {
        id, severity: 'warning', category: 'service',
        title: `确保服务 ${safeService || c.command} 正在运行`,
        description: `Check 脚本检查服务状态: ${c.command} ${c.args}`,
        checkCommand: safeService ? `systemctl status -- ${shq(safeService)}` : `${command /* shell-safe: 来自当前白名单命令目录 */} --help`,
        fixCommand: safeService ? `systemctl start -- ${shq(safeService)} && systemctl status -- ${shq(safeService)}` : `${command /* shell-safe: 来自当前白名单命令目录 */} --help`,
      };
    }
    if (c.category === 'database') {
      return {
        id, severity: 'critical', category: 'database',
        title: `确保数据库连接正常`,
        description: `Check 脚本使用 ${c.command} 测试数据库: ${c.args.substring(0, 60)}`,
        checkCommand: `${command /* shell-safe: 来自当前白名单命令目录 */} --version`,
        fixCommand: c.command === 'mysql' ? 'systemctl status mysql' : 'systemctl status redis',
      };
    }
    if (c.count >= 3) {
      return {
        id, severity: 'info', category: 'process',
        title: `Check 执行 ${c.command} ${c.args.substring(0, 40)}`,
        description: `共 ${c.count} 次${c.intervalSeconds ? `，周期约 ${c.intervalSeconds}s` : ''}`,
        checkCommand: `${command /* shell-safe: 来自当前白名单命令目录 */} --help`,
        fixCommand: `${command /* shell-safe: 来自当前白名单命令目录 */} --help`,
      };
    }
    return null;
  }

  // ──── 工具 ────

  private esc(s: string): string {
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private copyText(text: string): void {
    navigator.clipboard.writeText(text).catch(() => {});
    window.showNotification?.('已复制', 'success');
  }

  private showOutput(text: string): void {
    const p = document.getElementById('ca-output-panel');
    if (p) p.innerHTML = `<pre class="ca-output-pre">${this.esc(text)}</pre>`;
  }

  // ──── 渲染 ────

  renderContent(): void {
    const el = document.getElementById('ca-content');
    if (!el) return;
    if (!sshConnectionManager.isConnected()) { el.innerHTML = '<div class="ca-empty">请先连接服务器</div>'; return; }
    if (this.loading) { el.innerHTML = '<div class="ca-loading"><div class="ca-spinner"></div>正在检测命令状态...</div>'; return; }

    switch (this.currentTab) {
      case 'hijack': el.innerHTML = this.renderHijackTab(); break;
      case 'audit-log': el.innerHTML = this.renderAuditLogTab(); break;
      case 'analysis': el.innerHTML = this.renderAnalysisTab(); break;
      case 'quick-fix': el.innerHTML = this.renderQuickFixTab(); break;
    }
  }

  private renderHijackTab(): string {
    const rows = this.commands.map(c => {
      const statusClass = c.status === 'hijacked' ? 'hijacked' : c.status === 'original' ? 'original' : 'missing';
      const statusLabel = c.status === 'hijacked' ? '已劫持' : c.status === 'original' ? '原始' : c.status === 'missing' ? '未安装' : '检测中';
      return `<tr>
        <td><code>${this.esc(c.name)}</code></td>
        <td class="ca-cell-path">${this.esc(c.path || '-')}</td>
        <td><span class="ca-status ${statusClass}">${statusLabel}</span></td>
        <td class="ca-cell-actions">
          ${c.status === 'original' ? `<button class="ca-btn primary small" data-ca-action="deploy-cmd" data-ca-param="${c.name}">部署劫持</button>` : ''}
          ${c.status === 'hijacked' ? `<button class="ca-btn secondary small" data-ca-action="restore-cmd" data-ca-param="${c.name}">恢复原始</button>` : ''}
          ${c.custom ? `<button class="ca-btn danger small" data-ca-action="remove-custom" data-ca-param="${c.name}">移除</button>` : ''}
        </td>
      </tr>`;
    }).join('');

    const hijackedCount = this.commands.filter(c => c.status === 'hijacked').length;

    return `
      <div class="ca-section">
        <div class="ca-section-header">
          <h4>命令劫持管理</h4>
          <div class="ca-header-actions">
            <span class="ca-hint">已劫持 ${hijackedCount} / ${this.commands.length}</span>
            <button class="ca-btn primary" data-ca-action="deploy-all">一键全部部署</button>
            <button class="ca-btn secondary" data-ca-action="restore-all">一键全部恢复</button>
            <button class="ca-btn secondary" data-ca-action="refresh">刷新状态</button>
          </div>
        </div>
        <div class="ca-form-row">
          <input id="ca-custom-input" class="ca-input" placeholder="自定义命令名 (如 flag_reader)" />
          <button class="ca-btn secondary" data-ca-action="add-custom">添加</button>
        </div>
        <div class="ca-table-wrapper">
          <table class="ca-table">
            <thead><tr><th>命令</th><th>路径</th><th>状态</th><th>操作</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
      <div id="ca-output-panel" class="ca-output-panel"></div>
    `;
  }

  private renderAuditLogTab(): string {
    const stats = this.computeStats();
    const filterInput = `<input id="ca-log-filter" class="ca-input" placeholder="过滤命令/参数..." style="max-width:200px" />`;

    const cmdBadges = stats.cmdCounts.map(([cmd, cnt]) =>
      `<span class="ca-badge">${this.esc(cmd)}: ${cnt}</span>`
    ).join('');

    const filtered = this.getFilteredLog();
    const logRows = filtered.slice(-200).reverse().map(e => {
      const sus = this.isSuspicious(e);
      return `<tr class="${sus ? 'ca-suspicious' : ''}">
        <td class="ca-cell-ts">${this.esc(e.timestamp)}</td>
        <td><code>${this.esc(e.command)}</code></td>
        <td class="ca-cell-args" title="${this.esc(e.args)}">${this.esc(e.args.substring(0, 80))}</td>
        <td>${this.esc(e.user)}</td>
        <td>${e.pid}</td>
        <td>${this.esc(e.caller)}</td>
      </tr>`;
    }).join('');

    return `
      <div class="ca-section">
        <div class="ca-log-toolbar">
          ${filterInput}
          <select class="ca-select" data-ca-action="set-interval" onchange="this.setAttribute('data-ca-param',this.value);this.click()">
            <option value="3000" ${this.refreshInterval === 3000 ? 'selected' : ''}>3s</option>
            <option value="5000" ${this.refreshInterval === 5000 ? 'selected' : ''}>5s</option>
            <option value="10000" ${this.refreshInterval === 10000 ? 'selected' : ''}>10s</option>
          </select>
          <button class="ca-btn ${this.autoRefreshEnabled ? 'primary' : 'secondary'}" data-ca-action="toggle-auto">
            ${this.autoRefreshEnabled ? '[ ON ] 自动刷新' : '自动刷新'}
          </button>
          <button class="ca-btn secondary" data-ca-action="refresh-log">刷新</button>
          <button class="ca-btn secondary" data-ca-action="clear-log">清空</button>
          <button class="ca-btn secondary" data-ca-action="export-log">导出</button>
        </div>
        <div class="ca-stats-bar">
          <span>共 ${stats.total} 条</span>
          ${stats.suspiciousCount > 0 ? `<span class="ca-badge danger">可疑 ${stats.suspiciousCount}</span>` : ''}
          ${cmdBadges}
        </div>
        ${filtered.length === 0
          ? '<div class="ca-empty">暂无审计记录。请先在"命令劫持"Tab 部署劫持，等待 check 脚本执行后查看。</div>'
          : `<div class="ca-table-wrapper"><table class="ca-table">
            <thead><tr><th>时间</th><th>命令</th><th>参数</th><th>用户</th><th>PID</th><th>调用者</th></tr></thead>
            <tbody>${logRows}</tbody>
          </table></div>`}
      </div>
    `;
  }

  private getFilteredLog(): AuditLogEntry[] {
    const filter = (document.getElementById('ca-log-filter') as HTMLInputElement)?.value?.toLowerCase() || '';
    if (!filter) return this.logEntries;
    return this.logEntries.filter(e =>
      e.command.toLowerCase().includes(filter) || e.args.toLowerCase().includes(filter) || e.caller.toLowerCase().includes(filter)
    );
  }

  private renderAnalysisTab(): string {
    if (this.cycles.length === 0) {
      return `<div class="ca-empty">
        <p>暂无分析数据</p>
        <button class="ca-btn primary" data-ca-action="run-analysis">运行 Check 分析</button>
        <p class="ca-hint">需要先部署命令劫持并等待 check 脚本执行若干次后再分析</p>
      </div>`;
    }

    const cards = this.cycles.map(c => {
      const periodLabel = c.intervalSeconds ? `~${c.intervalSeconds}s` : '不规律';
      const catLabels: Record<string, string> = {
        'file-read': '文件读取', 'service-check': '服务检查',
        'network': '网络请求', 'database': '数据库', 'process': '进程',
      };
      return `<div class="ca-cycle-card">
        <div class="ca-cycle-left">
          <span class="ca-category-tag">${catLabels[c.category] || c.category}</span>
          <code class="ca-cycle-cmd">${this.esc(c.command)} ${this.esc(c.args.substring(0, 80))}</code>
        </div>
        <div class="ca-cycle-right">
          <span class="ca-interval-badge">${periodLabel}</span>
          <span class="ca-badge">${c.count} 次</span>
          <span class="ca-hint">${this.esc(c.lastSeen)}</span>
        </div>
      </div>`;
    }).join('');

    return `
      <div class="ca-section">
        <div class="ca-section-header">
          <h4>Check 脚本行为分析</h4>
          <button class="ca-btn primary" data-ca-action="run-analysis">重新分析</button>
        </div>
        ${cards}
      </div>
    `;
  }

  private renderQuickFixTab(): string {
    if (this.suggestions.length === 0) {
      return `<div class="ca-empty">
        <p>暂无修复建议</p>
        <button class="ca-btn primary" data-ca-action="run-analysis">先运行 Check 分析</button>
      </div>`;
    }

    const items = this.suggestions.map(s => `
      <div class="ca-fix-card ca-fix-${s.severity}">
        <div class="ca-fix-header">
          <span class="ca-severity-badge ${s.severity}">${s.severity === 'critical' ? '严重' : s.severity === 'warning' ? '警告' : '信息'}</span>
          <span class="ca-fix-title">${this.esc(s.title)}</span>
        </div>
        <p class="ca-fix-desc">${this.esc(s.description)}</p>
        <div class="ca-fix-cmds">
          <div class="ca-fix-cmd-row">
            <span class="ca-fix-cmd-label">Check 命令:</span>
            <code>${this.esc(s.checkCommand)}</code>
            <button class="ca-btn secondary small" data-ca-action="copy-cmd" data-ca-param="${this.esc(s.checkCommand)}">复制</button>
          </div>
          ${s.fixCommand ? `<div class="ca-fix-cmd-row">
            <span class="ca-fix-cmd-label">验证/修复:</span>
            <code>${this.esc(s.fixCommand)}</code>
            <button class="ca-btn primary small" data-ca-action="copy-cmd" data-ca-param="${this.esc(s.fixCommand)}">复制</button>
          </div>` : ''}
        </div>
      </div>
    `).join('');

    return `
      <div class="ca-section">
        <div class="ca-section-header">
          <h4>基于 Check 行为的修复建议</h4>
          <span class="ca-hint">${this.suggestions.length} 条建议</span>
        </div>
        ${items}
      </div>
    `;
  }
}

export const checkAuditManager = new CheckAuditManager();
