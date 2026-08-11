/**
 * 快速检测管理器
 * 负责执行安全和性能检测，管理检测状态和历史记录
 * 委托具体实现给 DetectionModules、DetectionReportRenderer 和 DetectionAIManager
 */

import { ReportExporter } from './reportExporter';
import { DetectionModules } from './detectionModules';
import { DetectionReportRenderer } from './detectionReportRenderer';
import { DetectionAIManager } from './detectionAIManager';
import { showAlert, showConfirm } from '../ui/confirmDialog';
import { getFixActionsForFinding, getFixActionsForDetectionItem, HARDENING_ITEMS, type FixActionDef, type HardeningItem } from './detectionFixMapper';
import { fixExecutor, type FixAction, type FixResult, type ResolvedBaselineItem } from './fixExecutor';
import { fixHistoryManager, type FixHistoryEntry } from './fixHistoryManager';
import { SystemDetector } from '../utils/systemDetector';
import { executeEmergencyCommand } from '../emergency/commandExecution';
import { operationJournal } from '../core/operationJournal';
import { activeTargetContext, type TargetIdentity } from '../core/targetContext';
import {
  COMPETITION_TRIAGE_IDS,
  calculateCompleteness,
  calculateTrustedScore,
  normalizeOutcome,
  notApplicableReason,
  type DetectionOutcome,
  type ScanEnvironment,
  type ScanMode,
} from './scanPlanning';
import { reportError } from '../utils/errorHandler';
import { targetCapabilityStore } from '../core/targetCapabilities';

// 检测项目类型
export interface DetectionItem {
  id: string;
  name: string;
  description: string;
  category: 'security' | 'performance' | 'competition';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'not-applicable';
  result?: DetectionResult;
}

// 检测结果
export interface DetectionResult {
  passed: boolean;
  score: number; // 0-100
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  findings: Finding[];
  duration: number; // 执行时间（毫秒）
  timestamp: Date;
  rawOutput?: any; // 原始命令返回结果
  outcome?: DetectionOutcome;
}

// 检测发现
export interface Finding {
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  recommendation?: string;
  details?: any;
}

// 检测报告
export interface DetectionReport {
  id: string;
  timestamp: Date;
  server: string;
  overallScore: number;
  totalDuration: number;
  items: DetectionItem[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  mode?: ScanMode;
  status?: 'completed' | 'partial' | 'cancelled';
  completeness?: ReturnType<typeof calculateCompleteness>;
  environment?: ScanEnvironment;
  target?: TargetIdentity;
  timeBudgetMs?: number;
}

export class QuickDetectionManager {
  private currentReport: DetectionReport | null = null;
  private detectionHistory: DetectionReport[] = [];
  private isRunning: boolean = false;
  private cancelled: boolean = false;
  private progressCallback?: (progress: number, current: string) => void;

  private detectionModules: DetectionModules;
  private reportRenderer: DetectionReportRenderer;
  private aiManager: DetectionAIManager;

  /** 探测到的目标发行版 ID（懒加载，复用 SystemDetector 的内部缓存） */
  private detectedDistro: string | null = null;
  private detectedDistroSessionId: string | null = null;
  private scanEnvironmentCache: { sessionId: string; environment: ScanEnvironment } | null = null;

  /** 并发组大小 — 同时发出的检测请求数 */
  private static readonly CONCURRENCY = 3;

  constructor() {
    this.detectionModules = new DetectionModules();
    this.reportRenderer = new DetectionReportRenderer();
    this.aiManager = new DetectionAIManager();
    this.loadHistory();
  }

  /**
   * 取消正在进行的扫描
   */
  cancelScan(): void {
    if (this.isRunning) {
      this.cancelled = true;
      window.showNotification?.('正在取消检测...', 'info');
    }
  }

  getCurrentReport(): DetectionReport | null {
    return this.currentReport;
  }

  /**
   * 开始全面扫描
   */
  async startFullScan(selectedIds?: string[]): Promise<DetectionReport> {
    return this.runScan(selectedIds || this.getAllCheckIds(), 'selected');
  }

  private async runScan(selectedIds: readonly string[], mode: ScanMode): Promise<DetectionReport> {
    if (this.isRunning) {
      throw new Error('检测已在进行中');
    }

    const itemsToRun = [...new Set(selectedIds)];
    if (itemsToRun.length === 0) throw new Error('没有选中的检测项');
    const scanTarget = activeTargetContext.get();
    if (!scanTarget) throw new Error('没有已确认的活动 SSH 目标');

    this.isRunning = true;
    this.cancelled = false;
    this.detectionModules.setCommandTimeout(mode === 'competition-triage' ? 6 : undefined);
    this.showProgressPanel();
    const totalItems = itemsToRun.length;
    let completedItems = 0;

    this.updateProgress(0, '正在进行环境预检...');
    let environment: ScanEnvironment;
    try {
      environment = await this.detectScanEnvironment();
    } catch (error) {
      this.isRunning = false;
      this.detectionModules.setCommandTimeout(undefined);
      this.hideProgressPanel();
      throw error;
    }
    if (!activeTargetContext.matches(scanTarget)) {
      this.isRunning = false;
      this.detectionModules.setCommandTimeout(undefined);
      this.hideProgressPanel();
      throw new Error('环境预检期间活动目标已变化，已中止扫描');
    }

    // 初始化报告
    this.currentReport = {
      id: this.generateReportId(),
      timestamp: new Date(),
      server: this.getCurrentServerInfo(),
      overallScore: 0,
      totalDuration: 0,
      items: itemsToRun.map(itemId => ({
        id: itemId,
        name: this.getCheckName(itemId),
        description: this.getCheckDescription(itemId),
        category: this.getCheckCategory(itemId),
        status: 'pending',
      })),
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      mode,
      status: 'completed',
      environment,
      target: {
        sessionId: scanTarget.sessionId,
        hostKeyFingerprint: scanTarget.hostKeyFingerprint,
        host: scanTarget.host,
        port: scanTarget.port,
        username: scanTarget.username,
      },
      timeBudgetMs: mode === 'competition-triage' ? 20_000 : undefined,
    };

    const startTime = Date.now();

    try {
      const queue: string[] = [];
      for (const item of this.currentReport.items) {
        const reason = notApplicableReason(item.id, environment);
        if (!reason) {
          queue.push(item.id);
          continue;
        }
        item.status = 'not-applicable';
        item.result = {
          passed: false,
          score: 0,
          severity: 'info',
          findings: [{ title: '不适用', description: reason, severity: 'info' }],
          duration: 0,
          timestamp: new Date(),
          outcome: 'not-applicable',
        };
        completedItems += 1;
        this.updateCheckStatus(item.id, 'not-applicable', item.result);
      }

      let cursor = 0;
      const concurrency = mode === 'competition-triage' ? 4 : QuickDetectionManager.CONCURRENCY;
      const worker = async (): Promise<void> => {
        while (!this.cancelled) {
          const itemId = queue[cursor++];
          if (!itemId) return;
          const item = this.currentReport?.items.find(entry => entry.id === itemId);
          if (!item) continue;
          item.status = 'running';
          this.updateCheckStatus(itemId, 'running');
          this.updateProgress(
            (completedItems / totalItems) * 100,
            `正在执行: ${this.getCheckName(itemId)}`,
          );

          try {
            const result = await this.executeDetection(itemId);
            const outcome = normalizeOutcome({ status: 'completed', result });
            result.outcome = outcome;
            item.result = result;
            item.status = outcome === 'error' ? 'failed' : 'completed';
            this.updateCheckStatus(itemId, item.status, result);
            if (outcome === 'passed' || outcome === 'failed') {
              for (const finding of result.findings) this.currentReport!.summary[finding.severity] += 1;
            }
          } catch (error) {
            item.status = 'failed';
            reportError(error, { module: 'QuickDetection', action: itemId, silent: true });
            this.updateCheckStatus(itemId, 'failed');
          } finally {
            completedItems += 1;
            this.updateProgress((completedItems / totalItems) * 100, '');
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));

      // 计算总体评分
      this.currentReport.totalDuration = Date.now() - startTime;
      this.currentReport.overallScore = this.calculateOverallScore(this.currentReport);
      this.currentReport.completeness = calculateCompleteness(totalItems, this.currentReport.items);
      this.currentReport.status = this.cancelled
        ? 'cancelled'
        : this.currentReport.completeness.failed > 0 ? 'partial' : 'completed';

      // 显示结果
      this.showSummaryPanel(this.currentReport);

      // 保存到历史
      this.saveToHistory(this.currentReport);

      if (this.cancelled) window.showNotification?.('检测已取消，已保存带完整度标记的部分报告', 'warning');

      return this.currentReport;
    } finally {
      this.isRunning = false;
      this.cancelled = false;
      this.detectionModules.setCommandTimeout(undefined);
      this.hideProgressPanel();
    }
  }

  private async detectScanEnvironment(): Promise<ScanEnvironment> {
    const target = activeTargetContext.get();
    if (!target) throw new Error('没有已确认的活动 SSH 目标');
    if (this.scanEnvironmentCache?.sessionId === target.sessionId) {
      return this.scanEnvironmentCache.environment;
    }

    const capabilities = targetCapabilityStore.get(target);
    if (capabilities && !capabilities.exec) {
      const environment: ScanEnvironment = {
        kubernetes: false,
        webRoot: false,
        containerRuntime: false,
        checkedAt: Date.now(),
      };
      this.scanEnvironmentCache = { sessionId: target.sessionId, environment };
      return environment;
    }
    const fallbackCapabilityProbe = capabilities
      ? ''
      : `printf 'KUBERNETES='; if command -v kubectl >/dev/null 2>&1 && kubectl version --request-timeout=2s >/dev/null 2>&1; then echo 1; else echo 0; fi; printf 'CONTAINER_RUNTIME='; if command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1 || command -v crictl >/dev/null 2>&1 || command -v ctr >/dev/null 2>&1; then echo 1; else echo 0; fi; `;
    const result = await executeEmergencyCommand({
      command: `${fallbackCapabilityProbe}printf 'WEB_ROOT='; if [ -d /var/www ] || [ -d /srv/www ] || [ -d /usr/share/nginx/html ]; then echo 1; else echo 0; fi`,
      timeoutSec: 8,
    });
    if (!result.success) throw new Error(`环境预检失败: ${result.message}`);
    const value = (key: string) => new RegExp(`^${key}=1$`, 'm').test(result.output);
    const environment: ScanEnvironment = {
      kubernetes: capabilities
        ? targetCapabilityStore.evaluate('kubernetes')?.available === true
        : value('KUBERNETES'),
      webRoot: value('WEB_ROOT'),
      containerRuntime: capabilities
        ? ['docker', 'podman', 'crictl', 'ctr'].some(tool => capabilities.tools[tool] === true)
        : value('CONTAINER_RUNTIME'),
      checkedAt: Date.now(),
    };
    this.scanEnvironmentCache = { sessionId: target.sessionId, environment };
    return environment;
  }

  /**
   * 执行单个检测
   */
  private async executeDetection(itemId: string): Promise<DetectionResult> {
    const startTime = Date.now();
    let result: DetectionResult;

    switch (itemId) {
      case 'port-scan':
        result = await this.runPortScan();
        break;
      case 'user-audit':
        result = await this.runUserAudit();
        break;
      case 'backdoor-scan':
        result = await this.runBackdoorScan();
        break;
      case 'process-analysis':
        result = await this.runProcessAnalysis();
        break;
      case 'file-permission':
        result = await this.runFilePermissionCheck();
        break;
      case 'ssh-audit':
        result = await this.runSSHAudit();
        break;
      case 'log-analysis':
        result = await this.runLogAnalysis();
        break;
      case 'firewall-check':
        result = await this.runFirewallCheck();
        break;

      // 账号与认证安全
      case 'password-policy':
        result = await this.runPasswordPolicyCheck();
        break;
      case 'sudo-audit':
        result = await this.runSudoAudit();
        break;
      case 'pam-config':
        result = await this.runPAMConfigCheck();
        break;
      case 'account-lockout':
        result = await this.runAccountLockoutCheck();
        break;

      // 系统加固
      case 'selinux-status':
        result = await this.runSELinuxStatusCheck();
        break;
      case 'kernel-params':
        result = await this.runKernelParamsCheck();
        break;
      case 'system-updates':
        result = await this.runSystemUpdatesCheck();
        break;

      // 服务与进程
      case 'unnecessary-services':
        result = await this.runUnnecessaryServicesCheck();
        break;
      case 'auto-start-services':
        result = await this.runAutoStartServicesCheck();
        break;

      // 审计与日志
      case 'audit-config':
        result = await this.runAuditConfigCheck();
        break;
      case 'history-audit':
        result = await this.runHistoryAudit();
        break;

      // 网络与时间
      case 'ntp-config':
        result = await this.runNTPConfigCheck();
        break;
      case 'dns-config':
        result = await this.runDNSConfigCheck();
        break;

      // 竞赛级检测
      case 'webshell-scan':
        result = await this.detectionModules.runWebshellScan();
        break;
      case 'rootkit-scan':
        result = await this.detectionModules.runRootkitScan();
        break;
      case 'persistence-scan':
        result = await this.detectionModules.runPersistenceScan();
        break;
      case 'log-tamper':
        result = await this.detectionModules.runLogTamperCheck();
        break;
      case 'network-backdoor':
        result = await this.detectionModules.runNetworkBackdoorScan();
        break;
      case 'enhanced-user':
        result = await this.detectionModules.runEnhancedUserAudit();
        break;
      case 'hidden-cron':
        result = await this.detectionModules.runHiddenCronCheck();
        break;
      case 'ssh-key-audit':
        result = await this.detectionModules.runSSHKeyAudit();
        break;
      case 'timestomp-check':
        result = await this.detectionModules.runTimestompCheck();
        break;
      case 'enhanced-process':
        result = await this.detectionModules.runEnhancedProcessAnalysis();
        break;
      case 'bin-tamper':
        result = await this.detectionModules.runBinTamperScan();
        break;
      case 'immutable-files':
        result = await this.detectionModules.runImmutableFilesScan();
        break;

      // K8s 安全检测:实现在 detectionModules,通过 kubectl over SSH 采集。
      // 靶机没有 kubectl / 未接集群时各方法自行返回 createErrorResult 降级,不会中断整轮扫描。
      case 'k8s-privileged-pod':
        result = await this.detectionModules.runK8sPrivilegedPodScan();
        break;
      case 'k8s-reverse-shell':
        result = await this.detectionModules.runK8sReverseShellScan();
        break;
      case 'k8s-rbac-audit':
        result = await this.detectionModules.runK8sRBACAudit();
        break;
      case 'k8s-container-escape':
        result = await this.detectionModules.runK8sContainerEscapeScan();
        break;
      case 'k8s-suspicious-cronjob':
        result = await this.detectionModules.runK8sSuspiciousCronJobScan();
        break;
      case 'k8s-network-policy':
        result = await this.detectionModules.runK8sNetworkPolicyScan();
        break;
      case 'k8s-sa-audit':
        result = await this.detectionModules.runK8sSAAudit();
        break;
      case 'k8s-node-persistence':
        result = await this.detectionModules.runK8sNodePersistenceScan();
        break;

      // 性能检测
      case 'cpu-test':
        result = await this.runCPUTest();
        break;
      case 'memory-test':
        result = await this.runMemoryTest();
        break;
      case 'disk-test':
        result = await this.runDiskTest();
        break;
      case 'network-test':
        result = await this.runNetworkTest();
        break;
      default:
        throw new Error(`未知的检测项: ${itemId}`);
    }

    result.duration = Date.now() - startTime;
    result.timestamp = new Date();

    return result;
  }

  // ========== Detection Module 委托方法 ==========

  private async runPortScan(): Promise<DetectionResult> {
    return this.detectionModules.runPortScan();
  }

  private async runUserAudit(): Promise<DetectionResult> {
    return this.detectionModules.runUserAudit();
  }

  private async runBackdoorScan(): Promise<DetectionResult> {
    return this.detectionModules.runBackdoorScan();
  }

  private async runProcessAnalysis(): Promise<DetectionResult> {
    return this.detectionModules.runProcessAnalysis();
  }

  private async runFilePermissionCheck(): Promise<DetectionResult> {
    return this.detectionModules.runFilePermissionCheck();
  }

  private async runSSHAudit(): Promise<DetectionResult> {
    return this.detectionModules.runSSHAudit();
  }

  private async runLogAnalysis(): Promise<DetectionResult> {
    return this.detectionModules.runLogAnalysis();
  }

  private async runFirewallCheck(): Promise<DetectionResult> {
    return this.detectionModules.runFirewallCheck();
  }

  private async runCPUTest(): Promise<DetectionResult> {
    return this.detectionModules.runCPUTest();
  }

  private async runMemoryTest(): Promise<DetectionResult> {
    return this.detectionModules.runMemoryTest();
  }

  private async runDiskTest(): Promise<DetectionResult> {
    return this.detectionModules.runDiskTest();
  }

  private async runNetworkTest(): Promise<DetectionResult> {
    return this.detectionModules.runNetworkTest();
  }

  private async runPasswordPolicyCheck(): Promise<DetectionResult> {
    return this.detectionModules.runPasswordPolicyCheck();
  }

  private async runSudoAudit(): Promise<DetectionResult> {
    return this.detectionModules.runSudoAudit();
  }

  private async runPAMConfigCheck(): Promise<DetectionResult> {
    return this.detectionModules.runPAMConfigCheck();
  }

  private async runAccountLockoutCheck(): Promise<DetectionResult> {
    return this.detectionModules.runAccountLockoutCheck();
  }

  private async runSELinuxStatusCheck(): Promise<DetectionResult> {
    return this.detectionModules.runSELinuxStatusCheck();
  }

  private async runKernelParamsCheck(): Promise<DetectionResult> {
    return this.detectionModules.runKernelParamsCheck();
  }

  private async runSystemUpdatesCheck(): Promise<DetectionResult> {
    return this.detectionModules.runSystemUpdatesCheck();
  }

  private async runUnnecessaryServicesCheck(): Promise<DetectionResult> {
    return this.detectionModules.runUnnecessaryServicesCheck();
  }

  private async runAutoStartServicesCheck(): Promise<DetectionResult> {
    return this.detectionModules.runAutoStartServicesCheck();
  }

  private async runAuditConfigCheck(): Promise<DetectionResult> {
    return this.detectionModules.runAuditConfigCheck();
  }

  private async runHistoryAudit(): Promise<DetectionResult> {
    return this.detectionModules.runHistoryAudit();
  }

  private async runNTPConfigCheck(): Promise<DetectionResult> {
    return this.detectionModules.runNTPConfigCheck();
  }

  private async runDNSConfigCheck(): Promise<DetectionResult> {
    return this.detectionModules.runDNSConfigCheck();
  }

  // ========== Report Renderer 委托方法 ==========

  private updateProgress(progress: number, currentTask: string): void {
    this.reportRenderer.setProgressCallback(this.progressCallback);
    this.reportRenderer.updateProgress(progress, currentTask);
  }

  private updateCheckStatus(checkId: string, status: string, result?: DetectionResult): void {
    this.reportRenderer.updateCheckStatus(checkId, status, result);
  }

  private showProgressPanel(): void {
    this.reportRenderer.showProgressPanel();
  }

  private hideProgressPanel(): void {
    this.reportRenderer.hideProgressPanel();
  }

  private showSummaryPanel(report: DetectionReport): void {
    this.reportRenderer.showSummaryPanel(report);
  }

  viewReport(): void {
    this.reportRenderer.setCurrentReport(this.currentReport);
    this.reportRenderer.viewReport();
  }

  closeReportModal(): void {
    this.reportRenderer.closeReportModal();
  }

  showRawOutput(itemId: string): void {
    this.reportRenderer.setCurrentReport(this.currentReport);
    this.reportRenderer.showRawOutput(itemId);
  }

  // ========== AI Manager 委托方法 ==========

  async generateAISolutionStream(title: string, description: string, severity: string, containerId: string): Promise<void> {
    this.aiManager.currentReport = this.currentReport;
    return this.aiManager.generateAISolutionStream(title, description, severity, containerId);
  }

  private showConfirm(options: {
    title: string;
    message: string;
    description?: string;
    confirmText?: string;
    cancelText?: string;
    dangerous?: boolean;
  }): Promise<boolean> {
    return showConfirm(options);
  }

  async generateAISolution(title: string, description: string, severity: string = 'medium'): Promise<void> {
    this.aiManager.currentReport = this.currentReport;
    return this.aiManager.generateAISolution(title, description, severity);
  }

  // ========== 评分计算（保留在本类中） ==========

  /**
   * 工具方法：计算总体评分
   */
  private calculateOverallScore(report: DetectionReport): number {
    return calculateTrustedScore(report.items);
  }

  // ========== 历史记录方法（保留在本类中） ==========

  /**
   * 历史记录：保存到历史
   */
  private saveToHistory(report: DetectionReport): void {
    this.detectionHistory.unshift(report);

    // 只保留最近 10 条记录
    if (this.detectionHistory.length > 10) {
      this.detectionHistory = this.detectionHistory.slice(0, 10);
    }

    // 保存到 localStorage（移除 rawOutput 防止超出 5MB 限制）
    try {
      const compactHistory = this.detectionHistory.map(r => ({
        ...r,
        items: r.items.map(item => ({
          ...item,
          result: item.result ? { ...item.result, rawOutput: undefined } : item.result,
        })),
      }));
      localStorage.setItem('detection-history', JSON.stringify(compactHistory));
    } catch (error) {
      console.error('保存历史记录失败:', error);
      window.showNotification?.('检测历史保存失败，可能存储空间不足', 'warning');
    }

  }

  /**
   * 历史记录：加载历史
   */
  private loadHistory(): void {
    try {
      const historyStr = localStorage.getItem('detection-history');
      if (historyStr) {
        this.detectionHistory = JSON.parse(historyStr);
      }
    } catch (error) {
      console.error('加载历史记录失败:', error);
      this.detectionHistory = [];
    }
  }

  getScanHistory(): DetectionReport[] {
    return [...this.detectionHistory];
  }

  /**
   * 历史记录：清空历史
   */
  async clearHistory(): Promise<void> {
    const confirmed = await this.showConfirm({
      title: '确认清空历史',
      message: '确定要清空所有检测历史吗？',
      description: '此操作不可撤销',
      confirmText: '清空',
      cancelText: '取消',
      dangerous: true
    });

    if (confirmed) {
      this.detectionHistory = [];
      try {
        localStorage.removeItem('detection-history');
      } catch (error) {
        reportError(error, { module: 'QuickDetection', action: 'clear-history', silent: true });
      }
    }
  }

  /**
   * 历史记录：查看历史报告
   */
  viewHistoryReport(reportId: string): void {
    const report = this.detectionHistory.find(r => r.id === reportId);
    if (report?.target && activeTargetContext.matches(report.target)) {
      this.currentReport = report;
      this.viewReport();
    }
  }

  selectHistoryReport(reportId: string): boolean {
    const report = this.detectionHistory.find(item => item.id === reportId);
    if (!report?.target || !activeTargetContext.matches(report.target)) return false;
    this.currentReport = report;
    return true;
  }

  /**
   * 导出报告（HTML 格式）
   */
  exportReport(): void {
    if (!this.currentReport) {
      showAlert({ title: '提示', message: '暂无可导出的报告' });
      return;
    }

    try {
      ReportExporter.exportAsHTML(this.currentReport);
    } catch (e) {
      console.error('导出报告失败:', e);
      showAlert({ title: '错误', message: '导出报告失败，请重试', type: 'error' });
    }
  }

  /**
   * UI 方法：全选/取消检测项
   */
  toggleAllChecks(category: 'security' | 'performance' | 'competition'): void {
    const checkboxes = document.querySelectorAll(`.detection-item[data-category="${category}"] input[type="checkbox"]`);
    if (checkboxes.length === 0) return;

    const firstCheckbox = checkboxes[0] as HTMLInputElement;
    const newState = !firstCheckbox.checked;

    checkboxes.forEach(cb => {
      const checkbox = cb as HTMLInputElement;
      checkbox.checked = newState;

      // 更新父元素的视觉样式
      const item = checkbox.closest('.detection-item') as HTMLElement;
      if (item) {
        if (newState) {
          item.classList.add('selected');
          item.style.borderColor = 'var(--primary-color)';
          item.style.background = 'var(--bg-primary)';
          item.style.boxShadow = '0 4px 12px rgba(0, 0, 0, 0.05)';
        } else {
          item.classList.remove('selected');
          item.style.borderColor = 'var(--border-color)';
          item.style.background = 'var(--bg-secondary)';
          item.style.boxShadow = 'none';
        }
      }
    });
  }

  // ========== 工具方法（保留在本类中） ==========

  /**
   * 工具方法：获取选中的检测项 ID
   */
  private getAllCheckIds(): string[] {
    const checkboxes = document.querySelectorAll('.detection-item input[type="checkbox"]:checked');
    return Array.from(checkboxes).map(cb => {
      const parent = cb.closest('.detection-item');
      return parent?.getAttribute('data-check-id') || '';
    }).filter(id => id !== '');
  }

  /**
   * 工具方法：获取检测项名称
   */
  private getCheckName(id: string): string {
    const names: Record<string, string> = {
      'port-scan': '端口安全扫描', 'user-audit': '用户权限审计',
      'backdoor-scan': '后门检测', 'process-analysis': '可疑进程分析',
      'file-permission': '文件权限检测', 'ssh-audit': 'SSH 安全审计',
      'log-analysis': '日志安全分析', 'firewall-check': '防火墙状态检查',
      'password-policy': '密码策略检查', 'sudo-audit': 'Sudo 配置审计',
      'pam-config': 'PAM 配置检查', 'account-lockout': '账号锁定策略',
      'selinux-status': 'SELinux/AppArmor', 'kernel-params': '内核参数检查',
      'system-updates': '系统补丁状态', 'unnecessary-services': '不必要服务',
      'auto-start-services': '自启动服务审计', 'audit-config': '审计配置检查',
      'history-audit': '历史命令审计', 'ntp-config': 'NTP 配置检查',
      'dns-config': 'DNS 配置检查',
      // 竞赛级检测
      'webshell-scan': 'Webshell 扫描', 'rootkit-scan': 'Rootkit 检测',
      'persistence-scan': '持久化机制扫描', 'log-tamper': '日志篡改检测',
      'network-backdoor': '网络后门检测', 'enhanced-user': '增强用户审计',
      'hidden-cron': '隐藏计划任务', 'ssh-key-audit': 'SSH 密钥审计',
      'timestomp-check': '时间戳篡改检测', 'enhanced-process': '增强进程分析',
      'bin-tamper': '命令篡改检测(bin/sbin)', 'immutable-files': '文件不可变属性检测',
      // K8s 安全检测
      'k8s-privileged-pod': 'K8s 特权容器检测', 'k8s-reverse-shell': 'K8s 反弹Shell检测',
      'k8s-rbac-audit': 'K8s RBAC 审计', 'k8s-container-escape': 'K8s 容器逃逸检测',
      'k8s-suspicious-cronjob': 'K8s 恶意CronJob检测', 'k8s-network-policy': 'K8s 网络策略检测',
      'k8s-sa-audit': 'K8s SA 审计', 'k8s-node-persistence': 'K8s 节点持久化检测',
      // 性能检测
      'cpu-test': 'CPU 压力测试', 'memory-test': '内存性能测试',
      'disk-test': '磁盘 I/O 测试', 'network-test': '网络性能测试',
    };
    return names[id] || id;
  }

  /**
   * 工具方法：获取检测项描述
   */
  private getCheckDescription(id: string): string {
    const descriptions: Record<string, string> = {
      'port-scan': '检测开放端口和高危服务', 'user-audit': '检查用户权限和空密码账号',
      'backdoor-scan': '扫描后门和可疑计划任务', 'process-analysis': '识别异常进程和网络连接',
      'file-permission': '检查敏感文件和 SUID 文件', 'ssh-audit': '检查 SSH 配置安全性',
      'log-analysis': '分析异常登录和暴力破解', 'firewall-check': '检查防火墙规则配置',
      'password-policy': '检查密码复杂度和有效期策略', 'sudo-audit': '检查 NOPASSWD 等危险配置',
      'pam-config': '检查 PAM 认证模块配置', 'account-lockout': '检查登录失败锁定策略',
      'selinux-status': '检查强制访问控制状态', 'kernel-params': '检查安全相关内核参数',
      'system-updates': '检查可用安全补丁', 'unnecessary-services': '检查危险服务 (telnet/ftp)',
      'auto-start-services': '审计自启动服务数量', 'audit-config': '检查 auditd 审计配置',
      'history-audit': '扫描命令历史中的可疑操作', 'ntp-config': '检查时间同步配置',
      'dns-config': '检查 DNS 解析配置',
      'webshell-scan': '扫描 Web 目录中的 Webshell 文件', 'rootkit-scan': '检测隐藏进程、内核模块、LD_PRELOAD',
      'persistence-scan': '全量扫描持久化机制 (cron/bashrc/systemd/rc.local)', 'log-tamper': '检测日志被清空、删除、篡改的证据',
      'network-backdoor': '检测反弹 Shell、C2 连接、可疑监听', 'enhanced-user': 'UID 冲突、全用户历史命令、sudo 组异常',
      'hidden-cron': '深度扫描所有 cron 目录和 at 队列', 'ssh-key-audit': '审计所有 SSH 密钥和 sshd 配置',
      'timestomp-check': '检测 mtime 与 ctime 异常的文件', 'enhanced-process': '扩大进程扫描范围，检测可疑二进制',
      'bin-tamper': '检测 /bin /sbin 中被替换为脚本的命令(命令劫持)', 'immutable-files': '检测 chattr +i 不可变文件(rootkit隐藏手段)',
      'k8s-privileged-pod': '检测以 privileged 模式运行的容器',
      'k8s-reverse-shell': '检测 Pod 中的反弹Shell命令',
      'k8s-rbac-audit': '检测 cluster-admin 绑定和通配符权限',
      'k8s-container-escape': '检测 hostPID/hostIPC/危险 Capabilities',
      'k8s-suspicious-cronjob': '检测恶意定时任务(CronJob)',
      'k8s-network-policy': '检测缺少 NetworkPolicy 的命名空间',
      'k8s-sa-audit': '检测高权限 ServiceAccount',
      'k8s-node-persistence': '检测节点上的可疑服务和 crontab',
      'cpu-test': '测试 CPU 性能和频率', 'memory-test': '测试内存读写速度',
      'disk-test': '测试磁盘读写性能', 'network-test': '测试带宽和延迟',
    };
    return descriptions[id] || '';
  }

  /**
   * 工具方法：获取检测项分类
   */
  private getCheckCategory(id: string): 'security' | 'performance' | 'competition' {
    const performanceChecks = ['cpu-test', 'memory-test', 'disk-test', 'network-test'];
    const competitionChecks = [
      'webshell-scan', 'rootkit-scan', 'persistence-scan', 'log-tamper',
      'network-backdoor', 'enhanced-user', 'hidden-cron', 'ssh-key-audit',
      'timestomp-check', 'enhanced-process', 'bin-tamper', 'immutable-files',
      'k8s-privileged-pod', 'k8s-reverse-shell', 'k8s-rbac-audit',
      'k8s-container-escape', 'k8s-suspicious-cronjob', 'k8s-network-policy',
      'k8s-sa-audit', 'k8s-node-persistence',
    ];
    if (performanceChecks.includes(id)) return 'performance';
    if (competitionChecks.includes(id)) return 'competition';
    return 'security';
  }

  /** 比赛首分钟摸底：高价值、只读、critical-first，不包含性能压测和无关 K8s 扫描。 */
  async startCompetitionScan(): Promise<DetectionReport> {
    return this.runScan(COMPETITION_TRIAGE_IDS, 'competition-triage');
  }

  /**
   * 工具方法：生成报告 ID
   */
  private generateReportId(): string {
    return `report-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * 工具方法：获取当前服务器信息
   */
  private getCurrentServerInfo(): string {
    const sshConnectionManager = (window as any).sshConnectionManager;
    const connectionStatus = sshConnectionManager?.getConnectionStatus?.();

    if (connectionStatus && connectionStatus.connected) {
      return `${connectionStatus.username}@${connectionStatus.host}:${connectionStatus.port}`;
    }

    return '未知服务器';
  }

  /**
   * 设置进度回调
   */
  setProgressCallback(callback: (progress: number, current: string) => void): void {
    this.progressCallback = callback;
  }

  // ════════════════════════════════════════════════════
  // 修复能力集成
  // ════════════════════════════════════════════════════

  /** 获取某个检测项的所有可用修复动作 */
  getFixActions(detectionItemId: string, findingTitle?: string): FixActionDef[] {
    if (findingTitle) return getFixActionsForFinding(detectionItemId, findingTitle);
    return getFixActionsForDetectionItem(detectionItemId);
  }

  /** 创建 FixAction 实例 */
  createFixAction(detectionItemId: string, findingTitle: string, def: FixActionDef): FixAction {
    return {
      id: `fa_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`,
      detectionItemId,
      findingTitle,
      def,
      status: 'pending',
    };
  }

  /** 执行单个修复 */
  async executeSingleFix(
    detectionItemId: string,
    findingTitle: string,
    actionDef: FixActionDef,
    onStatus?: (action: FixAction) => void,
  ): Promise<FixResult> {
    const action = this.createFixAction(detectionItemId, findingTitle, actionDef);
    fixExecutor.setServer(this.getServerInfo());

    // 解析 baseline 配置项 (如果是 baseline 类型)
    let resolved: ResolvedBaselineItem | undefined;
    if (actionDef.type === 'baseline' && actionDef.baselineItemId) {
      resolved = await this.resolveBaselineItem(actionDef.baselineItemId, actionDef.recommendedValue);
    }

    return fixExecutor.executeFix(action, resolved, onStatus);
  }

  /** 批量执行所有可修复的 findings */
  async executeAllFixes(
    onStatus?: (action: FixAction) => void,
    onProgress?: (completed: number, total: number) => void,
  ): Promise<FixResult[]> {
    if (!this.currentReport) return [];
    fixExecutor.setServer(this.getServerInfo());

    const actions: FixAction[] = [];
    const resolvedMap = new Map<string, ResolvedBaselineItem>();

    for (const item of this.currentReport.items) {
      if (!item.result?.findings) continue;
      for (const finding of item.result.findings) {
        const defs = getFixActionsForFinding(item.id, finding.title);
        for (const def of defs) {
          const action = this.createFixAction(item.id, finding.title, def);
          actions.push(action);
          if (def.type === 'baseline' && def.baselineItemId && !resolvedMap.has(def.baselineItemId)) {
            const resolved = await this.resolveBaselineItem(def.baselineItemId, def.recommendedValue);
            if (resolved) resolvedMap.set(def.baselineItemId, resolved);
          }
        }
      }
    }

    if (actions.length === 0) {
      window.showNotification?.('没有可自动修复的项目', 'info');
      return [];
    }

    const confirmed = await showConfirm({
      title: '批量修复',
      message: `将执行 ${actions.length} 项修复操作，所有修改前会自动备份。确认继续？`,
      confirmText: `执行 ${actions.length} 项修复`,
      cancelText: '取消',
      dangerous: true,
      defaultFocus: 'cancel',
    });
    if (!confirmed) return [];

    return fixExecutor.executeBatch(actions, resolvedMap, onStatus, onProgress);
  }

  /** 重新验证某个检测项 */
  async reVerify(detectionItemId: string): Promise<DetectionResult> {
    return this.detectionModules.runSingleDetection(detectionItemId);
  }

  async reVerifyAndUpdate(detectionItemId: string): Promise<DetectionResult> {
    const result = await this.reVerify(detectionItemId);
    const item = this.currentReport?.items.find(entry => entry.id === detectionItemId);
    if (item && this.currentReport) {
      item.result = result;
      item.status = 'completed';
      this.currentReport.summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const reportItem of this.currentReport.items) {
        const outcome = normalizeOutcome(reportItem);
        if (outcome === 'passed' || outcome === 'failed') {
          for (const finding of reportItem.result?.findings || []) {
            this.currentReport.summary[finding.severity] += 1;
          }
        }
      }
      this.currentReport.overallScore = this.calculateOverallScore(this.currentReport);
      this.showSummaryPanel(this.currentReport);
    }
    return result;
  }

  /** 回滚历史修复 */
  async rollbackFix(entryId: string): Promise<{ success: boolean; output: string }> {
    return fixHistoryManager.rollback(entryId);
  }

  /** 获取修复历史 */
  getFixHistory(): FixHistoryEntry[] {
    return fixHistoryManager.getHistory();
  }

  /** 清空修复历史 */
  clearFixHistory(): void {
    fixHistoryManager.clear();
  }

  /** 获取加固项列表 */
  getHardeningItems(): HardeningItem[] {
    return HARDENING_ITEMS;
  }

  /** 检查单个加固项状态 */
  async checkHardeningStatus(item: HardeningItem): Promise<boolean> {
    try {
      const result = await executeEmergencyCommand({ command: item.checkCommand });
      return result.success && item.checkPassed.test(result.output);
    } catch { return false; }
  }

  /** 执行单个加固项 */
  async executeHardening(item: HardeningItem): Promise<{ success: boolean; verified: boolean; output: string }> {
    const beforeSafe = await this.checkHardeningStatus(item);
    try {
      const result = await executeEmergencyCommand({ command: item.fixCommand });
      const verified = result.success && await this.checkHardeningStatus(item);
      const output = result.success ? (result.output || 'done') : `${result.message}: ${result.output}`;
      operationJournal.record({
        source: 'detection-hardening',
        server: this.getServerInfo(),
        title: item.title,
        command: item.fixCommand,
        beforeValue: beforeSafe ? 'safe' : 'unsafe',
        afterValue: verified ? 'safe' : 'verification-failed',
        output,
        success: result.success && verified,
      });
      return { success: result.success, verified, output };
    } catch (e) {
      const output = `failed: ${e}`;
      operationJournal.record({
        source: 'detection-hardening',
        server: this.getServerInfo(),
        title: item.title,
        command: item.fixCommand,
        beforeValue: beforeSafe ? 'safe' : 'unsafe',
        afterValue: 'error',
        output,
        success: false,
      });
      return { success: false, verified: false, output };
    }
  }

  /** 探测目标发行版类型，供 resolveForDistro 选择对应发行版的命令；失败保底 generic */
  private async getDetectedDistro(): Promise<string> {
    const sessionId = activeTargetContext.get()?.sessionId || null;
    if (this.detectedDistro && this.detectedDistroSessionId === sessionId) return this.detectedDistro;
    if (this.detectedDistroSessionId !== sessionId) {
      this.detectedDistro = null;
      SystemDetector.clearCache();
    }
    try {
      this.detectedDistro = (await SystemDetector.detectSystem()).type;
    } catch {
      this.detectedDistro = 'generic';
    }
    this.detectedDistroSessionId = sessionId;
    return this.detectedDistro;
  }

  /** 解析 baseline 配置项为可执行数据 */
  private async resolveBaselineItem(baselineItemId: string, overrideValue?: string): Promise<ResolvedBaselineItem | undefined> {
    try {
      // 动态导入 baselineConfigs 避免循环依赖
      const { baselineCategories, resolveForDistro } = await import('../baseline/baselineConfigs');

      for (const cat of baselineCategories) {
        for (const item of cat.items) {
          if (item.id === baselineItemId) {
            const distro = await this.getDetectedDistro();
            const resolved = resolveForDistro ? resolveForDistro(item, distro) : item;
            return {
              id: item.id,
              filePath: resolved.filePath || item.filePath,
              readCommand: resolved.readCommand || item.readCommand,
              writeCommand: resolved.writeCommand || item.writeCommand,
              parseRegex: item.parseRegex,
              backupCommand: resolved.backupCommand || item.backupCommand,
              restartCommand: resolved.restartCommand || item.restartCommand,
              recommendedValue: overrideValue || item.recommendedValue,
            };
          }
        }
      }
    } catch (e) {
      console.warn('解析 baseline 配置失败:', baselineItemId, e);
    }
    return undefined;
  }

  private getServerInfo(): string {
    try {
      const conn = (window as any).sshConnectionManager;
      return conn?.getConnectionStatus?.()?.host || 'unknown';
    } catch { return 'unknown'; }
  }
}

// 创建全局实例
export const quickDetectionManager = new QuickDetectionManager();
