import { invokeTargetBoundSSH } from './targetBoundSSH';
import { activeTargetContext, stableTargetKey, type TargetIdentity } from './targetContext';
import { logger } from './logger';

const log = logger.module('TargetCapabilities');

export interface TargetCapabilities {
  schema: 'lovelyres-target-capabilities/v1';
  osId: string;
  osIdLike: string;
  osVersion: string;
  prettyName: string;
  kernel: string;
  shell: string;
  uid?: number;
  isRoot: boolean;
  sudoNonInteractive: boolean;
  doasNonInteractive: boolean;
  procfs: boolean;
  exec: boolean;
  sftp: boolean;
  pty: boolean;
  initSystem: string;
  tools: Record<string, boolean>;
  probeError?: string | null;
  probedAt: string;
}

export type CapabilityAwareFeature =
  | 'terminal'
  | 'sftp'
  | 'system-info'
  | 'log-analysis'
  | 'packet-capture'
  | 'firewall'
  | 'docker'
  | 'kubernetes'
  | 'baseline-mutation';

export interface FeatureCapability {
  feature: CapabilityAwareFeature;
  available: boolean;
  reason?: string;
  alternative?: string;
}

function hasTool(capabilities: TargetCapabilities, tool: string): boolean {
  return capabilities.tools[tool] === true;
}

export function evaluateTargetFeature(
  capabilities: TargetCapabilities,
  feature: CapabilityAwareFeature,
): FeatureCapability {
  let available = false;
  let reason = '';
  let alternative = '';

  switch (feature) {
    case 'terminal':
      available = capabilities.exec && capabilities.pty;
      reason = '目标不接受 PTY，会话只能使用非交互命令';
      alternative = '使用应急命令页的非交互执行';
      break;
    case 'sftp':
      available = capabilities.sftp;
      reason = '目标未启用 SFTP subsystem';
      alternative = '使用经过转义的 cat/base64 命令传输小文件';
      break;
    case 'system-info':
      available = capabilities.procfs && hasTool(capabilities, 'ps');
      reason = '目标缺少可读 /proc 或 ps';
      alternative = '使用通用 uname、id 和文件核查命令';
      break;
    case 'log-analysis':
      available = hasTool(capabilities, 'journalctl') || hasTool(capabilities, 'find');
      reason = '目标没有 journalctl，也缺少通用日志发现工具';
      alternative = '在应急命令页手动读取已知日志路径';
      break;
    case 'packet-capture':
      available = hasTool(capabilities, 'tcpdump') || hasTool(capabilities, 'dumpcap');
      reason = '目标没有 tcpdump/dumpcap';
      alternative = '使用 ss/netstat 收集连接快照';
      break;
    case 'firewall':
      available = hasTool(capabilities, 'nft')
        || hasTool(capabilities, 'iptables')
        || hasTool(capabilities, 'firewall-cmd');
      reason = '目标未检测到受支持的防火墙前端';
      alternative = '仅生成隔离建议，不自动下发规则';
      break;
    case 'docker':
      available = hasTool(capabilities, 'docker') || hasTool(capabilities, 'podman');
      reason = '目标未检测到 Docker/Podman';
      alternative = '跳过容器处置，继续宿主机调查';
      break;
    case 'kubernetes':
      available = hasTool(capabilities, 'kubectl')
        || hasTool(capabilities, 'crictl')
        || hasTool(capabilities, 'ctr');
      reason = '目标未检测到 Kubernetes/CRI 工具';
      alternative = '将 Kubernetes 检测标记为 N/A';
      break;
    case 'baseline-mutation':
      available = capabilities.isRoot
        || capabilities.sudoNonInteractive
        || capabilities.doasNonInteractive;
      reason = '当前账户没有可用的非交互提权能力';
      alternative = '只运行只读核查并导出处置命令';
      break;
  }

  return {
    feature,
    available,
    reason: available ? undefined : reason,
    alternative: available ? undefined : alternative,
  };
}

class TargetCapabilityStore {
  private byTarget = new Map<string, TargetCapabilities>();

  async probeActiveTarget(): Promise<TargetCapabilities> {
    const target = activeTargetContext.get();
    if (!target) throw new Error('没有已确认的活动 SSH 目标');
    const capabilities = await invokeTargetBoundSSH<TargetCapabilities>('ssh_probe_capabilities');
    if (capabilities.schema !== 'lovelyres-target-capabilities/v1') {
      throw new Error('目标能力探测返回了未知格式');
    }
    this.byTarget.set(stableTargetKey(target), capabilities);
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new CustomEvent('target-capabilities-changed', {
        detail: { target: { ...target }, capabilities: { ...capabilities } },
      }));
    }
    log.info('目标能力预检完成', {
      target: `${target.username}@${target.host}:${target.port}`,
      os: `${capabilities.osId} ${capabilities.osVersion}`.trim(),
      sftp: capabilities.sftp,
      pty: capabilities.pty,
    });
    if (capabilities.probeError) {
      log.warn('目标能力预检已降级', capabilities.probeError);
    }
    return capabilities;
  }

  get(target: TargetIdentity | null = activeTargetContext.get()): TargetCapabilities | null {
    if (!target) return null;
    const capabilities = this.byTarget.get(stableTargetKey(target));
    return capabilities ? { ...capabilities, tools: { ...capabilities.tools } } : null;
  }

  evaluate(feature: CapabilityAwareFeature): FeatureCapability | null {
    const capabilities = this.get();
    return capabilities ? evaluateTargetFeature(capabilities, feature) : null;
  }

  clear(target?: TargetIdentity): void {
    if (target) this.byTarget.delete(stableTargetKey(target));
    else this.byTarget.clear();
  }
}

export const targetCapabilityStore = new TargetCapabilityStore();
