import type {
  DockerActionResult,
  DockerContainerSummary,
  DockerCopyRequest,
  DockerLogsOptions,
  DockerImage,
  DockerNetwork,
  DockerVolume,
  DockerComposeProject,
  DockerSystemInfo,
  DockerDiskUsage,
  DockerOverviewStats,
} from './types';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';
import { logger } from '../core/logger';
import { shq } from '../core/shellEscape';

const log = logger.module('DockerManager');

type DockerContainerAction = 'start' | 'stop' | 'restart' | 'kill' | 'pause' | 'unpause';

export interface DockerShellResult {
  success: boolean;
  output: string;
  exitCode: number | null;
  timedOut: boolean;
}

type SSHCommandResult = {
  output: string;
  exit_code: number | null;
  timed_out?: boolean;
};

export class DockerManager {
  private containers: DockerContainerSummary[] = [];

  // ============================================================
  // SSH Command Helper
  // ============================================================

  private async execSSH(command: string): Promise<SSHCommandResult | null> {
    if (!sshConnectionManager.isConnected()) return null;
    try {
      return await invokeTargetBoundSSH('ssh_execute_dashboard_command_direct', { command });
    } catch (e) {
      log.error(`SSH 命令失败: ${command}`, e);
      return null;
    }
  }

  private shellResult(result: SSHCommandResult | null): DockerShellResult {
    return {
      success: result?.timed_out !== true && result?.exit_code === 0,
      output: result?.output || '',
      exitCode: result?.exit_code ?? null,
      timedOut: result?.timed_out === true,
    };
  }

  // ============================================================
  // Container Operations (existing, via Tauri invoke)
  // ============================================================

  getCachedContainers(): DockerContainerSummary[] {
    return [...this.containers];
  }

  async listContainers(): Promise<DockerContainerSummary[]> {
    const containers = await invokeTargetBoundSSH<DockerContainerSummary[]>('docker_list_containers');
    this.containers = containers;
    return [...containers];
  }

  async performAction(containerRef: string, action: DockerContainerAction): Promise<DockerActionResult> {
    return invokeTargetBoundSSH<DockerActionResult>('docker_container_action', {
      containerId: containerRef,
      action,
    });
  }

  async getLogs(containerRef: string, options?: Partial<DockerLogsOptions>): Promise<string> {
    const payload: DockerLogsOptions | undefined = options
      ? {
          tail: options.tail,
          since: options.since,
          timestamps: options.timestamps ?? false,
          stdout: options.stdout ?? true,
          stderr: options.stderr ?? true,
        }
      : undefined;

    return invokeTargetBoundSSH<string>('docker_container_logs', {
      containerId: containerRef,
      options: payload,
    });
  }

  async inspect(containerRef: string): Promise<unknown> {
    return invokeTargetBoundSSH('docker_inspect_container', { containerId: containerRef });
  }

  async readFile(containerRef: string, path: string): Promise<string> {
    return invokeTargetBoundSSH<string>('docker_read_container_file', { containerId: containerRef, path });
  }

  async execCommand(containerRef: string, command: string): Promise<any> {
    return invokeTargetBoundSSH('docker_exec_command', { containerId: containerRef, command });
  }

  async createContainerTerminalWindow(containerName: string, containerId: string): Promise<string> {
    return invokeTargetBoundSSH<string>('create_container_terminal_window', { containerName, containerId });
  }

  async writeFile(containerRef: string, path: string, content: string): Promise<DockerActionResult> {
    return invokeTargetBoundSSH<DockerActionResult>('docker_write_container_file', { containerId: containerRef, path, content });
  }

  async copy(containerRef: string, request: DockerCopyRequest): Promise<DockerActionResult> {
    return invokeTargetBoundSSH<DockerActionResult>('docker_copy', { containerId: containerRef, request });
  }

  // ============================================================
  // Image Operations (via SSH)
  // ============================================================

  async listImages(): Promise<DockerImage[]> {
    // Try --format json first (Docker 23.0+), fallback to Go template
    let result = await this.execSSH('docker images --format json');
    if (!result || result.exit_code !== 0 || !result.output.trim()) {
      result = await this.execSSH('docker images --format "{{json .}}"');
    }
    if (!result || result.exit_code !== 0) return [];

    return result.output.trim().split('\n').filter(Boolean).map(line => {
      try {
        const img = JSON.parse(line);
        return {
          id: img.ID || '',
          shortId: (img.ID || '').substring(0, 12),
          repository: img.Repository || '<none>',
          tag: img.Tag || '<none>',
          size: img.Size || '',
          created: img.CreatedSince || img.CreatedAt || '',
          containers: 0
        };
      } catch { return null; }
    }).filter(Boolean) as DockerImage[];
  }

  async removeImage(imageRef: string, force: boolean = false): Promise<DockerShellResult> {
    const cmd = force ? `docker rmi -f ${shq(imageRef)}` : `docker rmi ${shq(imageRef)}`;
    const result = await this.execSSH(cmd);
    return this.shellResult(result);
  }

  async pullImage(imageName: string): Promise<{ success: boolean; output: string }> {
    const result = await this.execSSH(`docker pull ${shq(imageName)}`);
    return { success: result?.exit_code === 0, output: result?.output || '' };
  }

  async pruneImages(): Promise<DockerShellResult> {
    const result = await this.execSSH('docker image prune -f');
    return this.shellResult(result);
  }

  // ============================================================
  // Network Operations (via SSH)
  // ============================================================

  async listNetworks(): Promise<DockerNetwork[]> {
    let result = await this.execSSH('docker network ls --format json');
    if (!result || result.exit_code !== 0 || !result.output.trim()) {
      result = await this.execSSH('docker network ls --format "{{json .}}"');
    }
    if (!result || result.exit_code !== 0) return [];

    return result.output.trim().split('\n').filter(Boolean).map(line => {
      try {
        const net = JSON.parse(line);
        return {
          id: net.ID || '',
          shortId: (net.ID || '').substring(0, 12),
          name: net.Name || '',
          driver: net.Driver || '',
          scope: net.Scope || '',
          ipam: '',
          containers: 0,
          internal: net.Internal === 'true'
        };
      } catch { return null; }
    }).filter(Boolean) as DockerNetwork[];
  }

  async inspectNetwork(networkRef: string): Promise<string> {
    const result = await this.execSSH(`docker network inspect ${shq(networkRef)}`);
    return result?.output || '';
  }

  async removeNetwork(networkRef: string): Promise<DockerShellResult> {
    const result = await this.execSSH(`docker network rm ${shq(networkRef)}`);
    return this.shellResult(result);
  }

  async disconnectContainer(networkRef: string, containerRef: string): Promise<{ success: boolean; output: string }> {
    const result = await this.execSSH(`docker network disconnect ${shq(networkRef)} ${shq(containerRef)}`);
    return { success: result?.exit_code === 0, output: result?.output || '' };
  }

  async pruneNetworks(): Promise<DockerShellResult> {
    const result = await this.execSSH('docker network prune -f');
    return this.shellResult(result);
  }

  // ============================================================
  // Volume Operations (via SSH)
  // ============================================================

  async listVolumes(): Promise<DockerVolume[]> {
    let result = await this.execSSH('docker volume ls --format json');
    if (!result || result.exit_code !== 0 || !result.output.trim()) {
      result = await this.execSSH('docker volume ls --format "{{json .}}"');
    }
    if (!result || result.exit_code !== 0) return [];

    return result.output.trim().split('\n').filter(Boolean).map(line => {
      try {
        const vol = JSON.parse(line);
        return {
          name: vol.Name || '',
          driver: vol.Driver || 'local',
          mountpoint: vol.Mountpoint || '',
          scope: vol.Scope || 'local',
          labels: {},
          usedBy: []
        };
      } catch { return null; }
    }).filter(Boolean) as DockerVolume[];
  }

  async removeVolume(volumeRef: string, force: boolean = false): Promise<DockerShellResult> {
    const cmd = force ? `docker volume rm -f ${shq(volumeRef)}` : `docker volume rm ${shq(volumeRef)}`;
    const result = await this.execSSH(cmd);
    return this.shellResult(result);
  }

  async pruneVolumes(): Promise<DockerShellResult> {
    const result = await this.execSSH('docker volume prune -f');
    return this.shellResult(result);
  }

  // ============================================================
  // Compose Operations (via SSH)
  // ============================================================

  async listComposeProjects(): Promise<DockerComposeProject[]> {
    const result = await this.execSSH('docker compose ls --format json 2>/dev/null || echo "[]"');
    if (!result || result.exit_code !== 0) return [];

    try {
      const projects = JSON.parse(result.output);
      if (!Array.isArray(projects)) return [];
      return projects.map((p: any) => ({
        name: p.Name || '',
        status: p.Status || '',
        configFiles: p.ConfigFiles || '',
        services: 0,
        running: (p.Status || '').match(/running\((\d+)\)/)?.[1] ? parseInt((p.Status || '').match(/running\((\d+)\)/)[1]) : 0,
        stopped: 0
      }));
    } catch { return []; }
  }

  async composeAction(projectPath: string, action: 'up' | 'down' | 'restart' | 'stop' | 'pull'): Promise<{ success: boolean; output: string }> {
    let cmd = `docker compose -f ${shq(projectPath)}`;
    switch (action) {
      case 'up': cmd += ' up -d'; break;
      case 'down': cmd += ' down'; break;
      case 'restart': cmd += ' restart'; break;
      case 'stop': cmd += ' stop'; break;
      case 'pull': cmd += ' pull'; break;
    }
    const result = await this.execSSH(cmd);
    return { success: result?.exit_code === 0, output: result?.output || '' };
  }

  // ============================================================
  // System Info (via SSH)
  // ============================================================

  async getSystemInfo(): Promise<DockerSystemInfo | null> {
    let result = await this.execSSH('docker info --format json');
    if (!result || result.exit_code !== 0 || !result.output.trim()) {
      result = await this.execSSH('docker info --format "{{json .}}"');
    }
    if (!result || result.exit_code !== 0) return null;

    try {
      const info = JSON.parse(result.output);
      return {
        serverVersion: info.ServerVersion || '',
        apiVersion: info.ClientInfo?.ApiVersion || '',
        storageDriver: info.Driver || '',
        totalContainers: info.Containers || 0,
        runningContainers: info.ContainersRunning || 0,
        pausedContainers: info.ContainersPaused || 0,
        stoppedContainers: info.ContainersStopped || 0,
        totalImages: info.Images || 0,
        totalMemory: info.MemTotal ? `${Math.round(info.MemTotal / 1073741824)}GB` : '',
        cpus: info.NCPU || 0,
        rootDir: info.DockerRootDir || '',
        runtimeName: info.DefaultRuntime || 'runc'
      };
    } catch { return null; }
  }

  async getDiskUsage(): Promise<DockerDiskUsage | null> {
    let result = await this.execSSH('docker system df --format json');
    if (!result || result.exit_code !== 0 || !result.output.trim()) {
      result = await this.execSSH('docker system df --format "{{json .}}"');
    }
    if (!result || result.exit_code !== 0) return null;

    try {
      const lines = result.output.trim().split('\n').filter(Boolean);
      const usage: DockerDiskUsage = {
        images: { totalCount: 0, totalSize: '0B', reclaimable: '0B' },
        containers: { totalCount: 0, totalSize: '0B', reclaimable: '0B' },
        volumes: { totalCount: 0, totalSize: '0B', reclaimable: '0B' },
        buildCache: { totalSize: '0B', reclaimable: '0B' }
      };
      for (const line of lines) {
        try {
          const item = JSON.parse(line);
          const type = (item.Type || '').toLowerCase();
          const entry = { totalCount: item.TotalCount || 0, totalSize: item.Size || '0B', reclaimable: item.Reclaimable || '0B' };
          if (type.includes('image')) usage.images = entry;
          else if (type.includes('container')) usage.containers = entry;
          else if (type.includes('volume')) usage.volumes = entry;
          else if (type.includes('build')) usage.buildCache = { totalSize: item.Size || '0B', reclaimable: item.Reclaimable || '0B' };
        } catch (e) { console.warn('解析 docker system df 行失败，已跳过该行:', e); }
      }
      return usage;
    } catch (e) { console.warn('获取 docker 磁盘用量失败:', e); return null; }
  }

  async systemPrune(all: boolean = false): Promise<DockerShellResult> {
    const cmd = all ? 'docker system prune -af' : 'docker system prune -f';
    const result = await this.execSSH(cmd);
    return this.shellResult(result);
  }

  // ============================================================
  // Overview Stats
  // ============================================================

  async getOverviewStats(): Promise<DockerOverviewStats> {
    const [containers, images, networks, volumes] = await Promise.all([
      this.listContainers(),
      this.listImages(),
      this.listNetworks(),
      this.listVolumes()
    ]);

    const running = containers.filter(c => c.state === 'running');
    const privileged = containers.filter(c => c.quickChecks?.privileged);
    const unhealthy = containers.filter(c => c.quickChecks?.health === 'unhealthy');

    let totalCpu = 0;
    let totalMem = 0;
    running.forEach(c => {
      totalCpu += c.cpuPercent || 0;
      totalMem += c.memoryPercent || 0;
    });

    return {
      totalContainers: containers.length,
      runningContainers: running.length,
      stoppedContainers: containers.filter(c => c.state === 'exited' || c.state === 'dead').length,
      pausedContainers: containers.filter(c => c.state === 'paused').length,
      totalImages: images.length,
      totalNetworks: networks.length,
      totalVolumes: volumes.length,
      privilegedContainers: privileged.length,
      unhealthyContainers: unhealthy.length,
      totalCpuPercent: Math.round(totalCpu * 10) / 10,
      totalMemoryPercent: Math.round(totalMem * 10) / 10
    };
  }

  // ============================================================
  // Forensic / Emergency
  // ============================================================

  async getContainerProcesses(containerRef: string): Promise<string> {
    const result = await this.execSSH(`docker top ${shq(containerRef)}`);
    return result?.output || '';
  }

  async getContainerDiff(containerRef: string): Promise<string> {
    const result = await this.execSSH(`docker diff ${shq(containerRef)}`);
    return result?.output || '';
  }

  async getContainerEnv(containerRef: string): Promise<string> {
    const result = await this.execSSH(`docker exec ${shq(containerRef)} env 2>/dev/null`);
    return result?.output || '';
  }

  /**
   * 取消容器特权模式：停止容器 → 提取配置 → 删除旧容器 → 用相同配置(去除 --privileged)重建
   */
  async removePrivileged(containerRef: string): Promise<{ success: boolean; output: string }> {
    const inspectResult = await this.execSSH(
      `docker inspect ${shq(containerRef)} --format '{{json .}}'`
    );
    if (!inspectResult || inspectResult.exit_code !== 0) {
      return { success: false, output: '无法获取容器配置' };
    }

    let config: any;
    try { config = JSON.parse(inspectResult.output); } catch {
      return { success: false, output: '解析容器配置失败' };
    }

    // 确认确实是特权容器
    if (!config.HostConfig?.Privileged) {
      return { success: false, output: '该容器并非特权模式' };
    }

    return {
      success: false,
      output: [
        '安全门禁已阻止自动重建。',
        '仅凭 docker inspect 无法无损复原 Compose/编排语义、密钥、设备、健康检查和运行时约束；旧实现会先删除原容器，失败时可能无法恢复。',
        '请从受版本控制的 Compose/Kubernetes 定义移除 privileged，并通过灰度发布与健康检查完成替换。',
      ].join('\n'),
    };
  }

  async disconnectAllNetworks(containerRef: string): Promise<{ success: boolean; output: string }> {
    const networks = await this.execSSH(
      `docker inspect ${shq(containerRef)} --format "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}"`
    );
    if (!networks || !networks.output.trim()) {
      return { success: false, output: 'No networks found' };
    }

    const netNames = networks.output.trim().split(/\s+/).filter(Boolean);
    const results: string[] = [];
    let success = true;
    for (const net of netNames) {
      if (net === 'bridge' || net === 'host' || net === 'none') continue;
      const r = await this.execSSH(`docker network disconnect ${shq(net)} ${shq(containerRef)}`);
      const disconnected = r?.timed_out !== true && r?.exit_code === 0;
      success = success && disconnected;
      results.push(`${net}: ${disconnected ? 'disconnected' : 'failed'}`);
    }
    return { success: results.length > 0 && success, output: results.join('\n') };
  }
}

export const dockerManager = new DockerManager();
