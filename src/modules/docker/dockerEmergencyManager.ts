import { DockerManager } from './dockerManager';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';
import { shq } from '../core/shellEscape';
import { activeTargetContext } from '../core/targetContext';
import { operationJournal } from '../core/operationJournal';
import { isDockerActionVerified } from './dockerOperationContract';
import { showConfirm } from '../ui/confirmDialog';
import type {
    DockerEmergencyAction,
    DockerForensicReport,
    DockerEmergencyActionType,
    DockerContainerSummary
} from './types';

const MAX_ACTION_HISTORY = 100;

export class DockerEmergencyManager {
    private manager: DockerManager;
    private actionHistory: DockerEmergencyAction[] = [];

    constructor(manager: DockerManager) {
        this.manager = manager;
    }

    private recordAction(action: DockerEmergencyAction): void {
        if (action.targetIdentity && action.error !== 'cancelled') {
            const dockerAction: Partial<Record<DockerEmergencyActionType, string>> = {
                stop: 'stop',
                kill: 'kill',
                pause: 'pause',
                remove: 'rm -f',
            };
            const operation = dockerAction[action.type];
            const command = operation
                ? `docker ${operation.split(' ').map(shq).join(' ')} ${shq(action.target)}`
                : `docker emergency ${action.type} ${shq(action.target)}`;
            const receipt = operationJournal.record({
                source: 'docker',
                server: action.targetIdentity.host,
                target: action.targetIdentity,
                title: `Docker 应急动作 ${action.type}: ${action.target}`,
                command,
                restoreCommand: action.status === 'completed' ? action.rollbackCommand || undefined : undefined,
                output: action.result || action.error || '',
                exitCode: action.exitCode,
                timedOut: action.timedOut,
                verifyOutput: action.verifyOutput,
                verified: action.verified,
                success: action.status === 'completed',
            });
            action.operationId = receipt.id;
        }
        this.actionHistory.push(action);
        if (this.actionHistory.length > MAX_ACTION_HISTORY) {
            this.actionHistory.length = MAX_ACTION_HISTORY;
        }
    }

    private async confirmAction(action: DockerEmergencyAction, label: string, detail: string): Promise<boolean> {
        const target = action.targetIdentity;
        if (!target) {
            action.status = 'failed';
            action.error = '没有已确认的活动 SSH 目标';
            return false;
        }
        const confirmed = await showConfirm({
            title: label,
            message: `目标：${target.username}@${target.host}:${target.port}\n指纹：${target.hostKeyFingerprint}\n容器：${action.target}\n\n${detail}`,
            dangerous: true,
            defaultFocus: 'cancel',
        });
        if (!confirmed) {
            action.status = 'failed';
            action.error = 'cancelled';
            return false;
        }
        if (!activeTargetContext.matches(target)) {
            action.status = 'failed';
            action.error = '确认后活动目标已变化';
            return false;
        }
        return true;
    }

    // ============================================================
    // Emergency Actions
    // ============================================================

    public async emergencyStop(containerRef: string): Promise<DockerEmergencyAction> {
        const action = this.createAction('stop', containerRef);
        if (!(await this.confirmAction(action, '应急停止容器', '停止会中断该容器提供的服务。'))) {
            this.recordAction(action);
            return action;
        }
        try {
            const result = await this.manager.performAction(containerRef, 'stop');
            const verified = result.success && isDockerActionVerified('stop', result.updatedState || result.updatedStatus);
            action.verified = verified;
            action.verifyOutput = result.updatedState || result.updatedStatus || 'unknown';
            action.exitCode = result.success ? 0 : null;
            if (verified) {
                action.status = 'completed';
                action.result = `Container ${containerRef} stopped`;
                action.rollbackCommand = `docker start ${shq(containerRef)}`;
            } else {
                action.status = 'failed';
                action.error = result.message;
            }
        } catch (e) {
            action.status = 'failed';
            action.error = String(e);
        }
        this.recordAction(action);
        return action;
    }

    public async emergencyKill(containerRef: string): Promise<DockerEmergencyAction> {
        const action = this.createAction('kill', containerRef);
        if (!(await this.confirmAction(action, '应急强制杀死容器', '强制杀死可能造成未落盘数据丢失，且无法自动回滚进程状态。'))) {
            this.recordAction(action);
            return action;
        }
        try {
            const result = await this.manager.performAction(containerRef, 'kill');
            const verified = result.success && isDockerActionVerified('kill', result.updatedState || result.updatedStatus);
            action.verified = verified;
            action.verifyOutput = result.updatedState || result.updatedStatus || 'unknown';
            action.exitCode = result.success ? 0 : null;
            if (verified) {
                action.status = 'completed';
                action.result = `Container ${containerRef} killed`;
                action.rollbackCommand = '';
            } else {
                action.status = 'failed';
                action.error = result.message;
            }
        } catch (e) {
            action.status = 'failed';
            action.error = String(e);
        }
        this.recordAction(action);
        return action;
    }

    public async emergencyPause(containerRef: string): Promise<DockerEmergencyAction> {
        const action = this.createAction('pause', containerRef);
        if (!(await this.confirmAction(action, '应急暂停容器', '暂停会立即冻结容器内全部进程。'))) {
            this.recordAction(action);
            return action;
        }
        try {
            const result = await this.manager.performAction(containerRef, 'pause');
            const verified = result.success && isDockerActionVerified('pause', result.updatedState || result.updatedStatus);
            action.verified = verified;
            action.verifyOutput = result.updatedState || result.updatedStatus || 'unknown';
            action.exitCode = result.success ? 0 : null;
            if (verified) {
                action.status = 'completed';
                action.result = `Container ${containerRef} paused`;
                action.rollbackCommand = `docker unpause ${shq(containerRef)}`;
            } else {
                action.status = 'failed';
                action.error = result.message;
            }
        } catch (e) {
            action.status = 'failed';
            action.error = String(e);
        }
        this.recordAction(action);
        return action;
    }

    public async emergencyDisconnectNetwork(containerRef: string): Promise<DockerEmergencyAction> {
        const action = this.createAction('disconnect_network', containerRef);
        if (!(await this.confirmAction(action, '应急断开容器网络', '将断开所有非默认网络；网络别名与连接参数无法自动恢复。'))) {
            this.recordAction(action);
            return action;
        }
        try {
            const result = await this.manager.disconnectAllNetworks(containerRef);
            if (result.success) {
                action.status = 'completed';
                action.result = `Network disconnected:\n${result.output}`;
                action.rollbackCommand = '';
            } else {
                action.status = 'failed';
                action.error = result.output;
            }
        } catch (e) {
            action.status = 'failed';
            action.error = String(e);
        }
        this.recordAction(action);
        return action;
    }

    public async emergencyRemove(containerRef: string, force: boolean = true): Promise<DockerEmergencyAction> {
        const action = this.createAction('remove', containerRef);
        if (!(await this.confirmAction(action, '应急删除容器', '容器可写层将被永久删除，此操作不可恢复。'))) {
            this.recordAction(action);
            return action;
        }
        try {
            const cmd = force ? `docker rm -f ${shq(containerRef)}` : `docker rm ${shq(containerRef)}`;
            const result: any = await invokeTargetBoundSSH('ssh_execute_dashboard_command_direct', { command: cmd });
            action.exitCode = result.exit_code ?? null;
            action.timedOut = result.timed_out === true;
            if (!action.timedOut && result.exit_code === 0) {
                action.status = 'completed';
                action.result = `Container ${containerRef} removed`;
                action.rollbackCommand = '';
            } else {
                action.status = 'failed';
                action.error = result.output;
            }
        } catch (e) {
            action.status = 'failed';
            action.error = String(e);
        }
        this.recordAction(action);
        return action;
    }

    // ============================================================
    // Forensic Capture
    // ============================================================

    public async captureForensicSnapshot(containerRef: string, containerName: string): Promise<DockerForensicReport> {
        const report: DockerForensicReport = {
            containerName,
            containerId: containerRef,
            timestamp: new Date().toISOString(),
            inspect: '',
            logs: '',
            processes: '',
            diff: '',
            envVars: '',
            networkSettings: '',
            mounts: ''
        };

        const [inspect, logs, processes, diff, envVars] = await Promise.allSettled([
            this.manager.inspect(containerRef).then(r => JSON.stringify(r, null, 2)),
            this.manager.getLogs(containerRef, { tail: 500 }),
            this.manager.getContainerProcesses(containerRef),
            this.manager.getContainerDiff(containerRef),
            this.manager.getContainerEnv(containerRef)
        ]);

        if (inspect.status === 'fulfilled') report.inspect = inspect.value ?? '';
        else console.warn('Forensic: inspect failed:', inspect.reason);
        if (logs.status === 'fulfilled') report.logs = logs.value ?? '';
        else console.warn('Forensic: logs failed:', logs.reason);
        if (processes.status === 'fulfilled') report.processes = processes.value ?? '';
        else console.warn('Forensic: processes failed:', processes.reason);
        if (diff.status === 'fulfilled') report.diff = diff.value ?? '';
        else console.warn('Forensic: diff failed:', diff.reason);
        if (envVars.status === 'fulfilled') report.envVars = envVars.value ?? '';
        else console.warn('Forensic: envVars failed:', envVars.reason);

        // Extract network settings and mounts from inspect
        if (report.inspect) {
            try {
                const inspectData = JSON.parse(report.inspect);
                report.networkSettings = JSON.stringify(inspectData.NetworkSettings, null, 2) || '';
                report.mounts = JSON.stringify(inspectData.Mounts, null, 2) || '';
            } catch (e) { console.warn('解析容器 inspect 失败，networkSettings/mounts 将为空:', e); }
        }

        return report;
    }

    // ============================================================
    // Anomaly Detection
    // ============================================================

    public detectAnomalies(containers: DockerContainerSummary[]): string[] {
        const warnings: string[] = [];

        for (const c of containers) {
            // Privileged containers
            if (c.quickChecks?.privileged) {
                warnings.push(`[CRITICAL] Container "${c.name}" runs in privileged mode`);
            }

            // Unhealthy containers
            if (c.quickChecks?.health === 'unhealthy') {
                warnings.push(`[HIGH] Container "${c.name}" is unhealthy`);
            }

            // Docker socket mounted
            for (const mount of c.mounts) {
                if (mount.source?.includes('docker.sock')) {
                    warnings.push(`[CRITICAL] Container "${c.name}" has Docker socket mounted`);
                }
            }

            // Host network
            if (c.networkMode === 'host') {
                warnings.push(`[HIGH] Container "${c.name}" uses host network mode`);
            }

            // High CPU
            if ((c.cpuPercent || 0) > 90) {
                warnings.push(`[MEDIUM] Container "${c.name}" CPU usage: ${c.cpuPercent}%`);
            }

            // High memory
            if ((c.memoryPercent || 0) > 90) {
                warnings.push(`[MEDIUM] Container "${c.name}" memory usage: ${c.memoryPercent}%`);
            }
        }

        return warnings;
    }

    // ============================================================
    // History & Rollback
    // ============================================================

    public getActionHistory(): DockerEmergencyAction[] {
        return [...this.actionHistory];
    }

    public async executeRollback(actionId: string): Promise<{ success: boolean; output: string }> {
        const action = this.actionHistory.find(a => a.id === actionId);
        if (!action?.rollbackCommand) {
            return { success: false, output: 'No rollback command available' };
        }
        if (!action.targetIdentity || !activeTargetContext.matches(action.targetIdentity)) {
            return { success: false, output: '当前目标与应急动作目标不一致，已阻止回滚' };
        }
        try {
            const result: any = await invokeTargetBoundSSH('ssh_execute_dashboard_command_direct', {
                command: action.rollbackCommand
            });
            const success = result.timed_out !== true && result.exit_code === 0;
            if (success && action.operationId) operationJournal.markRolledBack(action.operationId);
            return { success, output: result.output || '' };
        } catch (e) {
            return { success: false, output: String(e) };
        }
    }

    private createAction(type: DockerEmergencyActionType, target: string): DockerEmergencyAction {
        return {
            id: `docker-action-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
            type, target,
            status: 'executing',
            timestamp: new Date().toISOString(),
            rollbackCommand: '',
            targetIdentity: activeTargetContext.get() || undefined,
        };
    }
}
