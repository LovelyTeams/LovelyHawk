import { KubernetesManager, type K8sMutationResult } from './kubernetesManager';
import { invokeTargetBoundSSH } from '../core/targetBoundSSH';
import { activeTargetContext } from '../core/targetContext';
import { operationJournal } from '../core/operationJournal';
import { shq } from '../core/shellEscape';
import {
    K8sEmergencyAction, K8sPodForensicReport,
    K8sAnomalyAlert, K8sPod, K8sEvent,
    EmergencyActionType, K8sForensicTimelineEntry, SecuritySeverity
} from './types';

export class KubernetesEmergencyManager {
    private manager: KubernetesManager;
    private actionHistory: K8sEmergencyAction[] = [];
    private anomalyAlerts: K8sAnomalyAlert[] = [];
    private isolationPolicies: Map<string, string> = new Map(); // podKey -> policyName

    // Thresholds for anomaly detection
    private readonly RESTART_THRESHOLD = 5;
    private readonly KNOWN_REGISTRIES = [
        'docker.io', 'gcr.io', 'ghcr.io', 'quay.io',
        'registry.k8s.io', 'k8s.gcr.io', 'mcr.microsoft.com',
        'public.ecr.aws', 'registry.cn-'
    ];

    private static readonly MAX_ACTION_HISTORY = 100;

    constructor(manager: KubernetesManager) {
        this.manager = manager;
    }

    private recordAction(action: K8sEmergencyAction): void {
        if (action.targetIdentity && action.command) {
            const receipt = operationJournal.record({
                source: 'kubernetes',
                server: action.targetIdentity.host,
                target: action.targetIdentity,
                title: `Kubernetes 应急动作 ${action.type}: ${action.namespace ? `${action.namespace}/` : ''}${action.target}`,
                command: action.command,
                restoreCommand: action.status === 'completed' ? action.rollbackCommand || undefined : undefined,
                output: action.result || action.error || '',
                exitCode: action.exitCode,
                timedOut: action.timedOut,
                verifyCommand: action.verifyCommand,
                verifyOutput: action.verifyOutput,
                verified: action.verified,
                restoreVerifyCommand: action.restoreVerifyCommand,
                restoreVerifyExpected: action.restoreVerifyExpected,
                success: action.status === 'completed',
            });
            action.operationId = receipt.id;
        }
        this.actionHistory.push(action);
        if (this.actionHistory.length > KubernetesEmergencyManager.MAX_ACTION_HISTORY) {
            this.actionHistory.length = KubernetesEmergencyManager.MAX_ACTION_HISTORY;
        }
    }

    private attachResult(action: K8sEmergencyAction, result: K8sMutationResult): void {
        action.command = result.command;
        action.exitCode = result.exitCode;
        action.timedOut = result.timedOut;
        action.verifyCommand = result.verifyCommand;
        action.verifyOutput = result.verifyOutput;
        action.verified = result.verified;
    }

    // ============================================================
    // Pod Isolation
    // ============================================================

    public async isolatePod(podName: string, namespace: string, podLabels: Record<string, string>): Promise<K8sEmergencyAction> {
        const action = this.createAction('isolate', podName, namespace);

        try {
            const policyName = `lovelyres-isolate-${podName}-${Date.now()}`;
            const policyYaml = this.generateIsolationPolicy(policyName, namespace, podLabels);

            const result = await this.manager.applyYaml(policyYaml);
            this.attachResult(action, result);

            if (result.success) {
                const policies = await this.manager.getNetworkPolicies(namespace);
                action.verified = policies.some(policy => policy.name === policyName);
                action.verifyCommand = `kubectl get networkpolicy ${shq(policyName)} -n ${shq(namespace)} -o name`;
                action.verifyOutput = action.verified ? `networkpolicy.networking.k8s.io/${policyName}` : '';
                action.status = action.verified ? 'completed' : 'failed';
                action.result = action.verified ? `NetworkPolicy "${policyName}" applied successfully` : undefined;
                action.error = action.verified ? undefined : '隔离策略应用后未能读回';
                action.rollbackCommand = `kubectl delete networkpolicy ${shq(policyName)} -n ${shq(namespace)}`;
                action.restoreVerifyCommand = `[ -z "$(kubectl get networkpolicy ${shq(policyName)} -n ${shq(namespace)} --ignore-not-found -o name)" ] && echo absent`;
                action.restoreVerifyExpected = 'absent';
                if (action.verified) this.isolationPolicies.set(`${namespace}/${podName}`, policyName);
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

    public async removeIsolation(podName: string, namespace: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('remove_isolation', podName, namespace);
        const key = `${namespace}/${podName}`;
        const policyName = this.isolationPolicies.get(key);

        if (!policyName) {
            action.status = 'failed';
            action.error = `No isolation policy found for ${key}`;
            this.recordAction(action);
            return action;
        }

        try {
            const result = await this.manager.deleteResource('networkpolicy', policyName, namespace);
            this.attachResult(action, result);
            if (result.success) {
                action.status = 'completed';
                action.result = `Isolation policy "${policyName}" removed`;
                this.isolationPolicies.delete(key);
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
    // Emergency Actions
    // ============================================================

    public async scaleToZero(deploymentName: string, namespace: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('scale_zero', deploymentName, namespace);

        try {
            // Get current replicas for rollback
            const deployments = await this.manager.getDeployments(namespace);
            const deploy = deployments.find(d => d.name === deploymentName);
            const currentReplicas = deploy?.replicas ?? 1;

            const result = await this.manager.scaleDeployment(deploymentName, namespace, 0);
            this.attachResult(action, result);
            if (result.success) {
                action.status = 'completed';
                action.result = `Scaled ${deploymentName} to 0 replicas`;
                action.rollbackCommand = `kubectl scale deployment ${shq(deploymentName)} -n ${shq(namespace)} --replicas=${currentReplicas}`;
                action.restoreVerifyCommand = `[ "$(kubectl get deployment ${shq(deploymentName)} -n ${shq(namespace)} -o jsonpath='{.spec.replicas}')" = ${shq(currentReplicas)} ] && echo restored`;
                action.restoreVerifyExpected = 'restored';
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

    public async cordonNode(nodeName: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('cordon', nodeName, '');

        try {
            const result = await this.manager.cordonNode(nodeName);
            this.attachResult(action, result);
            if (result.success) {
                action.status = 'completed';
                action.result = `Node ${nodeName} cordoned`;
                action.rollbackCommand = `kubectl uncordon ${shq(nodeName)}`;
                action.restoreVerifyCommand = `[ "$(kubectl get node ${shq(nodeName)} -o jsonpath='{.spec.unschedulable}')" != true ] && echo restored`;
                action.restoreVerifyExpected = 'restored';
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

    public async drainNode(nodeName: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('drain', nodeName, '');

        try {
            const result = await this.manager.drainNode(nodeName);
            this.attachResult(action, result);
            if (result.success) {
                action.status = 'completed';
                action.result = `Node ${nodeName} drained`;
                action.rollbackCommand = `kubectl uncordon ${shq(nodeName)}`;
                action.restoreVerifyCommand = `[ "$(kubectl get node ${shq(nodeName)} -o jsonpath='{.spec.unschedulable}')" != true ] && echo restored`;
                action.restoreVerifyExpected = 'restored';
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

    public async deletePod(podName: string, namespace: string, force: boolean = false): Promise<K8sEmergencyAction> {
        const action = this.createAction('delete_pod', podName, namespace);

        try {
            const result = await this.manager.deletePod(podName, namespace, force);
            this.attachResult(action, result);

            if (result.success) {
                action.status = 'completed';
                action.result = `Pod ${podName} deleted${force ? ' (force)' : ''}`;
                action.rollbackCommand = ''; // Cannot rollback a pod delete
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
    // Delete ServiceAccount (with associated bindings)
    // ============================================================

    public async deleteServiceAccount(saName: string, namespace: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('delete_sa', saName, namespace);
        const commands: string[] = [];
        const outputs: string[] = [];
        let allSucceeded = true;

        try {
            // First delete any ClusterRoleBindings referencing this SA
            const crbs = await this.manager.getClusterRoleBindings();
            for (const crb of crbs) {
                const hasSubject = crb.subjects.some(
                    s => s.kind === 'ServiceAccount' && s.name === saName && (s.namespace === namespace || !s.namespace)
                );
                if (hasSubject) {
                    const deletion = await this.manager.deleteResource('clusterrolebinding', crb.name);
                    commands.push(deletion.command);
                    outputs.push(deletion.output);
                    allSucceeded = allSucceeded && deletion.success;
                }
            }

            // Delete namespace-scoped RoleBindings referencing this SA
            const rbs = await this.manager.getRoleBindings(namespace);
            for (const rb of rbs) {
                const hasSubject = rb.subjects.some(
                    s => s.kind === 'ServiceAccount' && s.name === saName
                );
                if (hasSubject) {
                    const deletion = await this.manager.deleteResource('rolebinding', rb.name, namespace);
                    commands.push(deletion.command);
                    outputs.push(deletion.output);
                    allSucceeded = allSucceeded && deletion.success;
                }
            }

            // Delete the ServiceAccount itself
            const result = await this.manager.deleteServiceAccount(saName, namespace);
            this.attachResult(action, result);
            commands.push(result.command);
            outputs.push(result.output);
            action.command = commands.join(' ; ');
            action.result = outputs.filter(Boolean).join('\n');
            action.verified = allSucceeded && result.success;
            if (action.verified) {
                action.status = 'completed';
                action.result = `ServiceAccount "${saName}" and associated bindings deleted from namespace "${namespace}"\n${action.result}`.trim();
            } else {
                action.status = 'failed';
                action.error = 'ServiceAccount 或关联绑定存在删除/验证失败，结果为部分完成';
            }
        } catch (e) {
            action.status = 'failed';
            action.error = String(e);
        }

        this.recordAction(action);
        return action;
    }

    // ============================================================
    // Suspend Malicious CronJob
    // ============================================================

    public async suspendCronJob(name: string, namespace: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('suspend_cronjob', name, namespace);

        try {
            const result = await this.manager.suspendCronJob(name, namespace);
            this.attachResult(action, result);
            if (result.success) {
                action.status = 'completed';
                action.result = `CronJob "${name}" suspended in namespace "${namespace}"`;
                action.rollbackCommand = `kubectl patch cronjob ${shq(name)} -n ${shq(namespace)} -p '{"spec":{"suspend":false}}'`;
                action.restoreVerifyCommand = `[ "$(kubectl get cronjob ${shq(name)} -n ${shq(namespace)} -o jsonpath='{.spec.suspend}')" != true ] && echo restored`;
                action.restoreVerifyExpected = 'restored';
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

    public async captureForensicSnapshot(podName: string, namespace: string, container?: string): Promise<K8sPodForensicReport> {
        const report: K8sPodForensicReport = {
            podName,
            namespace,
            timestamp: new Date().toISOString(),
            describe: '',
            logs: '',
            previousLogs: '',
            envVars: {},
            mountedSecrets: [],
            networkPolicies: [],
            processTree: '',
            fileSystemSnapshot: ''
        };

        // Parallel forensic data collection
        const containerArg = container ? container : '';

        const [describe, logs, previousLogs, envResult, processResult, fsResult, networkPolicies] = await Promise.allSettled([
            this.manager.describeResource('pod', podName, namespace),
            this.manager.getPodLogs({ pod: podName, namespace, container: containerArg, tailLines: 500 }),
            this.manager.getPodLogs({ pod: podName, namespace, container: containerArg, tailLines: 200, previous: true }),
            this.manager.execInPod(podName, namespace, containerArg, 'env'),
            this.manager.execInPod(podName, namespace, containerArg, 'ps auxf 2>/dev/null || ps aux'),
            this.manager.execInPod(podName, namespace, containerArg, 'ls -la / 2>/dev/null; cat /proc/self/mountinfo 2>/dev/null'),
            this.manager.getNetworkPolicies(namespace)
        ]);

        if (describe.status === 'fulfilled') report.describe = describe.value;
        if (logs.status === 'fulfilled') report.logs = logs.value;
        if (previousLogs.status === 'fulfilled') report.previousLogs = previousLogs.value;

        if (envResult.status === 'fulfilled' && envResult.value) {
            const envLines = envResult.value.split('\n');
            for (const line of envLines) {
                const eqIdx = line.indexOf('=');
                if (eqIdx > 0) {
                    report.envVars[line.substring(0, eqIdx)] = line.substring(eqIdx + 1);
                }
            }
        }

        if (processResult.status === 'fulfilled') report.processTree = processResult.value;
        if (fsResult.status === 'fulfilled') report.fileSystemSnapshot = fsResult.value;

        if (networkPolicies.status === 'fulfilled') {
            report.networkPolicies = networkPolicies.value.map(np => np.name);
        }

        // Extract mounted secrets from describe output
        if (report.describe) {
            const secretMatches = report.describe.match(/SecretName:\s+(\S+)/g);
            if (secretMatches) {
                report.mountedSecrets = secretMatches.map(m => m.replace('SecretName:', '').trim());
            }
        }

        return report;
    }

    // ============================================================
    // Anomaly Detection
    // ============================================================

    public detectAnomalies(pods: K8sPod[]): K8sAnomalyAlert[] {
        const alerts: K8sAnomalyAlert[] = [];
        let alertId = 0;

        for (const pod of pods) {
            // High restart count
            if (pod.restarts >= this.RESTART_THRESHOLD) {
                alerts.push({
                    id: `anomaly-${++alertId}`,
                    timestamp: new Date().toISOString(),
                    type: 'restart_spike',
                    severity: pod.restarts >= 20 ? 'critical' : pod.restarts >= 10 ? 'high' : 'medium',
                    pod: pod.name,
                    namespace: pod.namespace,
                    details: `Pod has ${pod.restarts} restarts (threshold: ${this.RESTART_THRESHOLD})`,
                    acknowledged: false
                });
            }

            // CrashLoopBackOff
            if (pod.status === 'CrashLoopBackOff') {
                alerts.push({
                    id: `anomaly-${++alertId}`,
                    timestamp: new Date().toISOString(),
                    type: 'crash_loop',
                    severity: 'high',
                    pod: pod.name,
                    namespace: pod.namespace,
                    details: `Pod is in CrashLoopBackOff state`,
                    acknowledged: false
                });
            }

            // Host network
            if (pod.hostNetwork) {
                alerts.push({
                    id: `anomaly-${++alertId}`,
                    timestamp: new Date().toISOString(),
                    type: 'host_network',
                    severity: 'medium',
                    pod: pod.name,
                    namespace: pod.namespace,
                    details: `Pod is using host network`,
                    acknowledged: false
                });
            }

            // Reverse shell detection in pod commands
            for (const container of pod.containers) {
                const fullCmd = [...(container.command || []), ...(container.args || [])].join(' ');
                if (/\/dev\/tcp\//i.test(fullCmd) || /bash\s+-i\s+>&/i.test(fullCmd) ||
                    /nc\s+(-e|--exec)/i.test(fullCmd) || /ncat.*-e\s/i.test(fullCmd)) {
                    alerts.push({
                        id: `anomaly-${++alertId}`,
                        timestamp: new Date().toISOString(),
                        type: 'reverse_shell_pod',
                        severity: 'critical',
                        pod: pod.name,
                        namespace: pod.namespace,
                        details: `Container "${container.name}" has reverse shell command: ${fullCmd.substring(0, 100)}`,
                        acknowledged: false
                    });
                }
            }

            // Unauthorized image registry
            for (const container of pod.containers) {
                const isKnown = this.KNOWN_REGISTRIES.some(reg => container.image.includes(reg)) ||
                    !container.image.includes('/'); // Official images like nginx, redis
                if (!isKnown) {
                    alerts.push({
                        id: `anomaly-${++alertId}`,
                        timestamp: new Date().toISOString(),
                        type: 'unauthorized_image',
                        severity: 'medium',
                        pod: pod.name,
                        namespace: pod.namespace,
                        details: `Container "${container.name}" uses image from unrecognized registry: ${container.image}`,
                        acknowledged: false
                    });
                }
            }
        }

        this.anomalyAlerts = alerts;
        return alerts;
    }

    // ============================================================
    // Event Timeline
    // ============================================================

    public async buildEventTimeline(namespace?: string, limitMinutes: number = 60): Promise<K8sEvent[]> {
        const events = await this.manager.getEvents(namespace);
        const cutoff = new Date(Date.now() - limitMinutes * 60 * 1000);

        return events
            .filter(e => new Date(e.lastTimestamp) >= cutoff)
            .sort((a, b) => new Date(b.lastTimestamp).getTime() - new Date(a.lastTimestamp).getTime());
    }

    // ============================================================
    // Forensic Timeline (全集群取证时间线)
    // ============================================================

    public async buildForensicTimeline(): Promise<K8sForensicTimelineEntry[]> {
        const timeline: K8sForensicTimelineEntry[] = [];

        const [pods, events, crbs, rbs, cronJobs, sas] = await Promise.allSettled([
            this.manager.getPods(),
            this.manager.getEvents(),
            this.manager.getClusterRoleBindings(),
            this.manager.getRoleBindings(),
            this.manager.getCronJobs(),
            this.manager.getServiceAccounts()
        ]);

        // Non-system pods sorted by creation time
        if (pods.status === 'fulfilled') {
            for (const pod of pods.value) {
                if (pod.namespace === 'kube-system') continue;
                const severity: SecuritySeverity = pod.hostNetwork || pod.hostPID ? 'critical' :
                    pod.serviceAccount !== 'default' ? 'medium' : 'info';
                timeline.push({
                    timestamp: pod.creationTimestamp, type: 'pod_created', severity,
                    resource: pod.name, namespace: pod.namespace,
                    details: `Pod created | SA=${pod.serviceAccount} Node=${pod.node} Image=${pod.containers.map(c => c.image).join(',')}`
                });
            }
        }

        // Warning events
        if (events.status === 'fulfilled') {
            for (const event of events.value) {
                if (event.type !== 'Warning') continue;
                timeline.push({
                    timestamp: event.lastTimestamp, type: 'event_warning', severity: 'medium',
                    resource: `${event.involvedObject.kind}/${event.involvedObject.name}`, namespace: event.namespace,
                    details: `${event.reason}: ${event.message?.substring(0, 120)}`
                });
            }
        }

        // RBAC bindings (non-system)
        if (crbs.status === 'fulfilled') {
            for (const crb of crbs.value) {
                if (crb.name.startsWith('system:') || crb.name.startsWith('kubeadm:')) continue;
                const severity: SecuritySeverity = crb.roleRef.name === 'cluster-admin' ? 'critical' : 'medium';
                timeline.push({
                    timestamp: crb.creationTimestamp, type: 'rbac_change', severity,
                    resource: crb.name, namespace: 'cluster',
                    details: `ClusterRoleBinding → ${crb.roleRef.name} | Subjects: ${crb.subjects.map(s => `${s.kind}/${s.name}`).join(', ')}`
                });
            }
        }

        if (rbs.status === 'fulfilled') {
            for (const rb of rbs.value) {
                if (rb.name.startsWith('system:')) continue;
                timeline.push({
                    timestamp: rb.creationTimestamp, type: 'rbac_change', severity: 'low',
                    resource: rb.name, namespace: rb.namespace,
                    details: `RoleBinding → ${rb.roleRef.name} | Subjects: ${rb.subjects.map(s => `${s.kind}/${s.name}`).join(', ')}`
                });
            }
        }

        // CronJobs
        if (cronJobs.status === 'fulfilled') {
            for (const cj of cronJobs.value) {
                timeline.push({
                    timestamp: cj.creationTimestamp, type: 'cronjob_created', severity: 'low',
                    resource: cj.name, namespace: cj.namespace,
                    details: `CronJob schedule=${cj.schedule} suspend=${cj.suspend}`
                });
            }
        }

        // ServiceAccounts (non-default, non-system)
        if (sas.status === 'fulfilled') {
            for (const sa of sas.value) {
                if (sa.name === 'default' || sa.namespace === 'kube-system') continue;
                timeline.push({
                    timestamp: sa.creationTimestamp, type: 'sa_created', severity: 'low',
                    resource: sa.name, namespace: sa.namespace,
                    details: `ServiceAccount created | automount=${sa.automountServiceAccountToken ?? 'default'}`
                });
            }
        }

        // Sort by timestamp descending
        timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
        return timeline;
    }

    // ============================================================
    // Namespace Isolation (一键隔离整个namespace)
    // ============================================================

    public async isolateNamespace(namespace: string): Promise<K8sEmergencyAction> {
        const action = this.createAction('isolate_namespace', namespace, namespace);

        try {
            const result = await this.manager.isolateNamespace(namespace);
            this.attachResult(action, result);
            if (result.success) {
                const policies = await this.manager.getNetworkPolicies(namespace);
                action.verified = policies.some(policy => policy.name === 'lovelyres-deny-all');
                action.verifyCommand = `kubectl get networkpolicy 'lovelyres-deny-all' -n ${shq(namespace)} -o name`;
                action.verifyOutput = action.verified ? 'networkpolicy.networking.k8s.io/lovelyres-deny-all' : '';
                action.status = action.verified ? 'completed' : 'failed';
                action.result = action.verified ? `Namespace "${namespace}" isolated with deny-all NetworkPolicy` : undefined;
                action.error = action.verified ? undefined : '命名空间隔离策略应用后未能读回';
                action.rollbackCommand = `kubectl delete networkpolicy 'lovelyres-deny-all' -n ${shq(namespace)}`;
                action.restoreVerifyCommand = `[ -z "$(kubectl get networkpolicy 'lovelyres-deny-all' -n ${shq(namespace)} --ignore-not-found -o name)" ] && echo absent`;
                action.restoreVerifyExpected = 'absent';
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
    // Batch Pod Delete (批量删除多个Pod)
    // ============================================================

    public async batchDeletePods(pods: { name: string; namespace: string }[], force: boolean = true): Promise<K8sEmergencyAction> {
        const action = this.createAction('batch_delete', `${pods.length} pods`, '');
        const results: string[] = [];
        const commands: string[] = [];
        let failures = 0;

        for (const pod of pods) {
            try {
                const result = await this.manager.deletePod(pod.name, pod.namespace, force);
                commands.push(result.command);
                if (result.success) {
                    results.push(`✓ ${pod.namespace}/${pod.name}`);
                } else {
                    results.push(`✗ ${pod.namespace}/${pod.name}: ${result.output?.substring(0, 80)}`);
                    failures++;
                }
            } catch (e) {
                results.push(`✗ ${pod.namespace}/${pod.name}: ${String(e).substring(0, 80)}`);
                failures++;
            }
        }

        action.status = failures === 0 ? 'completed' : 'failed';
        action.result = results.join('\n');
        action.command = commands.join(' ; ');
        action.verified = failures === 0;
        action.verifyOutput = `${pods.length - failures}/${pods.length} deleted and absent`;
        if (failures > 0) action.error = `${failures}/${pods.length} failed`;

        this.recordAction(action);
        return action;
    }

    // ============================================================
    // Helpers
    // ============================================================

    public generateIsolationPolicy(policyName: string, namespace: string, podLabels: Record<string, string>): string {
        const matchLabels = Object.entries(podLabels)
            .map(([k, v]) => `        ${JSON.stringify(k)}: ${JSON.stringify(v)}`)
            .join('\n');

        return `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ${JSON.stringify(policyName)}
  namespace: ${JSON.stringify(namespace)}
  labels:
    lovelyres-emergency: "true"
    lovelyres-action: "isolate"
spec:
  podSelector:
    matchLabels:
${matchLabels}
  policyTypes:
  - Ingress
  - Egress`;
    }

    public getActionHistory(): K8sEmergencyAction[] {
        return [...this.actionHistory];
    }

    /** Kubernetes 运行态只属于当前 SSH 会话；切换目标后由页面管理器调用。 */
    public resetTargetState(): void {
        this.actionHistory = [];
        this.anomalyAlerts = [];
        this.isolationPolicies.clear();
    }

    public getAnomalyAlerts(): K8sAnomalyAlert[] {
        return [...this.anomalyAlerts];
    }

    public getIsolatedPods(): { pod: string; policy: string }[] {
        return Array.from(this.isolationPolicies.entries()).map(([pod, policy]) => ({ pod, policy }));
    }

    public acknowledgeAlert(alertId: string): void {
        const alert = this.anomalyAlerts.find(a => a.id === alertId);
        if (alert) alert.acknowledged = true;
    }

    public async executeRollback(actionId: string): Promise<{ success: boolean; output: string }> {
        const action = this.actionHistory.find(a => a.id === actionId);
        if (!action || !action.rollbackCommand) {
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

    private createAction(type: EmergencyActionType, target: string, namespace: string): K8sEmergencyAction {
        return {
            id: `action-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`,
            type,
            target,
            namespace,
            status: 'executing',
            timestamp: new Date().toISOString(),
            performedBy: 'LovelyRes',
            rollbackCommand: '',
            targetIdentity: activeTargetContext.get() || undefined,
        };
    }
}
