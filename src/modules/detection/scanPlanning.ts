export type DetectionOutcome = 'passed' | 'failed' | 'not-applicable' | 'error';
export type ScanMode = 'selected' | 'competition-triage';

export interface ScanEnvironment {
  kubernetes: boolean;
  webRoot: boolean;
  containerRuntime: boolean;
  checkedAt: number;
}

export interface ScanCompleteness {
  planned: number;
  completed: number;
  failed: number;
  notApplicable: number;
  processedPercent: number;
}

export interface ScorableDetectionItem {
  status: 'pending' | 'running' | 'completed' | 'failed' | 'not-applicable';
  result?: {
    passed: boolean;
    score: number;
    outcome?: DetectionOutcome;
    findings: Array<{ severity: string; title?: string }>;
  };
}

export const KUBERNETES_CHECK_IDS = new Set([
  'k8s-privileged-pod', 'k8s-reverse-shell', 'k8s-rbac-audit',
  'k8s-container-escape', 'k8s-suspicious-cronjob', 'k8s-network-policy',
  'k8s-sa-audit', 'k8s-node-persistence',
]);

export const COMPETITION_TRIAGE_IDS = [
  'network-backdoor',
  'enhanced-process',
  'user-audit',
  'persistence-scan',
  'hidden-cron',
  'ssh-key-audit',
  'webshell-scan',
  'port-scan',
] as const;

export function notApplicableReason(itemId: string, environment: ScanEnvironment): string | null {
  if (KUBERNETES_CHECK_IDS.has(itemId) && !environment.kubernetes) {
    return '目标未检测到可用的 Kubernetes 上下文';
  }
  if (itemId === 'webshell-scan' && !environment.webRoot) {
    return '目标未检测到常见 Web 根目录';
  }
  return null;
}

export function normalizeOutcome(item: ScorableDetectionItem): DetectionOutcome {
  if (item.status === 'not-applicable') return 'not-applicable';
  if (item.status === 'failed' || !item.result) return 'error';
  if (item.result.outcome) return item.result.outcome;
  if (item.result.findings.some(finding => finding.title === '检测失败')) return 'error';
  return item.result.passed ? 'passed' : 'failed';
}

export function calculateTrustedScore(items: ScorableDetectionItem[]): number {
  const scored = items.filter(item => {
    const outcome = normalizeOutcome(item);
    return outcome === 'passed' || outcome === 'failed';
  });
  if (scored.length === 0) return 0;

  let score = Math.round(
    scored.reduce((sum, item) => sum + (item.result?.score || 0), 0) / scored.length,
  );
  if (
    scored.some(item => item.result?.findings.some(finding => finding.severity === 'critical'))
    && score > 60
  ) {
    score = 60;
  }
  return score;
}

export function calculateCompleteness(
  planned: number,
  items: ScorableDetectionItem[],
): ScanCompleteness {
  let completed = 0;
  let failed = 0;
  let notApplicable = 0;
  for (const item of items) {
    const outcome = normalizeOutcome(item);
    if (outcome === 'passed' || outcome === 'failed') completed += 1;
    else if (outcome === 'error') failed += 1;
    else notApplicable += 1;
  }
  const processed = completed + failed + notApplicable;
  return {
    planned,
    completed,
    failed,
    notApplicable,
    processedPercent: planned > 0 ? Math.round((processed / planned) * 100) : 0,
  };
}
