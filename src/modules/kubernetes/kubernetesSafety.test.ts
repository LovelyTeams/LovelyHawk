import { describe, expect, it } from 'vitest';

import { KubernetesEmergencyManager } from './kubernetesEmergencyManager';
import { KubernetesManager } from './kubernetesManager';

describe('Kubernetes emergency safety boundaries', () => {
  it('quotes attacker-controlled YAML names, keys, and values', () => {
    const emergency = new KubernetesEmergencyManager(new KubernetesManager());
    const yaml = emergency.generateIsolationPolicy(
      'policy\n  namespace: kube-system',
      'contest\nkind: Secret',
      { 'role\n    injected': 'web"\n  privileged: true' },
    );

    expect(yaml).toContain('name: "policy\\n  namespace: kube-system"');
    expect(yaml).toContain('namespace: "contest\\nkind: Secret"');
    expect(yaml).toContain('"role\\n    injected": "web\\\"\\n  privileged: true"');
    expect(yaml).not.toContain('\nkind: Secret\n');
  });

  it('blocks the legacy etcd namespace-prefix deletion path', async () => {
    const manager = new KubernetesManager();
    await expect(manager.etcdDeletePod('one-pod', 'default')).resolves.toMatchObject({
      success: false,
    });
  });
});
