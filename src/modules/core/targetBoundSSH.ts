import { invoke } from '@tauri-apps/api/core';

import { activeTargetContext } from './targetContext';

export type TargetBoundSSHCommand =
  | 'ssh_execute_command_direct'
  | 'ssh_execute_emergency_command_direct'
  | 'ssh_execute_dashboard_command_direct'
  | 'ssh_execute_batch_commands'
  | 'execute_detection_command'
  | 'detect_system_type'
  | 'ssh_probe_capabilities'
  | 'get_network_interfaces'
  | 'start_packet_capture'
  | 'stop_packet_capture'
  | 'capture_pcap_evidence'
  | `sftp_${string}`
  | `docker_${string}`
  | `db_${string}`
  | 'create_container_terminal_window'
  | 'read_system_log'
  | 'read_journalctl_log'
  | 'analyze_multi_log'
  | 'search_ioc_in_logs'
  | 'list_log_files'
  | 'get_log_file_info'
  | `busybox_${string}`
  | 'get_bash_environment_info'
  | 'get_command_completion'
  | 'ssh_get_completion'
  | 'test_ssh_performance'
  | 'diagnose_shell_performance'
  | `detect_${string}`;

type InvokeFn = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
const defaultInvoke: InvokeFn = (command, args) => invoke(command, args);

export async function invokeTargetBoundSSH<T>(
  command: TargetBoundSSHCommand,
  args: Record<string, unknown> = {},
  invokeFn: InvokeFn = defaultInvoke,
): Promise<T> {
  const target = activeTargetContext.get();
  if (!target) {
    throw new Error('没有已确认的活动 SSH 目标，请先连接服务器');
  }

  const result = await invokeFn<T>(command, {
    ...args,
    sessionId: target.sessionId,
  });

  if (!activeTargetContext.matches(target)) {
    throw new Error(
      `命令执行期间活动目标已变化，已丢弃 ${target.username}@${target.host}:${target.port} 的结果`,
    );
  }

  return result;
}
