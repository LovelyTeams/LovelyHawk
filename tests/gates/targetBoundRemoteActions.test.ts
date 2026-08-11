import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

function sourceFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return sourceFiles(path);
    return /\.(?:ts|vue)$/.test(entry.name) ? [path] : [];
  });
}

const targetSensitiveCommands = [
  'get_network_interfaces',
  'start_packet_capture',
  'stop_packet_capture',
  'sftp_list_files',
  'sftp_read_file',
  'sftp_write_file',
  'sftp_chmod',
  'sftp_get_file_details',
  'sftp_compress',
  'sftp_extract',
  'sftp_upload',
  'sftp_download',
  'sftp_create_directory',
  'sftp_rename',
  'sftp_delete',
  'db_detect',
  'db_execute_sql',
  'db_list_databases',
  'db_list_tables',
  'db_list_columns',
  'db_list_users',
  'db_service_control',
  'db_backup',
  'db_get_stats',
  'docker_list_containers',
  'docker_container_action',
  'docker_container_logs',
  'docker_inspect_container',
  'docker_read_container_file',
  'docker_write_container_file',
  'docker_copy',
  'docker_exec_command',
  'create_container_terminal_window',
  'read_system_log',
  'read_journalctl_log',
  'analyze_multi_log',
  'search_ioc_in_logs',
  'list_log_files',
  'get_log_file_info',
  'busybox_detect',
  'busybox_install',
  'busybox_enable',
  'busybox_disable',
  'busybox_status',
  'get_bash_environment_info',
  'get_command_completion',
  'ssh_get_completion',
  'test_ssh_performance',
  'diagnose_shell_performance',
  'ssh_create_terminal_session',
];

describe('target-bound remote action gate', () => {
  it('does not invoke SFTP or packet capture against an implicit current session', () => {
    const commandPattern = targetSensitiveCommands.join('|');
    const directInvoke = new RegExp(
      String.raw`(?:\binvoke|\.invoke)(?:<[^>]+>)?\s*\(\s*['"](?:${commandPattern})['"]`,
    );
    const violations = sourceFiles('src').flatMap(file => {
      const normalized = file.replace(/\\/g, '/');
      if (normalized === 'src/container-terminal.ts' || normalized === 'src/components/SSHTerminal.vue') return [];
      const source = readFileSync(file, 'utf8');
      return directInvoke.test(source) ? [file] : [];
    });

    expect(violations, `仍依赖隐式当前会话的远端入口: ${violations.join(', ')}`).toEqual([]);
  });

  it('pins the standalone container terminal to its injected session', () => {
    const source = readFileSync('src/container-terminal.ts', 'utf8');
    expect(source).toContain('sessionId: this.containerInfo.sessionId');
  });

  it('pins each SSH terminal tab to the session captured during creation', () => {
    const source = readFileSync('src/components/SSHTerminal.vue', 'utf8');
    expect(source).toContain('sessionId: terminalInstance.connectionInfo.sessionId');
  });
});
