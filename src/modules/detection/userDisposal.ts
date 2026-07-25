/**
 * 用户 / 口令一键处置
 *
 * 从检测结果的用户类 Finding 直接调起，对指定账号做处置：锁定 / 解锁 / 删除 /
 * 改口令 / 清理未授权 authorized_keys。每个动作走 showConfirm 确认、shq 转义、
 * 并写入 operationJournal（带 restoreCommand，可在快照回滚中心撤销）。
 *
 * 自锁保护：处置目标为当前登录用户时显式警告。
 */

import { invoke } from '@tauri-apps/api/core';
import { operationJournal } from '../core/operationJournal';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { showConfirm } from '../ui/confirmDialog';
import { shq, isValidUsername } from '../core/shellEscape';

const KEY_BACKUP_DIR = '/tmp/.lovelyres_user';

class UserDisposal {
  private modal: HTMLElement | null = null;

  private server(): string {
    return sshConnectionManager.getConnectionStatus()?.host || '';
  }

  private currentUser(): string {
    return sshConnectionManager.getConnectionStatus()?.username || '';
  }

  private async exec(cmd: string): Promise<string> {
    const r = await invoke('ssh_execute_command_direct', { command: cmd }) as any;
    return r?.output || '';
  }

  /** 从 Finding 文本中提取候选用户名（用于预填） */
  extractUser(text: string): string {
    const m = /账号[:：]?\s*([a-z_][a-z0-9_-]{0,31})/i.exec(text) || /\b([a-z_][a-z0-9_-]{0,31})\b/i.exec(text);
    return m ? m[1] : '';
  }

  /** 从一段文本（Finding 标题/描述）中提取用户名并打开处置面板 */
  openFromText(text: string): void {
    this.open(this.extractUser(String(text || '')));
  }

  /** 打开处置面板，可预填用户名 */
  open(prefillUser = ''): void {
    this.close();
    const modal = document.createElement('div');
    modal.id = 'user-disposal-modal';
    modal.className = 'modal-overlay';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:center;justify-content:center;z-index:10050;';
    modal.innerHTML = `
      <div class="ud-box" style="background:var(--bg-primary);border:1px solid var(--border-color);border-radius:10px;width:460px;max-width:92vw;padding:0;overflow:hidden;">
        <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 16px;border-bottom:1px solid var(--border-color);">
          <h3 style="margin:0;font-size:15px;color:var(--text-primary);">账号处置</h3>
          <button class="ud-x" style="background:none;border:none;color:var(--text-secondary);font-size:18px;cursor:pointer;">✕</button>
        </div>
        <div style="padding:16px;">
          <label style="display:block;color:var(--text-secondary);font-size:12px;margin-bottom:6px;">目标用户名</label>
          <input id="ud-user" value="${this.esc(prefillUser)}" placeholder="如 test / hacker"
            style="width:100%;box-sizing:border-box;background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:8px 10px;border-radius:6px;font-size:13px;margin-bottom:12px;" />

          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;">
            <button class="ud-btn" data-ud="lock">锁定账号</button>
            <button class="ud-btn" data-ud="unlock">解锁账号</button>
            <button class="ud-btn" data-ud="clean-keys">清理 authorized_keys</button>
            <button class="ud-btn danger" data-ud="delete">删除账号</button>
          </div>

          <label style="display:block;color:var(--text-secondary);font-size:12px;margin-bottom:6px;">设置新口令（改弱口令用）</label>
          <div style="display:flex;gap:8px;">
            <input id="ud-pass" type="text" placeholder="新口令"
              style="flex:1;box-sizing:border-box;background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:8px 10px;border-radius:6px;font-size:13px;" />
            <button class="ud-btn primary" data-ud="passwd">改口令</button>
          </div>
          <div style="color:var(--text-secondary);font-size:11px;margin-top:12px;line-height:1.5;">
            处置动作会记入"快照与回滚中心"，除删除账号外均可一键回滚。
          </div>
        </div>
      </div>`;
    document.body.appendChild(modal);
    this.modal = modal;

    modal.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      if (target === modal || target.classList.contains('ud-x')) { this.close(); return; }
      const btn = target.closest('[data-ud]') as HTMLElement;
      if (!btn) return;
      const act = btn.getAttribute('data-ud') || '';
      const user = (document.getElementById('ud-user') as HTMLInputElement)?.value.trim() || '';
      const pass = (document.getElementById('ud-pass') as HTMLInputElement)?.value || '';
      this.dispatch(act, user, pass);
    });

    this.injectStyles();
  }

  close(): void {
    this.modal?.remove();
    this.modal = null;
  }

  private async dispatch(act: string, user: string, pass: string): Promise<void> {
    if (!isValidUsername(user)) { window.showNotification?.('请输入合法的用户名', 'error'); return; }
    switch (act) {
      case 'lock': return this.lock(user);
      case 'unlock': return this.unlock(user);
      case 'delete': return this.remove(user);
      case 'passwd': return this.setPassword(user, pass);
      case 'clean-keys': return this.cleanKeys(user);
    }
  }

  private selfWarn(user: string): string {
    return user === this.currentUser()
      ? `\n\n该账号是你当前登录使用的用户（${user}），处置后可能立即断开或无法再登录！`
      : '';
  }

  private async record(title: string, command: string, restoreCommand: string | undefined, run: () => Promise<string>): Promise<void> {
    let output = ''; let success = true;
    try { output = await run(); } catch (e) { success = false; output = String(e); }
    operationJournal.record({
      source: 'user', server: this.server(), title, command, restoreCommand, output, success,
    });
    window.showNotification?.(success ? `${title} 完成` : `${title} 失败: ${output}`, success ? 'success' : 'error');
  }

  private async lock(user: string): Promise<void> {
    const ok = await showConfirm({
      title: '锁定账号', message: `将锁定账号 ${user}（usermod -L，禁止其登录）。${this.selfWarn(user)}`,
      confirmText: '锁定', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    // busybox/Alpine 默认无 usermod / passwd -S，回退到 busybox 自带的 passwd -l/-u
    const cmd = `usermod -L ${shq(user)} 2>/dev/null || passwd -l ${shq(user)}; passwd -S ${shq(user)} 2>/dev/null || grep ${shq('^' + user + ':')} /etc/shadow`;
    const restore = `usermod -U ${shq(user)} 2>/dev/null || passwd -u ${shq(user)}`;
    await this.record(`锁定账号 ${user}`, cmd, restore, () => this.exec(cmd));
  }

  private async unlock(user: string): Promise<void> {
    const cmd = `usermod -U ${shq(user)} 2>/dev/null || passwd -u ${shq(user)}; passwd -S ${shq(user)} 2>/dev/null || grep ${shq('^' + user + ':')} /etc/shadow`;
    const restore = `usermod -L ${shq(user)} 2>/dev/null || passwd -l ${shq(user)}`;
    await this.record(`解锁账号 ${user}`, cmd, restore, () => this.exec(cmd));
  }

  private async remove(user: string): Promise<void> {
    const ok = await showConfirm({
      title: '删除账号（不可完美回滚）',
      message: `将删除账号 ${user} 及其家目录（userdel -r）。此操作无法自动还原，建议先在"快照回滚中心"创建开赛快照。${this.selfWarn(user)}`,
      confirmText: '删除', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    // Alpine/busybox 用 deluser --remove-home；shadow-utils 用 userdel -r
    const cmd = `userdel -r ${shq(user)} 2>/dev/null || deluser --remove-home ${shq(user)} 2>&1; echo "done"`;
    await this.record(`删除账号 ${user}`, cmd, undefined, () => this.exec(cmd));
  }

  private async setPassword(user: string, pass: string): Promise<void> {
    if (!pass) { window.showNotification?.('请输入新口令', 'error'); return; }
    const ok = await showConfirm({
      title: '修改口令',
      message: `将修改账号 ${user} 的口令。${this.selfWarn(user)}`,
      confirmText: '修改', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    // 先备份原口令 hash 以便回滚，再改
    // getent 在 busybox/Alpine 可能缺失，回退直接读 /etc/shadow
    const hashFile = shq(`${KEY_BACKUP_DIR}/${user}.hash`);
    const backup = `mkdir -p ${shq(KEY_BACKUP_DIR)} && { getent shadow ${shq(user)} 2>/dev/null || grep ${shq('^' + user + ':')} /etc/shadow; } | cut -d: -f2 > ${hashFile}`;
    const change = `echo ${shq(`${user}:${pass}`)} | chpasswd`;
    // usermod -p 在 Alpine 缺失，回退 chpasswd -e（busybox 与 shadow 均支持已加密 hash）
    const restore = `[ -s ${hashFile} ] && { usermod -p "$(cat ${hashFile})" ${shq(user)} 2>/dev/null || echo "${user}:$(cat ${hashFile})" | chpasswd -e; }`;
    const cmd = `${backup}; ${change} && echo "password changed"`;
    await this.record(`修改账号 ${user} 口令`, change, restore, () => this.exec(cmd));
  }

  private async cleanKeys(user: string): Promise<void> {
    const ok = await showConfirm({
      title: '清理 authorized_keys',
      message: `将备份并清空账号 ${user} 的 ~/.ssh/authorized_keys（移除所有已授权公钥）。可从快照回滚中心还原。`,
      confirmText: '清空', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;
    const home = user === 'root' ? '/root' : `/home/${user}`;
    const akeys = `${home}/.ssh/authorized_keys`;
    const bak = `${KEY_BACKUP_DIR}/${user}.authorized_keys.bak`;
    const cmd = `mkdir -p ${shq(KEY_BACKUP_DIR)}; [ -f ${shq(akeys)} ] && cp -a ${shq(akeys)} ${shq(bak)}; : > ${shq(akeys)} 2>/dev/null; echo "cleared ${akeys}"`;
    const restore = `[ -f ${shq(bak)} ] && cp -a ${shq(bak)} ${shq(akeys)}`;
    await this.record(`清理 ${user} authorized_keys`, cmd, restore, () => this.exec(cmd));
  }

  private esc(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  private injectStyles(): void {
    if (document.getElementById('ud-styles')) return;
    const style = document.createElement('style');
    style.id = 'ud-styles';
    style.textContent = `
      #user-disposal-modal .ud-btn{background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:8px 10px;border-radius:6px;cursor:pointer;font-size:12px;}
      #user-disposal-modal .ud-btn:hover{border-color:var(--primary-color);}
      #user-disposal-modal .ud-btn.primary{background:var(--primary-color);color:#fff;border-color:var(--primary-color);}
      #user-disposal-modal .ud-btn.danger{color:#ef4444;border-color:rgba(239,68,68,.4);}
      #user-disposal-modal .ud-btn.danger:hover{background:rgba(239,68,68,.1);}
    `;
    document.head.appendChild(style);
  }
}

export const userDisposal = new UserDisposal();
