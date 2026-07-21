/**
 * 防火墙规则管理（带防自锁）
 *
 * 能力：
 *  - 探测靶机可用的防火墙后端（iptables / nftables / ufw / firewalld）
 *  - 查看当前规则
 *  - 常用处置：封禁 IP、放行端口、设置默认拒绝策略
 *  - 每次改动前自动 iptables-save 备份，restoreCommand 写入 operationJournal 可一键回滚
 *
 * 防自锁（核心）：
 *  1. 任何"默认拒绝 / 封端口"类危险规则，应用前自动插入放行当前 SSH 来源与端口的豁免规则；
 *  2. 危险规则应用时在靶机后台起"死人开关"：N 秒后自动 iptables-restore 还原；
 *     前端弹确认框，用户点"保留"则 kill 掉该定时任务，否则到点自动回滚。
 *
 * 离线约束：所有 IP / 端口拼入命令前经 shq 转义并做格式校验；破坏性规则需先在 VM 实测。
 */

import { invoke } from '@tauri-apps/api/core';
import { operationJournal } from '../core/operationJournal';
import { sshConnectionManager } from '../remote/sshConnectionManager';
import { showConfirm } from '../ui/confirmDialog';
import { shq, isValidIpOrCidr, isValidPort } from '../core/shellEscape';

type FwBackend = 'iptables' | 'nftables' | 'ufw' | 'firewalld' | 'unknown';

const FW_BACKUP_DIR = '/tmp/.lovelyres_fw';
const DEADMAN_SECONDS = 60;

class FirewallManager {
  private backend: FwBackend = 'unknown';
  private eventsBound = false;
  private currentRules = '';
  private loading = false;

  initialize(): void {
    if (!this.eventsBound) { this.bindEvents(); this.eventsBound = true; }
    this.render();
    if (sshConnectionManager.isConnected()) {
      this.detectAndLoad();
    }
  }

  private server(): string {
    return sshConnectionManager.getConnectionStatus()?.host || '';
  }

  private sshPort(): number {
    return sshConnectionManager.getConnectionStatus()?.port || 22;
  }

  private async exec(cmd: string, timeoutSec = 60): Promise<string> {
    const r = await invoke('ssh_execute_emergency_command_direct', {
      command: cmd, username: null, timeoutSec, cwd: null,
    }) as any;
    return r?.output || '';
  }

  // ──────── 探测 & 加载规则 ────────

  private async detectAndLoad(): Promise<void> {
    this.loading = true;
    this.render();
    try {
      const probe = await this.exec(
        `echo "NFT=$(command -v nft || true)"; echo "IPT=$(command -v iptables || true)"; echo "UFW=$(command -v ufw || true)"; echo "FWD=$(command -v firewall-cmd || true)"; ufw status 2>/dev/null | head -1`
      );
      this.backend = this.pickBackend(probe);
      await this.loadRules();
    } catch (e) {
      window.showNotification?.(`探测防火墙失败: ${e}`, 'error');
    } finally {
      this.loading = false;
      this.render();
    }
  }

  private pickBackend(probe: string): FwBackend {
    // 优先级：ufw（若 active）> firewalld > nft > iptables
    const ufwActive = /Status:\s*active/i.test(probe);
    if (probe.includes('UFW=') && !probe.includes('UFW=\n') && ufwActive) return 'ufw';
    if (/FWD=\/\S+/.test(probe)) return 'firewalld';
    if (/NFT=\/\S+/.test(probe)) return 'nftables';
    if (/IPT=\/\S+/.test(probe)) return 'iptables';
    if (/UFW=\/\S+/.test(probe)) return 'ufw';
    return 'unknown';
  }

  private async loadRules(): Promise<void> {
    let cmd = '';
    switch (this.backend) {
      case 'ufw': cmd = 'ufw status numbered 2>/dev/null'; break;
      case 'firewalld': cmd = 'firewall-cmd --list-all 2>/dev/null'; break;
      case 'nftables': cmd = 'nft list ruleset 2>/dev/null'; break;
      case 'iptables': cmd = 'iptables -S 2>/dev/null'; break;
      default: cmd = 'iptables -S 2>/dev/null || nft list ruleset 2>/dev/null';
    }
    this.currentRules = await this.exec(cmd) || '(无规则或无权限)';
  }

  // ──────── 备份规则集 ────────

  /** 备份当前规则集，返回 { archive, restoreCommand } */
  private async backupRuleset(): Promise<{ archive: string; restoreCommand: string }> {
    const ts = this.stamp();
    await this.exec(`mkdir -p ${shq(FW_BACKUP_DIR)}`);
    if (this.backend === 'nftables') {
      const archive = `${FW_BACKUP_DIR}/${ts}.nft`;
      await this.exec(`nft list ruleset > ${shq(archive)} 2>/dev/null`);
      return { archive, restoreCommand: `nft -f ${shq(archive)}` };
    }
    // iptables / ufw(底层 iptables) / 默认
    const archive = `${FW_BACKUP_DIR}/${ts}.rules`;
    await this.exec(`iptables-save > ${shq(archive)} 2>/dev/null`);
    return { archive, restoreCommand: `iptables-restore < ${shq(archive)}` };
  }

  // ──────── 事件 ────────

  private bindEvents(): void {
    document.addEventListener('click', (e) => {
      const t = (e.target as HTMLElement).closest('[data-fw-action]') as HTMLElement;
      if (!t) return;
      const action = t.getAttribute('data-fw-action') || '';
      switch (action) {
        case 'refresh': this.detectAndLoad(); break;
        case 'block-ip': this.onBlockIp(); break;
        case 'allow-port': this.onAllowPort(); break;
        case 'default-deny': this.onDefaultDeny(); break;
      }
    });
  }

  private input(id: string): string {
    return (document.getElementById(id) as HTMLInputElement)?.value?.trim() || '';
  }

  // ──────── 处置动作 ────────

  private async onBlockIp(): Promise<void> {
    const ip = this.input('fw-ip');
    if (!isValidIpOrCidr(ip)) { window.showNotification?.('请输入合法的 IP 或 CIDR', 'error'); return; }

    const cmd = this.backend === 'ufw'
      ? `ufw insert 1 deny from ${shq(ip)}`
      : this.backend === 'nftables'
        ? `nft insert rule inet filter input ip saddr ${shq(ip)} drop 2>/dev/null || iptables -I INPUT -s ${shq(ip)} -j DROP`
        : `iptables -I INPUT -s ${shq(ip)} -j DROP`;
    const restore = this.backend === 'ufw'
      ? `ufw delete deny from ${shq(ip)}`
      : `iptables -D INPUT -s ${shq(ip)} -j DROP 2>/dev/null; nft flush chain inet filter input 2>/dev/null || true`;

    const ok = await showConfirm({
      title: '封禁 IP',
      message: `将封禁来源 ${ip} 的入站流量。\n\n命令：${cmd}`,
      confirmText: '封禁', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;

    // 封单个 IP 不会自锁（除非封的正是自己），但仍做备份以便回滚
    const backup = await this.backupRuleset();
    await this.runAndRecord(cmd, `封禁 IP ${ip}`, restore, backup.archive);
  }

  private async onAllowPort(): Promise<void> {
    const port = this.input('fw-port');
    if (!isValidPort(port)) { window.showNotification?.('请输入合法端口 (1-65535)', 'error'); return; }

    const cmd = this.backend === 'ufw'
      ? `ufw allow ${shq(port)}/tcp`
      : this.backend === 'nftables'
        ? `nft add rule inet filter input tcp dport ${shq(port)} accept 2>/dev/null || iptables -I INPUT -p tcp --dport ${shq(port)} -j ACCEPT`
        : `iptables -I INPUT -p tcp --dport ${shq(port)} -j ACCEPT`;
    const restore = this.backend === 'ufw'
      ? `ufw delete allow ${shq(port)}/tcp`
      : `iptables -D INPUT -p tcp --dport ${shq(port)} -j ACCEPT 2>/dev/null || true`;

    const ok = await showConfirm({
      title: '放行端口',
      message: `将放行 TCP 端口 ${port} 的入站流量。\n\n命令：${cmd}`,
      confirmText: '放行', cancelText: '取消',
    });
    if (!ok) return;

    const backup = await this.backupRuleset();
    await this.runAndRecord(cmd, `放行端口 ${port}/tcp`, restore, backup.archive);
  }

  private async onDefaultDeny(): Promise<void> {
    const sshPort = this.sshPort();
    // 防自锁豁免：先放行当前 SSH 端口，再设默认拒绝
    const exemption = this.backend === 'ufw'
      ? `ufw allow ${sshPort}/tcp`
      : `iptables -I INPUT -p tcp --dport ${sshPort} -j ACCEPT; iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT; iptables -I INPUT -i lo -j ACCEPT`;
    const denyCmd = this.backend === 'ufw'
      ? `ufw --force default deny incoming`
      : `iptables -P INPUT DROP`;

    const ok = await showConfirm({
      title: '设置默认拒绝（高危）',
      message: `将把入站默认策略设为 DROP。\n\n已自动豁免当前 SSH 端口 ${sshPort}、本地回环与已建立连接，防止断连。\n\n应用后将启动 ${DEADMAN_SECONDS} 秒"死人开关"：若你不点"保留规则"，到点会自动还原到当前规则集。`,
      confirmText: '应用', cancelText: '取消', dangerous: true,
    });
    if (!ok) return;

    const backup = await this.backupRuleset();

    // 死人开关：后台 sleep 后自动还原，PID 落盘
    const pidFile = `${FW_BACKUP_DIR}/deadman.pid`;
    const deadman = `( sleep ${DEADMAN_SECONDS}; ${backup.restoreCommand} ) >/dev/null 2>&1 & echo $! > ${shq(pidFile)}`;
    const applyCmd = `${exemption}; ${denyCmd}; ${deadman}`;

    let output = '';
    let success = true;
    try {
      output = await this.exec(applyCmd, 30);
    } catch (e) { success = false; output = String(e); }

    if (!success) {
      window.showNotification?.(`应用失败: ${output}`, 'error');
      await this.detectAndLoad();
      return;
    }

    // 记录（restoreCommand 用备份还原）
    operationJournal.record({
      source: 'firewall', server: this.server(),
      title: '设置入站默认拒绝（已豁免 SSH）',
      command: `${exemption}; ${denyCmd}`,
      backupInfo: backup.archive,
      restoreCommand: backup.restoreCommand,
      output, success: true,
    });

    // 让用户在死人开关到点前确认"网络仍正常"
    const keep = await showConfirm({
      title: '规则已应用 — 网络是否正常？',
      message: `默认拒绝规则已生效。若你仍能正常操作（此对话框能弹出即说明前端存活），请点"保留规则"。\n\n若不确认，${DEADMAN_SECONDS} 秒后规则将自动还原。`,
      confirmText: '保留规则', cancelText: '立即还原',
    });

    if (keep) {
      // kill 掉死人开关定时任务
      await this.exec(`[ -f ${shq(pidFile)} ] && kill "$(cat ${shq(pidFile)})" 2>/dev/null; rm -f ${shq(pidFile)}`);
      window.showNotification?.('规则已保留，死人开关已取消', 'success');
    } else {
      // 立即还原并取消死人开关
      await this.exec(`[ -f ${shq(pidFile)} ] && kill "$(cat ${shq(pidFile)})" 2>/dev/null; rm -f ${shq(pidFile)}; ${backup.restoreCommand}`);
      operationJournal.record({
        source: 'firewall', server: this.server(),
        title: '还原默认拒绝规则（用户主动）',
        command: backup.restoreCommand, output: '', success: true,
      });
      window.showNotification?.('已还原到应用前的规则', 'info');
    }
    await this.detectAndLoad();
  }

  /** 执行处置命令并记入 journal，随后刷新规则视图 */
  private async runAndRecord(cmd: string, title: string, restoreCommand: string, archive: string): Promise<void> {
    let output = '';
    let success = true;
    try {
      output = await this.exec(cmd, 30);
    } catch (e) { success = false; output = String(e); }

    operationJournal.record({
      source: 'firewall', server: this.server(),
      title, command: cmd, backupInfo: archive, restoreCommand,
      output, success,
    });
    window.showNotification?.(success ? `${title} 完成` : `${title} 失败: ${output}`, success ? 'success' : 'error');
    await this.loadRules();
    this.render();
  }

  // ──────── 渲染 ────────

  private render(): void {
    const container = document.getElementById('firewall-content');
    if (!container) return;

    if (!sshConnectionManager.isConnected()) {
      container.innerHTML = `<div class="fw-empty">请先连接服务器后使用防火墙管理。</div>${this.styles()}`;
      return;
    }

    const backendLabel: Record<FwBackend, string> = {
      iptables: 'iptables', nftables: 'nftables', ufw: 'ufw', firewalld: 'firewalld', unknown: '未探测到',
    };

    container.innerHTML = `
      <div class="fw-bar">
        <span class="fw-backend">当前后端：<b>${backendLabel[this.backend]}</b> · SSH 端口 ${this.sshPort()}</span>
        <span class="fw-spacer"></span>
        <button class="fw-btn" data-fw-action="refresh">${this.loading ? '探测中...' : '刷新'}</button>
      </div>

      <div class="fw-actions">
        <div class="fw-act-row">
          <input id="fw-ip" class="fw-input" placeholder="要封禁的 IP / CIDR，如 1.2.3.4 或 1.2.3.0/24" />
          <button class="fw-btn danger" data-fw-action="block-ip">封禁 IP</button>
        </div>
        <div class="fw-act-row">
          <input id="fw-port" class="fw-input" placeholder="要放行的 TCP 端口，如 80" />
          <button class="fw-btn" data-fw-action="allow-port">放行端口</button>
        </div>
        <div class="fw-act-row">
          <span class="fw-danger-label">默认拒绝入站（自动豁免当前 SSH + 死人开关兜底）</span>
          <button class="fw-btn danger" data-fw-action="default-deny">设置默认拒绝</button>
        </div>
      </div>

      <div class="fw-section-title">当前规则</div>
      <pre class="fw-rules">${this.esc(this.currentRules || '(加载中...)')}</pre>
      ${this.styles()}
    `;
  }

  private stamp(): string {
    const d = new Date();
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  }

  private esc(s: string): string {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  private styles(): string {
    if (document.getElementById('fw-styles')) return '';
    return `<style id="fw-styles">
      .fw-empty{color:var(--text-secondary);text-align:center;padding:40px;font-size:13px;}
      .fw-bar{display:flex;align-items:center;gap:10px;margin-bottom:14px;}
      .fw-spacer{flex:1;}
      .fw-backend{color:var(--text-secondary);font-size:12px;}
      .fw-btn{background:var(--bg-secondary);border:1px solid var(--border-color);color:var(--text-primary);padding:7px 14px;border-radius:6px;cursor:pointer;font-size:12px;}
      .fw-btn:hover{border-color:var(--primary-color);}
      .fw-btn.danger{color:#ef4444;border-color:rgba(239,68,68,.4);}
      .fw-btn.danger:hover{background:rgba(239,68,68,.1);}
      .fw-actions{background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:8px;padding:14px;margin-bottom:16px;}
      .fw-act-row{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
      .fw-act-row:last-child{margin-bottom:0;}
      .fw-input{flex:1;background:var(--bg-primary);border:1px solid var(--border-color);color:var(--text-primary);padding:7px 10px;border-radius:6px;font-size:12px;}
      .fw-danger-label{flex:1;color:var(--text-secondary);font-size:12px;}
      .fw-section-title{color:var(--text-primary);font-weight:600;font-size:13px;margin-bottom:8px;}
      .fw-rules{background:var(--bg-primary);border:1px solid var(--border-color);border-radius:8px;padding:12px;font-family:monospace;font-size:11px;color:var(--text-primary);max-height:340px;overflow:auto;white-space:pre-wrap;word-break:break-all;}
    </style>`;
  }
}

export const firewallManager = new FirewallManager();
