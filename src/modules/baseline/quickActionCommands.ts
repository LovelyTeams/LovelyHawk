/**
 * 基线快捷操作 —— 命令生成与参数校验（纯函数，无 DOM 依赖）
 *
 * 从 baselineQuickEditManager 抽出，目的有二：
 *  1. 这些命令以 root 在靶机上执行，是全项目风险最高的拼接点之一，必须能被单测覆盖；
 *  2. 参数校验与命令拼接放在一处，避免「加了新操作却忘了配校验」。
 *
 * 安全模型（两层，缺一不可）：
 *  - 有确定格式的参数（用户名 / IP / 端口 / PID / 天数）走 PARAM_VALIDATORS 白名单，
 *    非法直接拒绝。赛场上非法输入几乎总是粘贴错了，静默执行比报错危险得多。
 *  - 所有进 shell 的值一律 shq() 单引号包裹。少数几处必须裸拼（sed 的 s|...| 表达式、
 *    firewall-cmd 的 rich-rule 单引号参数）在注释里写明了它依赖哪条白名单。
 */

import {
  shq,
  isValidUsername,
  isValidIpOrCidr,
  isValidPort,
  isValidPid,
  isValidNonNegativeInt,
} from '../core/shellEscape';

export interface QuickActionCommand {
  cmd: string;
  desc: string;
  dangerous?: boolean;
}

/** 必须填参数才能执行的操作 */
export const QUICK_ACTIONS_NEEDING_PARAM = [
  'block-ip', 'unblock-ip', 'block-port', 'kick-user', 'kill-pid', 'kill-name', 'kill-port',
  'lock-user', 'unlock-user', 'force-passwd', 'clear-crontab', 'clear-authkeys', 'clear-history',
  'remove-sshkey-line', 'query-user-chage', 'set-user-maxdays', 'set-user-warndays',
  'set-user-mindays', 'expire-user-passwd', 'set-user-nologin', 'delete-user', 'query-user-sudo-log',
] as const;

/**
 * chage 类操作的参数是「<天数> <用户名>」两段式，两段都要合法才放行。
 * 只有本页在用这个组合格式，故不下沉到 shellEscape.ts。
 */
export function isValidDaysAndUser(value: string): boolean {
  const parts = value.trim().split(/\s+/);
  return parts.length === 2 && isValidNonNegativeInt(parts[0]) && isValidUsername(parts[1]);
}

const USERNAME_RULE = { check: isValidUsername, hint: '请输入合法的 Linux 用户名' };
const IP_RULE = { check: isValidIpOrCidr, hint: '请输入合法的 IPv4/IPv6 地址或 CIDR' };
const PORT_RULE = { check: isValidPort, hint: '请输入 1-65535 的端口号' };

/** 按操作类型的参数白名单。未列出的操作（如 kill-name、remove-sshkey-line）是自由文本，只靠 shq() 兜底 */
export const PARAM_VALIDATORS: Record<string, { check: (v: string) => boolean; hint: string }> = {
  'block-ip': IP_RULE,
  'unblock-ip': IP_RULE,
  'block-port': PORT_RULE,
  'kill-port': PORT_RULE,
  'kill-pid': { check: isValidPid, hint: '请输入合法的进程 PID' },
  'kick-user': USERNAME_RULE,
  'lock-user': USERNAME_RULE,
  'unlock-user': USERNAME_RULE,
  'force-passwd': USERNAME_RULE,
  'clear-crontab': USERNAME_RULE,
  'clear-authkeys': USERNAME_RULE,
  'clear-history': USERNAME_RULE,
  'query-user-chage': USERNAME_RULE,
  'expire-user-passwd': USERNAME_RULE,
  'set-user-nologin': USERNAME_RULE,
  'delete-user': USERNAME_RULE,
  'query-user-sudo-log': USERNAME_RULE,
  'set-user-maxdays': { check: isValidDaysAndUser, hint: '格式: <天数> <用户名>，如 90 root' },
  'set-user-warndays': { check: isValidDaysAndUser, hint: '格式: <天数> <用户名>，如 7 root' },
  'set-user-mindays': { check: isValidDaysAndUser, hint: '格式: <天数> <用户名>，如 1 root' },
};

export type ParamCheckResult =
  | { ok: true }
  | { ok: false; reason: 'missing' | 'illegal-char' | 'format'; hint: string };

/**
 * 执行前的参数校验。两道防线：
 *  1. 字符黑名单——纵深防御。它本身并不完整（不拦 > < ' * ? 和前导 -），
 *     不能作为唯一保证，但能挡掉最常见的手滑。
 *  2. 按类型白名单——真正的保证。
 */
export function checkQuickActionParam(actionId: string, param: string): ParamCheckResult {
  const needsParam = (QUICK_ACTIONS_NEEDING_PARAM as readonly string[]).includes(actionId);
  if (needsParam && !param) {
    return { ok: false, reason: 'missing', hint: '请输入参数' };
  }
  if (param && /[;&|`$(){}]/.test(param)) {
    return { ok: false, reason: 'illegal-char', hint: '参数包含非法字符' };
  }
  const validator = PARAM_VALIDATORS[actionId];
  if (validator && !validator.check(param)) {
    return { ok: false, reason: 'format', hint: validator.hint };
  }
  return { ok: true };
}

/**
 * 生成快捷操作命令。actionId 未知时返回 null。
 *
 * 调用方必须先跑 checkQuickActionParam()——本函数假定参数已通过校验，
 * 少数裸拼点（sed 表达式 / rich-rule）的安全性依赖于此。
 */
export function buildQuickActionCommand(
  actionId: string,
  param: string,
  distro: string | null,
): QuickActionCommand | null {
  const isAlpine = distro === 'alpine';
  const hasNft = distro === 'fedora' || distro === 'rhel' || distro === 'openeuler' || distro === 'anolis';

  const blockIpCmd = (ip: string) => {
    if (isAlpine) return `iptables -A INPUT -s ${shq(ip)} -j DROP`;
    // rich-rule 整体是一个单引号参数，内层不能再套 shq()（会产生嵌套引号）。
    // 裸拼的前提：isValidIpOrCidr 已保证 ip 只含 [0-9a-f:./]，不含引号。
    return hasNft
      ? `firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=${ip} drop' && firewall-cmd --reload || iptables -A INPUT -s ${shq(ip)} -j DROP`
      : `(command -v ufw >/dev/null 2>&1 && ufw deny from ${shq(ip)}) || iptables -A INPUT -s ${shq(ip)} -j DROP`;
  };
  const unblockIpCmd = (ip: string) => {
    if (hasNft) return `firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address=${ip} drop' 2>/dev/null; firewall-cmd --reload 2>/dev/null; iptables -D INPUT -s ${shq(ip)} -j DROP 2>/dev/null; echo done`;
    return `(command -v ufw >/dev/null 2>&1 && ufw delete deny from ${shq(ip)} 2>/dev/null); iptables -D INPUT -s ${shq(ip)} -j DROP 2>/dev/null; echo done`;
  };
  const blockPortCmd = (port: string) => {
    const p = shq(port);
    if (hasNft) return `firewall-cmd --permanent --remove-port=${shq(port + '/tcp')} 2>/dev/null; firewall-cmd --permanent --remove-port=${shq(port + '/udp')} 2>/dev/null; firewall-cmd --reload || (iptables -A INPUT -p tcp --dport ${p} -j DROP && iptables -A INPUT -p udp --dport ${p} -j DROP)`;
    return `(command -v ufw >/dev/null 2>&1 && ufw deny ${p}) || (iptables -A INPUT -p tcp --dport ${p} -j DROP && iptables -A INPUT -p udp --dport ${p} -j DROP)`;
  };

  // Alpine 没有 usermod -s，直接改 /etc/passwd。
  // 用户名进 sed 的 s|...| 表达式，一个 '|' 或 '.' 就能破坏模式——这里不做转义，
  // 而是依赖 isValidUsername 把用户名限定为 [a-z_][a-z0-9_-]*（不含任何 sed 元字符）。
  const lockUserCmd = (u: string) => isAlpine
    ? `passwd -l ${shq(u)} 2>/dev/null; sed -i 's|^${u}:\\([^:]*\\):\\([^:]*\\):\\([^:]*\\):\\([^:]*\\):\\([^:]*\\):.*|${u}:\\1:\\2:\\3:\\4:\\5:/sbin/nologin|' /etc/passwd`
    : `passwd -l ${shq(u)} && usermod -s /sbin/nologin ${shq(u)}`;
  const unlockUserCmd = (u: string) => isAlpine
    ? `passwd -u ${shq(u)} 2>/dev/null; sed -i 's|^${u}:\\([^:]*\\):\\([^:]*\\):\\([^:]*\\):\\([^:]*\\):\\([^:]*\\):.*|${u}:\\1:\\2:\\3:\\4:\\5:/bin/sh|' /etc/passwd`
    : `passwd -u ${shq(u)} && usermod -s /bin/bash ${shq(u)}`;
  const forcePasswdCmd = (u: string) => isAlpine
    ? `passwd -e ${shq(u)} 2>/dev/null || echo 'Alpine: 请手动执行 passwd ${u}'`
    : `chage -d 0 ${shq(u)}`;
  const disableCtrlAltDelCmd = isAlpine
    ? `sed -i 's/^ca::ctrlaltdel:/#ca::ctrlaltdel:/' /etc/inittab 2>/dev/null; echo done`
    : `systemctl mask ctrl-alt-del.target && systemctl daemon-reload && echo done`;

  /** 通过 getent 取真实主目录，避免 `eval h=~user` 展开未转义输入，也修好主目录不在 /home/<user> 的情况 */
  const clearUserFile = (relPath: string) =>
    `h=$(getent passwd ${shq(param)} | cut -d: -f6); [ -n "$h" ] || { echo "用户不存在"; exit 1; }; ` +
    `: > "$h/${relPath}" 2>/dev/null && echo "cleared: $h/${relPath}" || echo "failed"`;

  const commandMap: Record<string, () => QuickActionCommand> = {
    'block-ip': () => ({ cmd: blockIpCmd(param), desc: `封禁 IP: ${param}`, dangerous: true }),
    'unblock-ip': () => ({ cmd: unblockIpCmd(param), desc: `解封 IP: ${param}` }),
    'block-port': () => ({ cmd: blockPortCmd(param), desc: `封禁端口: ${param}`, dangerous: true }),
    'kick-user': () => ({ cmd: `pkill -KILL -u ${shq(param)}`, desc: `踢出用户: ${param}`, dangerous: true }),
    'kill-pid': () => ({ cmd: `kill -9 -- ${shq(param)}`, desc: `杀进程 PID: ${param}`, dangerous: true }),
    // 进程名是自由文本（pkill 的匹配模式），无格式白名单可套，只靠 shq()；
    // 额外加 -- 防止以 - 开头的输入被 pkill 当成选项。
    'kill-name': () => ({ cmd: `pkill -9 -- ${shq(param)}`, desc: `杀进程: ${param}`, dangerous: true }),
    'kill-port': () => ({ cmd: `fuser -k ${shq(param + '/tcp')} 2>/dev/null; fuser -k ${shq(param + '/udp')} 2>/dev/null; echo done`, desc: `杀端口监听: ${param}`, dangerous: true }),
    'lock-user': () => ({ cmd: lockUserCmd(param), desc: `锁定用户: ${param}`, dangerous: true }),
    'unlock-user': () => ({ cmd: unlockUserCmd(param), desc: `解锁用户: ${param}` }),
    'force-passwd': () => ({ cmd: forcePasswdCmd(param), desc: `强制用户 ${param} 下次登录改密` }),
    'who-online': () => ({ cmd: `echo '=== who ===' && who && echo '=== w ===' && w`, desc: '查看在线用户' }),
    'clear-crontab': () => ({ cmd: `crontab -r -u ${shq(param)} 2>/dev/null; echo "crontab cleared for ${param}"`, desc: `清理 ${param} 的 crontab`, dangerous: true }),
    'clear-authkeys': () => ({ cmd: clearUserFile('.ssh/authorized_keys'), desc: `清空 ${param} 的 authorized_keys`, dangerous: true }),
    'clear-history': () => ({ cmd: clearUserFile('.bash_history'), desc: `清空 ${param} 的 bash_history` }),
    'clean-tmp': () => ({ cmd: `find /tmp /var/tmp /dev/shm -type f -executable -delete 2>/dev/null; echo "cleaned"`, desc: '清理 /tmp 可执行文件', dangerous: true }),
    // 原实现把 param 插进 grep 的单引号和 sed 的 /PATTERN/ 里：一个 ' 就能逃逸，
    // 而公钥串本身几乎必然含 '/'（base64），会直接破坏 sed 的分隔符。
    // 改为存进 shell 变量，全程 grep -F 定长匹配，不再经过任何正则引擎。
    'remove-sshkey-line': () => ({
      cmd: `k=${shq(param)}; for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do [ -f "$f" ] || continue; if grep -qF -- "$k" "$f"; then grep -vF -- "$k" "$f" > "$f.lovelyres.tmp" && cat "$f.lovelyres.tmp" > "$f" && rm -f "$f.lovelyres.tmp" && echo "cleaned: $f"; fi; done; echo done`,
      desc: `删除含 "${param}" 的公钥行`, dangerous: true,
    }),
    // ── 一键加固（无参数，全静态）──
    'set-tmout': () => ({ cmd: `grep -q '^\\(export \\)\\?TMOUT=' /etc/profile && sed -i 's/^\\(export \\)\\?TMOUT=.*/export TMOUT=600/' /etc/profile || echo 'export TMOUT=600' >> /etc/profile`, desc: '设置会话超时 600s' }),
    'set-histformat': () => ({ cmd: `grep -q 'HISTTIMEFORMAT' /etc/profile && sed -i "s/^.*HISTTIMEFORMAT.*/export HISTTIMEFORMAT='%F %T '/" /etc/profile || echo "export HISTTIMEFORMAT='%F %T '" >> /etc/profile`, desc: '启用历史时间戳' }),
    'disable-usb': () => ({ cmd: `echo 'install usb-storage /bin/true' > /etc/modprobe.d/disable-usb-storage.conf && rmmod usb_storage 2>/dev/null; echo done`, desc: '禁用 USB 存储' }),
    'disable-ctrlaltdel': () => ({ cmd: disableCtrlAltDelCmd, desc: '禁用 Ctrl+Alt+Del' }),
    'set-banner': () => ({ cmd: `echo 'Authorized users only. All activity may be monitored and reported.' | tee /etc/issue /etc/issue.net > /dev/null && echo done`, desc: '设置登录警告 Banner' }),
    'disable-core': () => ({ cmd: `grep -q '^\\*.*hard.*core' /etc/security/limits.conf && sed -i 's/^\\*.*hard.*core.*/*               hard    core            0/' /etc/security/limits.conf || echo '*               hard    core            0' >> /etc/security/limits.conf`, desc: '禁用 Core dump' }),
    // ── 用户账户操作 ──
    'query-user-chage': () => ({ cmd: `chage -l ${shq(param)} 2>/dev/null || echo '用户不存在或无权限'`, desc: `查询 ${param} 密码策略` }),
    'set-user-maxdays': () => {
      const [days, user] = param.split(/\s+/);
      return { cmd: `chage -M ${shq(days)} ${shq(user)} && chage -l ${shq(user)}`, desc: `设置 ${user} 密码最大天数=${days}` };
    },
    'set-user-warndays': () => {
      const [days, user] = param.split(/\s+/);
      return { cmd: `chage -W ${shq(days)} ${shq(user)} && chage -l ${shq(user)}`, desc: `设置 ${user} 密码警告天数=${days}` };
    },
    'set-user-mindays': () => {
      const [days, user] = param.split(/\s+/);
      return { cmd: `chage -m ${shq(days)} ${shq(user)} && chage -l ${shq(user)}`, desc: `设置 ${user} 密码最小天数=${days}` };
    },
    'expire-user-passwd': () => ({ cmd: `chage -d 0 ${shq(param)} && echo '已设置，用户下次登录需修改密码'`, desc: `强制 ${param} 下次改密` }),
    // Alpine 分支同 lockUserCmd：用户名进 sed 表达式，靠 isValidUsername 保证不含元字符
    'set-user-nologin': () => ({ cmd: isAlpine ? `sed -i 's|^${param}:.*:/bin/.*|${param}:\\&:/sbin/nologin|' /etc/passwd` : `usermod -s /sbin/nologin ${shq(param)}`, desc: `禁止 ${param} 登录`, dangerous: true }),
    'delete-user': () => ({ cmd: `userdel -r ${shq(param)} 2>/dev/null && echo '用户已删除' || echo '删除失败'`, desc: `删除用户 ${param}`, dangerous: true }),
    // ── 信息采集 ──
    'query-ssh-version': () => ({ cmd: `ssh -V 2>&1`, desc: '查看 SSH 版本' }),
    'query-kernel': () => ({ cmd: `uname -a`, desc: '查看内核版本' }),
    'query-login-defs': () => ({ cmd: `grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_MIN_LEN|^PASS_WARN_AGE' /etc/login.defs 2>/dev/null || echo '文件不存在'`, desc: '查看密码策略文件' }),
    // 原实现把 param 插进 grep 的单引号正则里两次，一个 ' 即逃逸。
    // 改为存入 shell 变量 + grep -F 定长匹配（用户名不需要正则语义），sudo 关键字拆成第二级 grep。
    'query-user-sudo-log': () => ({
      cmd: `u=${shq(param)}; { grep -iF -- "$u" /var/log/auth.log /var/log/secure 2>/dev/null; journalctl _COMM=sudo --no-pager 2>/dev/null | grep -iF -- "$u"; } | grep -i sudo | tail -30 || echo '(无记录)'`,
      desc: `查询 ${param} 的 sudo 日志`,
    }),
    'query-malicious-ports': () => ({ cmd: `echo '=== 恶意端口扫描 ===' && (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E ':1234\\b|:2333\\b|:3333\\b|:4444\\b|:4445\\b|:5555\\b|:6666\\b|:6667\\b|:7777\\b|:8888\\b|:9999\\b|:1080\\b|:3128\\b|:4443\\b|:5900\\b|:31337\\b|:12345\\b|:23456\\b|:65535\\b|:14444\\b|:55553\\b' || echo '(未发现已知恶意端口)' && echo '=== 高端口(>10000) ===' && (ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | awk '{if(match($0,/:([0-9]+) /,m) && m[1]>10000)print}'`, desc: '恶意端口扫描' }),
    'query-suspicious-users': () => ({ cmd: `echo '=== UID=0 ===' && awk -F: '$3==0{print $1}' /etc/passwd && echo '=== 空密码 ===' && awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null && echo '=== 异常Shell ===' && awk -F: '$7 ~ /(bash|sh|zsh)$/ && ($3>=1000||$3==0){print $1,"UID="$3}' /etc/passwd && echo '=== 权限分离检查 ===' && getent group sudo wheel 2>/dev/null && echo '=== NOPASSWD ===' && grep -r NOPASSWD /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'`, desc: '可疑用户全面检测' }),
    'query-all-listening': () => ({ cmd: `(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) && echo '=== UDP ===' && (ss -ulnp 2>/dev/null || netstat -ulnp 2>/dev/null)`, desc: '所有监听端口' }),
  };

  const gen = commandMap[actionId];
  return gen ? gen() : null;
}
