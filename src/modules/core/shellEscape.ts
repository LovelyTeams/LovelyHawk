/**
 * Shell 参数转义工具
 *
 * 线下防御赛的命令大量拼接用户输入（用户名、口令、路径、IP）。为避免命令注入 /
 * 特殊字符破坏命令，所有拼进 shell 的动态值都必须经过 shq()。
 *
 * shq('a b') => 'a b'（单引号包裹）
 * shq("O'Brien") => 'O'\''Brien'（POSIX 标准的单引号转义）
 */

/** 用单引号安全包裹任意字符串，供 POSIX sh 使用 */
export function shq(value: string | number): string {
  const s = String(value);
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** 简单校验：Linux 用户名（防止把任意串当用户名拼进命令） */
export function isValidUsername(name: string): boolean {
  return /^[a-z_][a-z0-9_-]{0,31}$/i.test(name);
}

/** 简单校验：IPv4 / IPv6 / CIDR，用于防火墙封禁来源 */
export function isValidIpOrCidr(value: string): boolean {
  const v = value.trim();
  // IPv4 或 IPv4/CIDR
  const ipv4 = /^(\d{1,3})(\.\d{1,3}){3}(\/\d{1,2})?$/;
  // IPv6（宽松）或带 CIDR
  const ipv6 = /^[0-9a-f:]+(\/\d{1,3})?$/i;
  if (ipv4.test(v)) {
    const octets = v.split('/')[0].split('.').map(Number);
    return octets.every(o => o >= 0 && o <= 255);
  }
  return ipv6.test(v) && v.includes(':');
}

/** 简单校验：端口号 1-65535 */
export function isValidPort(value: string | number): boolean {
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/** 简单校验：进程 PID（Linux 上限见 /proc/sys/kernel/pid_max，取 2^22） */
export function isValidPid(value: string | number): boolean {
  const s = String(value).trim();
  if (!/^\d+$/.test(s)) return false;
  const n = Number(s);
  return n >= 1 && n <= 4194304;
}

/**
 * 简单校验：非负整数（chage 的天数等）
 */
export function isValidNonNegativeInt(value: string | number): boolean {
  const s = String(value).trim();
  return /^\d+$/.test(s) && Number(s) <= 99999;
}
