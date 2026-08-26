// Every row is something the lab deliberately planted. If a rule change ever
// silences one of these, this is the probe that says so.
//
// A row that no command covers is not a bug in the lab — it is a gap in the
// catalogue, and it is reported as MISS so it stays visible.
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const PLANTED = [
  // accounts
  ["second uid 0 account", "UID 0 账户", /svcadm/u],
  ["passwordless account", "空/锁定口令字段", /backup2/u],
  ["system account given a shell", "用户与登录 Shell", /daemon.*(bash|sh)/u],
  ["blanket NOPASSWD sudo rule", "免密提权规则", /www-data.*NOPASSWD/u],
  ["NOPASSWD on a shell-granting tool", "免密提权规则", /ops.*(find|awk)/u],
  ["user added to a privileged group", "特权组成员", /deploy/u],

  // login scripts and environment
  ["backdoor in /etc/profile", "全局登录脚本内容", /198\.51\.100\.7|curl/u],
  ["backdoor in a profile.d drop-in", "全局登录脚本内容", /pyshared|helper|198\.51\.100\.7/u],
  ["backdoor in root's bashrc", "用户登录脚本内容", /curl|198\.51\.100\.7/u],
  ["LD_PRELOAD in /etc/environment", "环境变量", /LD_PRELOAD/u],
  ["ld.so.preload entry", "动态库注入痕迹", /pyshared|preload/u],

  // ssh
  ["attacker key in root's authorized_keys", "SSH 授权公钥内容", /ssh-(ed25519|rsa)/u],
  ["root login and password auth enabled", "SSH 服务配置", /permitrootlogin|passwordauthentication/iu],

  // persistence
  ["cron drop-in calling out", "系统计划任务内容", /198\.51\.100\.7|curl/u],
  ["user crontab calling out", "用户计划任务内容", /198\.51\.100\.7|curl/u],
  ["rc.local reverse shell", "开机脚本与运行级", /dev\/tcp|bash -i/u],
  ["systemd unit beacon", "近期改动的服务单元", /system-health|\.service/u],
  ["pam hook on every login", "认证模块变更", /pam\.d|pam_exec/u],

  // permissions and files
  ["SUID backdoor", "SUID 可执行", /\.sysd/u],
  ["SUID set on a standard tool", "SUID 可执行", /\/usr\/bin\/find/u],
  ["world-writable library path", "全局可写目录", /pyshared/u],
  ["hidden implant directory", "隐藏文件", /X11-unix|\.cache/u],
  ["history redirected to /dev/null", "命令历史文件", /bash_history/u],

  // network
  ["listener on a handler port", "监听端口", /4444/u],
  ["hosts file hijack", "域名解析配置", /198\.51\.100\.7/u],

  // web
  ["php webshell", "站点可疑代码特征", /eval|assert|upload\.php|config\.inc/u],

  // logs
  ["brute force in the auth log", "认证日志", /Failed password/u],
  ["successful login after the brute force", "SSH 登录成功记录", /Accepted/u],
  ["account created during the intrusion", "账号变更日志", /svcadm|new user/u],
  ["login records emptied", "日志被清理迹象", /wtmp|btmp|0$/u],
];

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  if (status.stage !== "connected") throw new Error(JSON.stringify(status));
  const binding = status.bindingHandle;
  let catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });

  // The catalogue is a five minute capability. A slow host can outlast it in
  // the middle of a sweep, which in the window is a reload button.
  const reload = async () => {
    catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding }, 180_000);
  };

  // One run per command, reused across the rows that share it.
  const runs = new Map();
  const runFor = async (title) => {
    if (runs.has(title)) return runs.get(title);
    let command = catalog.commands.find((entry) => entry.title === title);
    if (command === undefined) {
      runs.set(title, null);
      return null;
    }
    let run;
    try {
      run = await sidecar.call("emergency-command.run", {
        bindingHandle: binding, snapshotHandle: catalog.snapshotHandle,
        commandHandle: command.commandHandle,
      }, 90_000);
    } catch (error) {
      if (!/catalog/u.test(error.message)) throw error;
      await reload();
      command = catalog.commands.find((entry) => entry.title === title);
      run = await sidecar.call("emergency-command.run", {
        bindingHandle: binding, snapshotHandle: catalog.snapshotHandle,
        commandHandle: command.commandHandle,
      }, 90_000);
    }
    runs.set(title, run);
    return run;
  };

  let missed = 0;
  for (const [what, title, pattern] of PLANTED) {
    const run = await runFor(title);
    if (run === null) {
      console.log(`MISS ${what}: no command titled ${title}`);
      missed += 1;
      continue;
    }
    const lines = run.output.split("\n");
    const flagged = (run.findingLines ?? []).map((index) => lines[index] ?? "");
    const hit = flagged.find((line) => pattern.test(line));
    if (hit === undefined) {
      const present = lines.some((line) => pattern.test(line));
      console.log(`MISS ${what} (${title}): ${flagged.length} flagged, ` +
        `${present ? "the line is in the output but not highlighted" : "not in the output at all"}`);
      missed += 1;
    } else {
      console.log(`ok   ${what}: ${hit.trim().slice(0, 74)}`);
    }
  }
  console.log(`\n${PLANTED.length - missed}/${PLANTED.length} planted artefacts reported`);
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
