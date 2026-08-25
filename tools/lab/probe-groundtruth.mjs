// Every row is something the lab deliberately planted. If a rule change ever
// silences one of these, this is the probe that says so.
import { Sidecar, newDataRoot, connect } from "./rpc-harness.mjs";
import { labTarget } from "./lab-target.mjs";

const PLANTED = [
  ["SUID backdoor", "SUID 可执行", /\.sysd/u],
  ["world-writable library path", "全局可写目录", /pyshared/u],
  ["second uid 0 account", "UID 0 账户", /svcadm/u],
  ["passwordless account", "空\/锁定口令字段", /backup2/u],
  ["NOPASSWD sudoers drop-in", "免密提权规则", /NOPASSWD/u],
  ["attacker authorized key", "SSH 授权公钥内容", /ssh-(ed25519|rsa)/u],
  ["listener on 4444", "监听端口", /4444/u],
  ["brute force in auth.log", "认证日志", /Failed password/u],
  ["successful login after the brute force", "SSH 登录成功记录", /Accepted/u],
  ["cron callback", "系统计划任务内容", /198\.51\.100\.7|curl/u],
  ["rc.local reverse shell", "开机脚本与运行级", /dev\/tcp|bash -i/u],
  ["ld.so.preload entry", "动态库注入痕迹", /preload|pyshared/u],
  ["bashrc backdoor", "用户登录脚本内容", /curl|198\.51\.100\.7/u],
  ["webshell in the web root", "站点可疑代码特征", /eval|upload\.php/u],
];

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", newDataRoot());
try {
  const status = await connect(sidecar, labTarget());
  const binding = status.bindingHandle;
  const catalog = await sidecar.call("emergency-command.catalog.load", { bindingHandle: binding });

  let missed = 0;
  for (const [what, title, pattern] of PLANTED) {
    const command = catalog.commands.find((entry) => entry.title === title);
    if (command === undefined) {
      console.log(`MISS ${what}: no command titled ${title}`);
      missed += 1;
      continue;
    }
    const run = await sidecar.call("emergency-command.run", {
      bindingHandle: binding, snapshotHandle: catalog.snapshotHandle, commandHandle: command.commandHandle,
    }, 90_000);
    const lines = run.output.split("\n");
    const flagged = (run.findingLines ?? []).map((index) => lines[index] ?? "");
    const hit = flagged.find((line) => pattern.test(line));
    if (hit === undefined) {
      console.log(`MISS ${what} (${title}): ${flagged.length} lines flagged, none matched`);
      missed += 1;
    } else {
      console.log(`ok   ${what}: ${hit.trim().slice(0, 78)}`);
    }
  }
  console.log(`\n${PLANTED.length - missed}/${PLANTED.length} planted artefacts still reported`);
} catch (error) {
  console.log("FAILED:", error.message);
} finally {
  sidecar.close();
}
