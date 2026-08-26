// The entries are only useful if the window can connect with them untouched.
import { Sidecar } from "./rpc-harness.mjs";

const sidecar = new Sidecar("D:/LovelyRes/target/debug/lovelyres-backend.exe", "D:/LovelyRes");
try {
  const connections = await sidecar.call("connections.list", {});
  const labs = connections.filter((entry) => entry.name.startsWith("实验靶机"));
  console.log(`连接库里有 ${labs.length} 台实验靶机`);
  for (const lab of labs) {
    console.log(`  ${lab.name.padEnd(22)} ${lab.host}:${String(lab.port).padEnd(5)} ` +
      `${lab.username} 口令已存=${lab.hasPassword}`);
  }
  // Connect through one of them exactly as the window would.
  const first = labs.find((entry) => entry.name.includes("ubuntu")) ?? labs[0];
  const started = await sidecar.call("ssh.connect.start", { connectionId: first.id });
  let status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
  for (let step = 0; step < 60 && status.stage !== "connected" && status.stage !== "failed"; step += 1) {
    if (status.hostKeyPrompt?.promptHandle !== undefined) {
      status = await sidecar.call("ssh.host-key.confirm", {
        attemptHandle: started.attemptHandle, promptHandle: status.hostKeyPrompt.promptHandle,
      });
      continue;
    }
    await new Promise((resolve) => setTimeout(resolve, 400));
    status = await sidecar.call("ssh.attempt.get", { attemptHandle: started.attemptHandle });
  }
  console.log(`\n用 ${first.name} 直接连接：${status.stage}`);
} catch (error) {
  console.error("失败：", error.message);
  process.exitCode = 1;
} finally {
  sidecar.close();
}
