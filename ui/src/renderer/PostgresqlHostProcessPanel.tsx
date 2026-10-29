import type { PostgresqlHostInspection, PostgresqlProcessReason } from "../shared/postgresql-runtime-contract";

const reasons: Record<PostgresqlProcessReason, string> = {
  unsupported: "未取得所需的 Python 3.9+ 或 Linux pidfd 能力；未自动安装。",
  "transport-unavailable": "SSH 未能完成进程核对，请核实连接和执行权限。",
  "no-tcp-observation": "数据库未提供完整连接两端，无法核对主机进程。",
  "permission-denied": "当前 SSH 账号无法读取所需进程信息；未自动提权。",
  "process-unavailable": "当前 SSH 可见范围内未取得对应进程，可能涉及另一主机或容器。",
  "process-changed": "核对期间进程或可执行文件发生变化，请重新读取。",
  "namespace-unmatched": "数据库进程与 SSH 检查不在相同 PID、网络或挂载命名空间。",
  "socket-unmatched": "数据库连接未对应到该进程持有的 socket，可能涉及代理或转发。",
  "executable-unmatched": "会话与父进程的可执行文件不一致，仍需核实实例。",
  "executable-unavailable": "进程可执行文件已删除或无法确认，仍需核实实例。",
  "path-unavailable": "进程报告的路径无法完整展示，仍需核实实例。",
  "limit-exceeded": "所需进程信息超过检查上限，本次未完成对应。",
  "invalid-input": "进程信息未通过完整性核对，请重新读取。",
  "invalid-procfs": "进程信息未通过完整性核对，请重新读取。",
  "invalid-output": "进程信息未通过完整性核对，请重新读取。",
  timeout: "进程核对超时，请核实目标负载后重试。",
};
export function PostgresqlHostProcessPanel({ inspection, expert }: { inspection: PostgresqlHostInspection; expert: boolean }) {
  const process = inspection.process;
  return <section className="database-host-process database-session" aria-label="SSH 主机实例核对">
    <h4>{process ? "已对应到 SSH 主机上的连接进程" : "尚未对应到 SSH 主机实例"}</h4>
    {process ? <>
      <p>已用本次数据库连接的地址和端口核对所属进程，并核实父进程、可执行文件与命名空间。</p>
      <p>{process.reportedDirectoryMatches === null ? "数据库未提供数据目录，配置归属仍需核实。" : process.reportedDirectoryMatches ? "数据库报告的数据目录与主进程工作目录一致。" : "数据库报告的数据目录与主进程工作目录不一致，配置归属仍需核实。"}</p>
      {expert ? <details><summary>查看主机核对依据</summary><dl>
        <dt>主进程 PID / 启动 ticks</dt><dd>{process.postmasterPid} / {process.postmasterStartTicks}</dd>
        <dt>会话 PID / 启动 ticks</dt><dd>{process.backendPid} / {process.backendStartTicks}</dd>
        <dt>主机启动标识</dt><dd>{process.bootId}</dd><dt>主机观察时间（UTC）</dt><dd>{process.observedAt}</dd>
        <dt>可执行文件</dt><dd>{process.executablePath}</dd><dt>可执行文件 SHA-256</dt><dd>{process.executableSha256}</dd>
        <dt>文件设备 / inode</dt><dd>{process.executableDevice} / {process.executableInode}</dd>
        <dt>主进程工作目录</dt><dd>{process.dataDirectory}</dd><dt>连接 socket inode</dt><dd>{process.socketInode}</dd>
        <dt>PID / 网络 / 挂载命名空间</dt><dd>{process.pidNamespace} / {process.networkNamespace} / {process.mountNamespace}</dd>
      </dl></details> : null}
    </> : <p role="status">{reasons[inspection.reason]} 参数仍可独立查看；本次未取得主机实例对应依据。</p>}
  </section>;
}
