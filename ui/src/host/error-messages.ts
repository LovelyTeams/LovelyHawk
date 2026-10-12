// What a backend error code means, in the words an operator reads.
//
// The backend answers failures in English with a stable code, and the host
// passes them on as "<message> (<code>)". Pages show that text directly, so
// the bridge swaps the English for these sentences and keeps the code at the
// end: support can still read it, and page logic that looks for a code (a
// revision conflict, a lost target) keeps working. A code missing here keeps
// its English; error-messages.test.ts fails when the backend gains a code that
// has no sentence.

export const BACKEND_ERROR_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  // Protocol and process.
  "invalid-request": "请求格式不正确，操作没有执行。",
  "invalid-request-id": "请求编号不正确，操作没有执行。",
  "invalid-params": "请求参数不正确，操作没有执行。",
  "request-too-large": "请求内容超出大小上限，操作没有执行。",
  "response-too-large": "返回内容超出大小上限，结果没有显示。",
  "response-encoding-failed": "结果无法整理成可显示的内容。",
  "unsupported-protocol": "界面与后台版本不一致，请使用同一版本的完整程序。",
  "backend-task-failed": "后台操作意外中止，请查看应用日志。",
  "bootstrap-failed": "无法读取程序旁 data 目录中的设置。",

  // SSH connections and targets.
  "ssh-invalid": "SSH 连接参数不正确。",
  "ssh-attempt-failed": "SSH 连接没有完成，详细原因见应用日志。",
  "ssh-host-not-found": "找不到这个主机名。请检查主机名拼写，或本机的 DNS 设置。",
  "ssh-unreachable": "没能和这台主机建立 SSH 连接：地址或端口不通、目标机没有运行 SSH 服务、网络超时，或双方没有共同支持的加密算法。请检查地址、端口和网络。",
  "ssh-jump-failed": "经堡垒机连接目标没有成功：堡垒机连不上目标，或不允许转发。请先确认堡垒机本身能连到目标的地址和端口。",
  "ssh-auth-rejected": "认证没有通过：服务器拒绝了用户名或凭据，或认证超时。请核对用户名、密码或私钥，以及服务器是否允许这种认证方式。",
  "ssh-key-unusable": "私钥或证书无法使用：可能需要口令、口令不对，或文件格式不受支持。",
  "ssh-agent-unavailable": "SSH Agent 无法使用：本机没有运行 Agent，或 Agent 里没有所选的身份。",
  "ssh-controller-failed": "SSH 连接操作没有完成。",
  "ssh-capability-not-found": "这次连接尝试已经结束或过期，请重新连接。",
  "host-key-changed": "目标主机的密钥与记录的不一致，可能被替换或遭到中间人攻击；程序不会自动改记。请独立核实后再处理。",
  "connection-invalid": "连接配置不完整或不正确，请检查必填项（例如密码认证需要填写密码）后重试。",
  "connection-not-found": "这个连接已不存在，可能已被删除。",
  "connection-delete-invalid": "这次删除确认已失效，请重新发起删除。",
  "connections-operation-failed": "连接操作没有完成，详细原因见应用日志。",
  "connections-store-unreadable": "无法读取本机保存的连接文件（程序目录 data 中的 connections.json），文件可能已损坏或来自不兼容的版本。程序没有改动它；data/backups 中可能有之前的备份。",
  "delete-plan-invalid": "这次删除确认已失效（已过期或已使用），请重新发起删除。",
  "delete-plan-capacity": "待确认的删除太多，请先处理已打开的确认。",

  // Settings and favourites.
  "settings-operation-failed": "设置没有保存，详细原因见应用日志。",
  "settings-plan-invalid": "这次设置确认已失效，请重新操作。",
  "settings-plan-capacity": "待确认的设置更改太多，请先处理已打开的确认。",
  "favorites-save-failed": "收藏没有保存。",

  // Notes.
  "note-not-found": "这条笔记已不存在。",
  "notes-revision-conflict": "笔记在读取后被改动过，请重新打开后再保存。",
  "notes-operation-failed": "笔记操作没有完成，可能超出标题、正文或标签的上限；详细原因见应用日志。",
  "notes-idempotency-conflict": "同一次保存被重复提交了不同内容，已拒绝。",
  "notes-idempotency-capacity": "短时间内提交的笔记更改太多，请稍后再试。",
  "notes-export-too-large": "笔记导出内容太大，无法复制到剪贴板。",

  // AI and command history.
  "ai-history-empty": "没有可删除的 AI 历史记录。",
  "ai-history-export-unavailable": "AI 历史导出不可用，或超出大小上限。",
  "ai-history-operation-failed": "AI 历史操作没有完成，详细原因见应用日志。",
  "ai-history-plan-capacity": "待确认的 AI 历史更改太多，请先处理已打开的确认。",
  "ai-history-plan-invalid": "这次 AI 历史确认已失效，请重新操作。",
  "ai-history-record-not-found": "这条 AI 历史记录已不存在。",
  "ai-history-record-too-large": "这条 AI 历史记录太大，无法完整显示。",
  "ai-history-verification-failed": "AI 历史的更改结果没能核实，请刷新后检查。",
  "command-history-binding-unavailable": "命令历史对应的目标连接已断开或已切换。",
  "command-history-empty": "没有可删除的命令历史记录。",
  "command-history-operation-failed": "命令历史操作没有完成，详细原因见应用日志。",
  "command-history-plan-capacity": "待确认的命令历史更改太多，请先处理已打开的确认。",
  "command-history-plan-invalid": "这次命令历史确认已失效，请重新操作。",
  "command-history-record-not-found": "这条命令历史记录已不存在。",
  "command-history-record-too-large": "这条命令历史记录太大，无法完整显示。",
  "command-history-verification-failed": "命令历史的更改结果没能核实，请刷新后检查。",

  // Host overview.
  "system-info-binding-unavailable": "目标连接已断开或已切换，请重新连接后再读取。",
  "system-info-capacity": "同时打开的主机全景快照太多，请关闭一些后再试。",
  "system-info-operation-failed": "主机信息读取没有完成，详细原因见应用日志。",
  "system-info-action-unavailable": "这一行已不能执行这个操作，请刷新后重试。",
  "system-info-detail-none": "这一行没有更多详情。",
  "system-info-plan-unavailable": "这次操作计划已失效（过期、未确认或已使用），请重新发起。",
  "system-info-row-gone": "这一行已不在当前表格中，请刷新后重试。",
  "system-info-snapshot-stale": "表格内容比目标主机的最新情况旧，请刷新后重试。",
  "system-info-timeout": "操作超时，请在目标主机上核对结果后再重试。",

  // Command workbench and file actions.
  "emergency-command-binding-unavailable": "目标连接已断开或已切换，命令没有执行。",
  "emergency-command-capacity": "同时进行的命令太多，请等待已有命令结束。",
  "emergency-command-catalog-unavailable": "命令目录已过期，请重新加载。",
  "emergency-command-operation-failed": "命令没有完成，详细原因见应用日志。",
  "emergency-command-result-invalid": "命令结果不完整或格式异常，已丢弃。",
  "emergency-command-timeout": "命令超出时限，请在目标主机上核对是否仍在运行。",
  "emergency-path-operation-failed": "对这个文件的操作没有完成，详细原因见应用日志。",
  "emergency-path-unavailable": "这个文件操作入口已过期或已使用，请从输出行重新打开。",

  // Baseline and audits.
  "baseline-binding-unavailable": "目标连接已断开或已切换，基线检查没有执行。",
  "baseline-capacity": "同时进行的基线检查太多，请等待已有检查结束。",
  "baseline-operation-failed": "基线检查没有完成，详细原因见应用日志。",
  "baseline-output-invalid": "基线检查结果格式异常，已丢弃。",
  "baseline-output-limit": "基线检查结果超出大小上限，已停止读取。",
  "check-audit-binding-unavailable": "目标连接已断开或已切换，核查没有执行。",
  "check-audit-capacity": "同时进行的核查太多，请等待已有核查结束。",
  "check-audit-catalog-unavailable": "核查目录已过期，请重新加载。",
  "check-audit-operation-failed": "核查没有完成，详细原因见应用日志。",
  "configuration-destination-exists": "所选位置已有同名的文件或文件夹。导出只新建、不覆盖；请换一个位置。",
  "configuration-draft-not-found": "这份配置草稿已不存在或已过期，请重新生成。",
  "configuration-invalid": "配置请求不正确，或所依据的内容已经变化。",
  "configuration-operation-failed": "配置操作没有完成，详细原因见应用日志。",
  "integrity-baseline-unavailable": "文件完整性基线已不存在或已过期，请重新建立。",
  "integrity-binding-unavailable": "目标连接已断开或已切换，完整性检查没有执行。",
  "integrity-capacity": "同时进行的完整性检查太多，请等待已有检查结束。",
  "integrity-comparison-invalid": "完整性比对结果不可用或格式异常。",
  "integrity-comparison-unavailable": "完整性比对结果已过期，请重新比对。",
  "integrity-operation-failed": "文件完整性操作没有完成，详细原因见应用日志。",

  // Logs and packet capture.
  "log-analysis-archive-tool-missing": "目标主机没有 gzip，无法打开压缩的日志归档。",
  "log-analysis-binding-unavailable": "目标连接已断开或已切换，日志没有读取。",
  "log-analysis-capacity": "同时打开的日志读取太多，请等待已有读取结束。",
  "log-analysis-operation-failed": "日志读取没有完成，详细原因见应用日志。",
  "log-analysis-snapshot-unavailable": "这份日志结果已过期，请重新读取。",
  "packet-capture-already-running": "这台主机上已经有一个抓包在运行。",
  "packet-capture-binding-unavailable": "目标连接已断开或已切换，抓包没有开始。",
  "packet-capture-busy": "上一个抓包请求还在处理中，请稍候。",
  "packet-capture-interface-unavailable": "所选网卡已不可用，请重新选择。",
  "packet-capture-operation-failed": "抓包没有完成，详细原因见应用日志。",
  "packet-capture-output-invalid": "抓包输出格式异常，已丢弃。",
  "packet-capture-timeout": "抓包操作超出时限。",
  "packet-capture-too-many": "同时运行的抓包太多。",
  "packet-capture-unavailable": "这次抓包已结束或已过期。",

  // Containers and Kubernetes.
  "docker-binding-unavailable": "目标连接已断开或已切换，容器信息没有读取。",
  "docker-capacity": "同时进行的容器读取太多，请等待已有读取结束。",
  "docker-operation-failed": "容器信息读取没有完成，详细原因见应用日志。",
  "docker-resource-unavailable": "这个容器资源已不存在或列表已过期，请刷新。",
  "docker-snapshot-unavailable": "容器列表已过期，请刷新。",
  "docker-runtime-absent": "这台主机没有安装 Docker 或 Podman。",
  "docker-runtime-not-running": "这台主机装有容器运行时，但它没有响应。",
  "docker-container-unavailable": "这个容器已不在制定计划时的列表中，请刷新后重新操作。",
  "docker-action-capacity": "待确认的容器操作太多，请先处理已打开的确认。",
  "docker-file-path-invalid": "文件路径要写成以 / 开头的完整文件路径；复制时源和目标不能相同。",
  "docker-file-missing": "这个文件不存在。",
  "docker-file-too-large": "文件超过了可编辑、可复制的上限（2 MiB）。",
  "docker-file-not-text": "这个文件不是 UTF-8 纯文本，不能在这里编辑。",
  "docker-file-changed": "文件在打开之后被改过了，请重新打开再改。",
  "docker-file-unreadable": "容器读不出这个文件的信息：可能缺少 sha256sum、没有权限，或者它不是普通文件。",
  "docker-action-failed": "容器操作没有完成，详细原因见应用日志。",
  "docker-action-not-confirmed": "容器操作还没有确认，没有执行。",
  "docker-action-plan-invalid": "这次容器操作计划已失效（过期或已使用），请重新发起。",
  "docker-action-timeout": "容器操作超出时限，请刷新后核对容器状态。",
  "kubernetes-binding-unavailable": "目标连接已断开或已切换，集群信息没有读取。",
  "kubernetes-capacity": "同时进行的集群读取太多，请等待已有读取结束。",
  "kubernetes-operation-failed": "集群信息读取没有完成，详细原因见应用日志。",
  "kubernetes-namespace-unavailable": "所选命名空间已过期，请重新选择。",
  "kubernetes-resource-unavailable": "这个资源已不在制定计划时的列表中，或列表已过期，请刷新。",
  "kubernetes-logs-unavailable": "这个资源没有可读取的 Pod 日志。",
  "kubernetes-logs-not-ready": "kubelet 这会儿交不出这段容器日志：容器刚被替换或旧日志已被回收。稍等几秒再读一次。",
  "kubernetes-pod-container-unavailable": "这个 Pod 里没有所选的容器，请刷新列表后重新选择。",
  "kubernetes-forbidden": "集群拒绝了当前账号的这次请求（权限不足），什么都没有读取或改动。请改选这个账号能访问的命名空间，或换有权限的 kubeconfig、账号。",
  "kubernetes-manifest-unavailable": "没有导出：这个对象已不是列表里的那一个（可能被删除后重建），或集群没有给出它的清单。请刷新列表后再试。",
  "kubernetes-action-capacity": "待确认的工作负载操作太多，请先处理已打开的确认。",
  "kubernetes-action-failed": "工作负载操作没有完成，详细原因见应用日志。",
  "kubernetes-action-kind-mismatch": "这个操作不适用于这类资源。",
  "kubernetes-action-not-confirmed": "工作负载操作还没有确认，没有执行。",
  "kubernetes-action-plan-invalid": "这次工作负载操作计划已失效（过期或已使用），请重新发起。",
  "kubernetes-action-timeout": "工作负载操作超出时限，请刷新后核对状态。",

  // Terminal and file manager.
  "terminal-binding-unavailable": "终端对应的目标连接已断开或已切换。",
  "terminal-capacity": "打开的终端太多，请先关闭一些。",
  "terminal-operation-failed": "终端操作没有完成，详细原因见应用日志。",
  "terminal-output-limit": "这个终端的输出已达到保留上限。",
  "terminal-protocol-invalid": "终端数据流异常，已停止。",
  "terminal-search-limit": "搜索匹配太多，只显示了一部分。",
  "terminal-timeout": "终端操作超时。",
  "terminal-unavailable": "这个终端会话已结束。",
  "sftp-browser-binding-unavailable": "文件管理对应的目标连接已断开或已切换。",
  "sftp-browser-capacity": "同时打开的文件管理太多，请先关闭一些。",
  "sftp-browser-invalid": "文件管理请求不正确，操作没有执行。",
  "sftp-browser-invalid-response": "目标返回的文件信息格式异常，已丢弃。",
  "sftp-browser-operation-failed": "文件操作没有完成，详细原因见应用日志。",
  "sftp-browser-subsystem-unavailable": "目标主机没有完成 SFTP 握手，可能未启用 SFTP。",
  "sftp-browser-timeout": "文件操作超出时限，请刷新后核对结果。",
  "sftp-browser-cancelled": "传输已取消，写到一半的文件已经删除，没有留下不完整的文件。",
  "sftp-browser-unavailable": "这个目录或文件入口已过期，请刷新。",

  // Java hot update.
  "java-binding-unavailable": "目标连接已断开或已切换，Java 热更新没有执行。",
  "java-hot-update-stale": "进程列表、JAR、类文件或计划已经过期，请重新扫描后再操作。",
  "java-hot-update-capacity": "待处理的类文件或计划太多，请先取消一些。",
  "java-hot-update-unconfirmed": "计划还没有确认，没有执行任何改动。",
  "java-tool-missing": "目标机上找不到可用的 jar 工具，无法列出或改写 JAR；原因见页面“Java 环境”里的说明。",
  "java-backup-folder-missing": "这个登录账号没有自己的主目录，无处保存原 JAR 的备份，所以不生成替换计划。请改用有主目录的账号或 root 登录。",
  "java-hot-update-timeout": "Java 操作没有在时限内结束，请重新打开 JAR 核对当前内容。",
  "java-hot-update-failed": "Java 操作没有完成，详细原因见应用日志。",

  // Reports.
  "disposal-report-binding-unavailable": "目标连接已断开或已切换，处置报告没有生成。",
  "disposal-report-capacity": "待处理的处置报告快照太多，请先关闭一些。",
  "disposal-report-operation-failed": "处置报告操作没有完成，详细原因见应用日志。",
  "disposal-report-too-large": "处置报告超出大小上限。",
  "disposal-report-unavailable": "这份处置报告快照已过期，请刷新。",
});

const TRAILING_CODE = /^(?<message>[\s\S]*?)\s*\((?<code>[a-z][a-z0-9]*(?:-[a-z0-9]+)+)\)\s*$/u;

/**
 * Replaces the English sentence of "<message> (<code>)" with the operator's
 * sentence for that code. Anything else — a host sentence already in Chinese,
 * a message without a code, a code with no entry — is returned unchanged.
 */
export function operatorErrorMessage(text: string): string {
  const match = TRAILING_CODE.exec(text);
  const code = match?.groups?.code;
  if (code === undefined || !Object.hasOwn(BACKEND_ERROR_MESSAGES, code)) return text;
  return `${BACKEND_ERROR_MESSAGES[code]} (${code})`;
}
